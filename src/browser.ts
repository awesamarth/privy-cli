import { spawn, type ChildProcess } from 'node:child_process';
import { access, chmod, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { CliError } from './errors.ts';
import { ORIGIN } from './client.ts';
import type { Credentials } from './store.ts';

function localUrl(value: string, protocols: string[]): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new CliError('INVALID_CDP_URL', 'Expected a loopback Chrome debugging URL.', 2); }
  if (!protocols.includes(url.protocol) || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) || url.username || url.password) {
    throw new CliError('INVALID_CDP_URL', 'Browser debugging is restricted to loopback addresses.', 2);
  }
  return url;
}

export class CdpConnection {
  private nextId = 0;
  private pending = new Map<number, { resolve: (value: any) => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> }>();
  private constructor(private socket: WebSocket) {
    socket.addEventListener('message', event => {
      let message: any;
      try { message = JSON.parse(String(event.data)); } catch { return; }
      const pending = this.pending.get(message.id);
      if (!pending) return;
      clearTimeout(pending.timer); this.pending.delete(message.id);
      if (message.error) pending.reject(new CliError('BROWSER_ERROR', 'Chrome rejected a browser command.'));
      else pending.resolve(message.result);
    });
    socket.addEventListener('close', () => this.rejectPending());
    socket.addEventListener('error', () => this.rejectPending());
  }
  private rejectPending(): void {
    for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(new CliError('BROWSER_CLOSED', 'The login browser connection closed.')); }
    this.pending.clear();
  }
  static async connect(url: string): Promise<CdpConnection> {
    localUrl(url, ['ws:']);
    const socket = new WebSocket(url);
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => { socket.close(); reject(new CliError('BROWSER_TIMEOUT', 'Chrome connection timed out.')); }, 5000);
      socket.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
      socket.addEventListener('error', () => { clearTimeout(timer); reject(new CliError('BROWSER_ERROR', 'Could not connect to Chrome.')); }, { once: true });
    });
    return new CdpConnection(socket);
  }
  send(method: string, params: Record<string, unknown> = {}): Promise<any> {
    const id = ++this.nextId;
    return new Promise((resolve, reject) => {
      if (this.socket.readyState !== WebSocket.OPEN) { reject(new CliError('BROWSER_CLOSED', 'Chrome connection is closed.')); return; }
      const timer = setTimeout(() => { this.pending.delete(id); reject(new CliError('BROWSER_TIMEOUT', 'Chrome command timed out.')); }, 5000);
      this.pending.set(id, { resolve, reject, timer });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }
  close(): void { this.rejectPending(); this.socket.close(); }
}

export async function readBrowserCredentials(endpoint: string): Promise<Credentials | null> {
  const origin = localUrl(endpoint, ['http:']).origin;
  let targets: any[];
  try {
    const response = await fetch(`${origin}/json/list`, { signal: AbortSignal.timeout(3000), redirect: 'error' });
    targets = await response.json() as any[];
  } catch { throw new CliError('BROWSER_UNAVAILABLE', 'Cannot reach the Chrome debugging endpoint.'); }
  if (!Array.isArray(targets)) throw new CliError('INVALID_CDP_RESPONSE', 'Chrome returned an invalid target list.');
  const pages = targets.filter(t => {
    try { return t.type === 'page' && new URL(t.url).origin === ORIGIN; } catch { return false; }
  });
  if (pages.length > 1) throw new CliError('AMBIGUOUS_BROWSER', 'Keep exactly one Privy dashboard tab open in the login browser.');
  if (!pages.length) return null;
  // Don't capture a partially authenticated session while OTP/MFA is still on the login page.
  if (['/', '/logout', '/sso/callback'].includes(new URL(pages[0].url).pathname)) return null;
  const cdp = await CdpConnection.connect(pages[0].webSocketDebuggerUrl);
  try {
    const result = await cdp.send('Runtime.evaluate', {
      expression: `(() => {
        if (location.origin !== ${JSON.stringify(ORIGIN)} || location.pathname === '/') return null;
        const read = k => { const raw = localStorage.getItem(k); try { return JSON.parse(raw); } catch { return raw; } };
        const accessToken = read('privy:token'), refreshToken = read('privy:refresh_token');
        return typeof accessToken === 'string' && typeof refreshToken === 'string' ? {accessToken, refreshToken} : null;
      })()`,
      returnByValue: true,
    });
    if (result.exceptionDetails) return null;
    const value = result.result?.value;
    return value && typeof value.accessToken === 'string' && typeof value.refreshToken === 'string' ? value : null;
  } finally { cdp.close(); }
}

export async function chromePath(explicit?: string): Promise<string> {
  const candidates = explicit ? [explicit] : process.platform === 'darwin'
    ? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/Applications/Chromium.app/Contents/MacOS/Chromium']
    : process.platform === 'win32'
      ? [join(process.env.PROGRAMFILES || 'C:\\Program Files', 'Google/Chrome/Application/chrome.exe')]
      : ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser'];
  for (const path of candidates) { try { await access(path); return path; } catch {} }
  throw new CliError('CHROME_NOT_FOUND', 'Install Google Chrome/Chromium, or pass --browser /absolute/path/to/browser.');
}

export async function browserLogin(options: {
  cdp?: string; browser?: string; timeoutSeconds: number;
  signal?: AbortSignal;
  validate: (credentials: Credentials) => Promise<void>;
  save: (credentials: Credentials) => Promise<void>;
  log: (message: string) => void;
}): Promise<void> {
  let directory: string | undefined;
  let child: ChildProcess | undefined;
  let endpoint = options.cdp;
  let spawnFailed = false;
  try {
    if (!endpoint) {
      const executable = await chromePath(options.browser);
      directory = await mkdtemp(join(tmpdir(), 'privy-cli-login-'));
      await chmod(directory, 0o700);
      child = spawn(executable, [`--user-data-dir=${directory}`, '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', '--no-first-run', '--no-default-browser-check', ORIGIN], { stdio: 'ignore' });
      child.on('error', () => { spawnFailed = true; });
      const deadline = Date.now() + 15_000;
      while (Date.now() < deadline) {
        options.signal?.throwIfAborted();
        if (spawnFailed || child.exitCode !== null) throw new CliError('CHROME_START_FAILED', 'Chrome exited before its debugging endpoint was ready.');
        try {
          const port = (await readFile(join(directory, 'DevToolsActivePort'), 'utf8')).split('\n')[0];
          if (/^\d+$/.test(port)) { endpoint = `http://127.0.0.1:${port}`; break; }
        } catch {}
        await sleep(200);
      }
      if (!endpoint) throw new CliError('BROWSER_TIMEOUT', 'Chrome did not start in time.');
      options.log('Log into Privy in the new Chrome window. Complete email verification and any CAPTCHA/MFA there.');
    } else {
      localUrl(endpoint, ['http:']);
      options.log('Importing the explicitly selected dashboard browser session. CLI logout will revoke this shared session too.');
    }
    const deadline = Date.now() + options.timeoutSeconds * 1000;
    while (Date.now() < deadline) {
      options.signal?.throwIfAborted();
      const credentials = await readBrowserCredentials(endpoint);
      if (credentials) {
        await options.validate(credentials);
        await options.save(credentials);
        options.log('Dashboard session verified and saved in the OS credential store.');
        return;
      }
      await sleep(750);
    }
    throw new CliError('LOGIN_TIMEOUT', 'Login timed out. Run auth login to try again.');
  } finally {
    if (child) {
      child.kill('SIGTERM');
      const end = Date.now() + 5000;
      while (child.exitCode === null && child.signalCode === null && Date.now() < end) await sleep(100);
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    }
    if (directory) await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
}
