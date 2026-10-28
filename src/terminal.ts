import { spawn } from 'node:child_process';
import { access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { delimiter, join } from 'node:path';
import { createInterface } from 'node:readline';
import { Writable } from 'node:stream';
import { CliError } from './errors.ts';

export type LoginPrompt = (field: 'email' | 'code', signal: AbortSignal) => Promise<string>;

export function requireInteractiveLogin(): void {
  if (!process.stdin.isTTY || !process.stderr.isTTY) {
    throw new CliError('INTERACTIVE_REQUIRED', 'Email login requires an interactive terminal to enter the login code. Run privy auth login in a terminal; --no-open lets you open the verification URL manually on this machine.', 2);
  }
}

// No OTP argument/environment variable: keep codes out of shell history and process listings.
export const terminalPrompt: LoginPrompt = (field, signal) => {
  requireInteractiveLogin();
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const hidden = field === 'code';
    const muted = new Writable({ write(_chunk, _encoding, callback) { callback(); } });
    const rl = createInterface({ input: process.stdin, output: hidden ? muted : process.stderr, terminal: true, historySize: 0 });
    let settled = false;
    const finish = (error?: unknown, value?: string) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', cancel);
      rl.close(); muted.destroy();
      if (hidden) process.stderr.write('\n');
      if (error) reject(error); else resolve(value!.trim());
    };
    const cancel = () => finish(signal.reason ?? new CliError('CANCELLED', 'Login cancelled.', 130));
    signal.addEventListener('abort', cancel, { once: true });
    rl.once('line', value => finish(undefined, value));
    rl.once('SIGINT', () => finish(new CliError('CANCELLED', 'Login cancelled.', 130)));
    rl.once('close', () => finish(new CliError('CANCELLED', 'Terminal closed before login completed.', 130)));
    process.stderr.write(hidden ? "Login code (input won't be displayed): " : 'Privy dashboard email: ');
    if (signal.aborted) cancel();
  });
};

export function browserLaunchCommand(platform: NodeJS.Platform = process.platform): { command: string; args: string[] } {
  if (platform === 'darwin') return { command: '/usr/bin/open', args: [] };
  if (platform === 'win32') return { command: join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'rundll32.exe'), args: ['url.dll,FileProtocolHandler'] };
  return { command: 'xdg-open', args: [] };
}

export async function browserLauncherAvailable(): Promise<boolean> {
  const { command } = browserLaunchCommand();
  const candidates = command === 'xdg-open' ? (process.env.PATH ?? '').split(delimiter).filter(Boolean).map(path => join(path, command)) : [command];
  for (const candidate of candidates) {
    try { await access(candidate, constants.X_OK); return true; } catch {}
  }
  return false;
}

export async function openDefaultBrowser(url: string, signal: AbortSignal): Promise<void> {
  const target = new URL(url);
  if (target.protocol !== 'http:' || target.hostname !== '127.0.0.1' || target.username || target.password) {
    throw new CliError('INVALID_BROWSER_URL', 'Only the local verification page may be opened.', 2);
  }
  signal.throwIfAborted();
  const { command, args } = browserLaunchCommand();
  await new Promise<void>((resolve, reject) => {
    const child = spawn(command, [...args, url], { stdio: 'ignore', windowsHide: true, shell: false });
    let settled = false;
    const finish = (ok: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer); signal.removeEventListener('abort', cancel);
      if (!ok) child.kill();
      if (ok) resolve(); else reject(new CliError('BROWSER_OPEN_FAILED', 'Could not open the default browser. Open the printed verification URL manually.'));
    };
    const cancel = () => finish(false);
    const timer = setTimeout(cancel, 10_000);
    child.once('error', cancel);
    child.once('exit', code => finish(code === 0));
    signal.addEventListener('abort', cancel, { once: true });
    if (signal.aborted) cancel();
  });
}
