// Normal browser verification only: never reads browser storage or dashboard cookies.
import { createServer, type IncomingMessage } from 'node:http';
import { randomBytes } from 'node:crypto';

interface BridgeOptions {
  siteKey: string;
  onToken: (token: string, context: { signal: AbortSignal }) => Promise<{ emailSent?: boolean } | void>;
  onEvent?: (event: { event: string }) => void;
  timeoutMs?: number;
  signal?: AbortSignal;
  purpose?: 'login' | 'research';
}
type Result = { ok: true; emailSent: boolean } | { ok: false; reason: string };
const MAX_BODY = 64 * 1024;
function readJson(req: IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    let chunks: Buffer[] = [], size = 0, failed = false;
    req.on('data', (chunk: Buffer) => {
      if (failed) return;
      size += chunk.length;
      if (size > MAX_BODY) { failed = true; chunks = []; reject(new Error('BODY_TOO_LARGE')); return; }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (failed) return;
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(new Error('INVALID_JSON')); }
    });
    req.on('error', () => reject(new Error('REQUEST_INTERRUPTED')));
  });
}

export async function startVerificationBridge({ siteKey, onToken, onEvent = () => {}, timeoutMs = 300_000, signal, purpose = 'research' }: BridgeOptions) {
  if (typeof siteKey !== 'string' || !/^[a-z0-9-]{1,100}$/i.test(siteKey)) throw new Error('INVALID_PUBLIC_SITE_KEY');
  if (typeof onToken !== 'function') throw new Error('TOKEN_HANDLER_REQUIRED');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 1_800_000) throw new Error('INVALID_TIMEOUT');
  signal?.throwIfAborted();
  const state = randomBytes(24).toString('hex');
  const scriptNonce = randomBytes(18).toString('base64');
  const lifetime = new AbortController();
  let origin: string, timer: ReturnType<typeof setTimeout> | undefined, used = false, terminal = false;
  let resolveDone!: (result: Result) => void;
  const done = new Promise<Result>(resolve => { resolveDone = resolve; });
  const finish = (result: Result) => {
    if (terminal) return;
    terminal = true; clearTimeout(timer);
    if (!result.ok) lifetime.abort();
    resolveDone(result);
  };
  const server = createServer((req, res) => {
    void handle(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ error: 'INTERNAL_ERROR' }));
      finish({ ok: false, reason: 'internal-error' });
    });
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 5_000;
  server.keepAliveTimeout = 1_000;

  async function handle(req: IncomingMessage, res: import('node:http').ServerResponse) {
    const json = (status: number, value: unknown) => {
      res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value));
    };
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (req.headers.host !== new URL(origin).host) return json(403, { error: 'INVALID_HOST' });
    if (req.url === `/${state}` && req.method === 'GET') {
      if (terminal || used) return json(410, { error: 'FLOW_FINISHED' });
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Content-Security-Policy', `default-src 'none'; script-src 'nonce-${scriptNonce}' https://hcaptcha.com https://*.hcaptcha.com; style-src 'unsafe-inline'; frame-src https://hcaptcha.com https://*.hcaptcha.com; connect-src 'self' https://hcaptcha.com https://*.hcaptcha.com; img-src data: https://hcaptcha.com https://*.hcaptcha.com; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`);
      return res.end(page(siteKey, state, scriptNonce, purpose));
    }
    if (req.method !== 'POST' || !['/complete', '/event'].includes(req.url ?? '')) return json(404, { error: 'NOT_FOUND' });
    if (req.headers.origin !== origin) return json(403, { error: 'INVALID_ORIGIN' });
    if (req.headers['content-type']?.split(';')[0].trim().toLowerCase() !== 'application/json') return json(415, { error: 'JSON_REQUIRED' });
    let body;
    try { body = await readJson(req); }
    catch (error) { const code = (error as Error).message; return json(code === 'BODY_TOO_LARGE' ? 413 : 400, { error: code }); }
    if (!body || typeof body !== 'object' || Array.isArray(body) || body.state !== state) return json(403, { error: 'INVALID_STATE' });
    if (terminal || used) return json(409, { error: 'FLOW_FINISHED' });
    if (req.url === '/event') {
      if (!['sdk-ready', 'sdk-error', 'expired', 'challenge-open'].includes(body.event)) return json(400, { error: 'INVALID_EVENT' });
      onEvent({ event: body.event }); // Never forward arbitrary page-provided strings to logs.
      json(200, { ok: true });
      if (['sdk-error', 'expired'].includes(body.event)) finish({ ok: false, reason: body.event });
      return;
    }
    if (typeof body.token !== 'string' || body.token.length < 1 || body.token.length > 60_000) return json(400, { error: 'INVALID_TOKEN' });
    used = true; // Consume before awaiting: concurrent callbacks must not send duplicate emails.
    try {
      const result = await onToken(body.token, { signal: lifetime.signal });
      if (terminal) return json(410, { error: 'FLOW_FINISHED' });
      const emailSent = result?.emailSent === true;
      json(200, { ok: true, emailSent });
      finish({ ok: true, emailSent });
    } catch {
      json(502, { error: 'VERIFICATION_NOT_ACCEPTED' });
      finish({ ok: false, reason: 'verification-not-accepted' });
    } finally { body.token = undefined; }
  }

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  origin = `http://127.0.0.1:${(server.address() as import('node:net').AddressInfo).port}`;
  timer = setTimeout(() => finish({ ok: false, reason: 'timeout' }), timeoutMs);
  timer.unref();
  const cancel = () => finish({ ok: false, reason: 'cancelled' });
  signal?.addEventListener('abort', cancel, { once: true });
  if (signal?.aborted) cancel();
  let closing: Promise<void> | undefined;
  return {
    url: `${origin}/${state}`, done,
    close(): Promise<void> {
      if (closing) return closing;
      finish({ ok: false, reason: 'cancelled' }); clearTimeout(timer);
      lifetime.abort();
      signal?.removeEventListener('abort', cancel);
      // Allow the completed HTTP response to flush, but never wait forever for a socket.
      closing = new Promise(resolve => {
        const force = setTimeout(() => server.closeAllConnections(), 1000);
        force.unref();
        server.close(() => { clearTimeout(force); resolve(); });
        server.closeIdleConnections();
      });
      return closing;
    },
  };
}

function page(siteKey: string, state: string, nonce: string, purpose: 'login' | 'research'): string {
  const login = purpose === 'login';
  const intro = login
    ? 'Complete browser verification here. Your CLI will request a login code by email; enter that code only in your terminal.'
    : 'This tab only tests browser verification. This research probe does not sign you in or accept email codes.';
  const sent = login
    ? 'Login code sent to your email. Return to your terminal and enter the code there. You can close this tab.'
    : 'Email initiation verified. This research probe stops here; ignore the email code. You can close this tab.';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Privy CLI · Browser verification</title><style>
body{background:#f6f6f5;color:#202020;font:16px/1.6 system-ui;margin:0;padding:64px 24px}main{max-width:540px;margin:auto;background:white;border:1px solid #e5e5e5;border-radius:20px;padding:36px}h1{font-size:26px;line-height:1.2}small{color:#666}.badge{font:12px monospace;letter-spacing:.08em}#status{padding:20px 0;font-size:18px}footer{margin-top:24px;border-top:1px solid #eee;padding-top:20px}
</style></head><body><main><div class="badge">UNOFFICIAL PRIVY CLI${login ? '' : ' · RESEARCH'}</div><h1>Verify your browser</h1><p>${intro}</p><div id="status" role="status" aria-live="polite">Loading verification…</div><div id="captcha"></div><footer><small>No browser session, cookies or account credentials are imported. This is not an official Privy login integration.</small></footer></main><script nonce="${nonce}">
const state=${JSON.stringify(state)};const status=document.getElementById('status');let completed=false;
async function report(event){try{await fetch('/event',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({state,event})});}catch{}}
window.ready=()=>{try{const widget=hcaptcha.render('captcha',{sitekey:${JSON.stringify(siteKey)},size:'invisible',callback:async(token)=>{if(completed)return;completed=true;status.textContent='Verification complete. Sending the result to your local CLI…';try{const response=await fetch('/complete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({state,token})});const result=await response.json();if(!response.ok)throw Error();status.textContent=result.emailSent?${JSON.stringify(sent)}:'Browser verification completed. No email was sent in this research run. You can close this tab.';}catch{status.textContent='Could not complete verification. Check the terminal; restart the flow rather than retrying this tab.'}},'error-callback':()=>{if(completed)return;status.textContent='Browser verification failed. Check the terminal and restart the flow.';report('sdk-error');},'expired-callback':()=>{if(completed)return;status.textContent='Verification expired. Restart the flow in your terminal.';report('expired');},'open-callback':()=>{if(completed)return;status.textContent='Complete the browser challenge here. Enter your login code only in the terminal.';report('challenge-open');}});status.textContent='Verifying your browser…';report('sdk-ready');hcaptcha.execute(widget);}catch{status.textContent='Unable to start browser verification.';report('sdk-error');}};
setTimeout(()=>{if(!window.hcaptcha&&!completed)status.textContent='Verification could not load. Check browser/network blocking and the terminal. This flow will time out safely.';},20000);
</script><script nonce="${nonce}" src="https://js.hcaptcha.com/1/api.js?render=explicit&onload=ready&recaptchacompat=off" async defer></script></body></html>`;
}
