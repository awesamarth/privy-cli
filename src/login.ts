import { CliError } from './errors.ts';
import { tokenClaims, type Fetcher } from './client.ts';
import { ORIGIN, DASHBOARD_APP_ID, type JsonObject } from './operations.ts';
import type { Credentials } from './store.ts';
import { startVerificationBridge } from './verification.ts';
import { openDefaultBrowser, requireInteractiveLogin, terminalPrompt, type LoginPrompt } from './terminal.ts';

export interface EmailLoginOptions {
  email?: string;
  timeoutSeconds: number;
  noOpen?: boolean;
  signal?: AbortSignal;
  validate: (credentials: Credentials, signal: AbortSignal) => Promise<void>;
  save: (credentials: Credentials) => Promise<void>;
  log: (message: string) => void;
  // Test seams; the CLI never accepts arbitrary origins, tokens or challenge results as flags.
  fetcher?: Fetcher;
  prompt?: LoginPrompt;
  openBrowser?: (url: string, signal: AbortSignal) => Promise<void>;
}

export function validateEmail(email: string): string {
  const value = email.trim();
  if (value.length > 320 || !/^[^\s@\x00-\x1f\x7f]+@[^\s@\x00-\x1f\x7f]+\.[^\s@\x00-\x1f\x7f]+$/.test(value)) {
    throw new CliError('INVALID_EMAIL', 'Enter a valid dashboard email address.', 2);
  }
  return value;
}

export async function emailLogin(options: EmailLoginOptions): Promise<void> {
  if (!Number.isInteger(options.timeoutSeconds) || options.timeoutSeconds < 1 || options.timeoutSeconds > 1800) {
    throw new CliError('INVALID_TIMEOUT', 'Timeout must be 1–1800 seconds.', 2);
  }
  if (!options.prompt) requireInteractiveLogin();
  const prompt = options.prompt ?? terminalPrompt;
  const fetcher = options.fetcher ?? ((url, init) => fetch(url, init));
  const deadline = AbortSignal.timeout(options.timeoutSeconds * 1000);
  const signal = AbortSignal.any([deadline, ...(options.signal ? [options.signal] : [])]);
  let candidate: Credentials | undefined, saved = false;
  let bridge: Awaited<ReturnType<typeof startVerificationBridge>> | undefined;

  async function request(path: string, active: AbortSignal, body?: JsonObject, credentials?: Credentials): Promise<JsonObject> {
    active.throwIfAborted();
    let response: Response;
    try {
      response = await fetcher(ORIGIN + path, {
        method: body ? 'POST' : 'GET', redirect: 'error', credentials: 'omit',
        headers: { origin: ORIGIN, 'privy-app-id': DASHBOARD_APP_ID, accept: 'application/json',
          ...(body ? { 'content-type': 'application/json' } : {}),
          ...(credentials ? { authorization: `Bearer ${credentials.accessToken}` } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
        signal: AbortSignal.any([active, AbortSignal.timeout(20_000)]),
      });
    } catch { throw new CliError('AUTH_NETWORK_ERROR', 'Authentication request failed or timed out. No automatic email/code retry was attempted.'); }
    let data: JsonObject | undefined;
    try {
      const value = await response.json();
      if (value && typeof value === 'object' && !Array.isArray(value)) data = value as JsonObject;
    } catch {}
    if (!response.ok) {
      const error = new CliError('AUTH_REJECTED', `Privy authentication returned HTTP ${response.status}.`, 1, response.status);
      if (typeof data?.code === 'string' && /^[a-z_]{1,80}$/.test(data.code)) error.code = data.code;
      error.hint = response.status === 429 ? 'Wait before requesting another code; no automatic retries were made.'
        : response.status === 403 ? 'Additional authorization, MFA or SSO may be required. This email flow cannot complete those steps; use your organization-approved dashboard login.'
        : path.endsWith('/authenticate') ? 'Check the code is correct and unexpired. No retry was made; restart login if necessary.'
        : 'Email initiation was refused. The verification may have expired or your account may require another login method.';
      const retryAfter = response.headers.get('retry-after');
      if (retryAfter && /^\d{1,6}$/.test(retryAfter)) error.retryAfterSeconds = Number(retryAfter);
      const requestId = response.headers.get('x-request-id') ?? response.headers.get('cf-ray');
      if (requestId && /^[a-zA-Z0-9_:\-.]{1,128}$/.test(requestId)) error.requestId = requestId;
      throw error;
    }
    if (response.status === 204) return {};
    if (!data) throw new CliError('INVALID_AUTH_RESPONSE', 'Unexpected authentication response. No credentials were saved.');
    return data;
  }

  try {
    signal.throwIfAborted();
    const email = validateEmail(options.email ?? await prompt('email', signal));
    options.log('Unofficial Privy login: browser verification, then a login code in this terminal. No dashboard browser session is imported.');
    const config = await request(`/api/v1/apps/${DASHBOARD_APP_ID}`, signal);
    if (config.data_classification !== 'public' || config.enabled_captcha_provider !== 'hcaptcha' || typeof config.captcha_site_key !== 'string') {
      throw new CliError('UNSUPPORTED_AUTH_CONFIG', 'The dashboard verification configuration changed. Login stopped without sending an email.');
    }
    const siteKey = config.captcha_site_key.replace(/^h:/, '');
    if (!/^[a-z0-9-]{1,100}$/i.test(siteKey)) throw new CliError('UNSUPPORTED_AUTH_CONFIG', 'The public verification key is invalid. Login stopped.');
    let initiationError: unknown;
    bridge = await startVerificationBridge({
      siteKey, signal, timeoutMs: options.timeoutSeconds * 1000, purpose: 'login',
      onEvent: ({ event }) => { if (event === 'challenge-open') options.log('Complete the browser challenge if one appears. Enter the login code only in this terminal.'); },
      async onToken(token, context) {
        try {
          const data = await request('/api/v1/passwordless/init', AbortSignal.any([signal, context.signal]), { email, token });
          if (data.success !== true) throw new CliError('EMAIL_NOT_SENT', 'Email initiation was not confirmed. No automatic retry was made.');
          return { emailSent: true };
        } catch (error) { initiationError = error; throw error; }
      },
    });
    options.log(`Open this verification URL on this machine: ${bridge.url}`);
    if (!options.noOpen) {
      try { await (options.openBrowser ?? openDefaultBrowser)(bridge.url, signal); }
      catch {
        signal.throwIfAborted();
        options.log('Could not open the default browser. Open the printed URL manually; the CLI is still waiting.');
      }
    }
    const verification = await bridge.done;
    await bridge.close(); bridge = undefined;
    signal.throwIfAborted();
    if (initiationError) throw initiationError;
    if (!verification.ok || !verification.emailSent) {
      throw new CliError('VERIFICATION_FAILED', 'Browser verification did not complete. Restart login; no automatic retry was made.');
    }
    options.log('Login code sent to your email. Enter it here to finish login.');
    let code = (await prompt('code', signal)).trim();
    if (!/^\d{6}$/.test(code)) throw new CliError('INVALID_CODE', 'Expected the six-digit login code. No authentication request was sent.', 2);
    let data: JsonObject;
    try { data = await request('/api/v1/passwordless/authenticate', signal, { email, code, mode: 'no-signup' }); }
    finally { code = ''; }
    if (typeof data.token === 'string' && data.token.length > 0 && data.token.length <= 32_768 &&
        typeof data.refresh_token === 'string' && data.refresh_token.length > 0 && data.refresh_token.length <= 32_768) {
      candidate = { accessToken: data.token, refreshToken: data.refresh_token };
    }
    if (!candidate || data.session_update_action !== 'set' || data.is_new_user === true ||
        data.mfa_required === true || data.mfa_verification_required === true || data.mfa_challenge) {
      throw new CliError('ADDITIONAL_AUTH_REQUIRED', 'A completed existing-account session was not issued. MFA, SSO or another login step may be required; no credentials were saved.');
    }
    const claims = tokenClaims(candidate.accessToken);
    if (claims.exp <= Date.now() / 1000) throw new CliError('SESSION_EXPIRED', 'The newly issued session is already expired.');
    signal.throwIfAborted();
    // Decoded claims are not proof of authorization. Require a real dashboard account read.
    await options.validate(candidate, signal);
    signal.throwIfAborted();
    await options.save(candidate);
    saved = true;
    options.log('Dashboard access verified. Session saved in the OS credential store.');
  } catch (error) {
    if (candidate && !saved) {
      try { await request('/api/v1/sessions/logout', AbortSignal.timeout(10_000), { refresh_token: candidate.refreshToken }, candidate); }
      catch { options.log('Warning: revocation of the new, unsaved session could not be confirmed.'); }
    }
    if (options.signal?.aborted) throw new CliError('CANCELLED', 'Login cancelled.', 130);
    if (deadline.aborted) throw new CliError('LOGIN_TIMEOUT', 'Login timed out. Restart auth login when ready.');
    if (error instanceof CliError) throw error;
    throw new CliError('LOGIN_FAILED', 'Login could not complete. No credential details were printed.');
  } finally { await bridge?.close(); }
}
