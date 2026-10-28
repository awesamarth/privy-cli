import { isDeepStrictEqual } from 'node:util';
import type { AppSecretSink } from './app-secret-storage.ts';
import { connectionList, writeConnection } from './ecosystem-operations.ts';
import { owningAccount, securityState, writeSecurity, redirectsAllowed } from './security-settings.ts';
import { jwtState, publicJwt, writeJwt } from './jwt-settings.ts';
import { availabilityState, writeAvailability } from './availability-operations.ts';
import { inspectAdvanced, mergingState, writeMerging, readCaptcha, writeCaptcha } from './advanced-operations.ts';
import { readIntegration, writeIntegration } from './integration-operations.ts';
import { uploadImage, finalizeImage, imageState, imageInfo, uploadComplete, type PreparedImage, type ImageReceipt } from './image-operations.ts';
import { CliError } from './errors.ts';
import { summarizeApproval } from './approval-operations.ts';
import { watchlistValues } from './webhook-operations.ts';
import { readSignedExport } from './output.ts';
import { credentialMetadata } from './credential-operations.ts';
import { appClientMetadata } from './app-client-operations.ts';
import { domainState, normalizeCookieDomain } from './domain-operations.ts';
import { accountState, projectAccount } from './account-operations.ts';
import { validateUserMetadata } from './user-metadata-operations.ts';
import { writeAccess } from './access-operations.ts';
import { providerMetadata, providerList, readProvider, writeProvider, providerValidationFields, telegramMetadata, writeTelegram } from './provider-operations.ts';
import { prepareEmbeddedWalletUpdate } from './app-setting-operations.ts';
import { type CredentialStore, type Credentials, type ProfileConfig, type SecretRef, validateId } from './store.ts';
import { ORIGIN, DASHBOARD_APP_ID, operation, planRequest, validateUserId, type JsonObject, type Operation, type OperationInput, type RequestPlan } from './operations.ts';
export { ORIGIN, DASHBOARD_APP_ID, parsePatch, type JsonObject } from './operations.ts';
export type Fetcher = (url: string, init: RequestInit) => Promise<Response>;
export interface ExecutionOptions {
  appCredential?: string;
  appSecretStorage?: AppSecretSink;
  imageFile?: PreparedImage; imageReceipt?: ImageReceipt; stageOnly?: boolean;
  allowAccessChange?: boolean; enableAuth?: boolean; allowUnrestrictedJwt?: boolean;
  includeIdentities?: boolean; confirmAccount?: string; allowSelfImpact?: boolean; confirmWallet?: string;
  allowProduction?: boolean; all?: boolean; maxPages?: number; confirmName?: string; confirmOwner?: string; confirmUrl?: string; confirmDomain?: string; allowSessionImpact?: boolean;
  storeSecret?: (ref: SecretRef, value: string) => Promise<JsonObject>;
}

export function tokenClaims(token: string): { sub: string; exp: number; iat?: number } {
  try {
    if (token.length > 32_768 || token.split('.').length !== 3) throw new Error();
    const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
    if (claims.iss !== 'privy.io' || claims.aud !== DASHBOARD_APP_ID || typeof claims.sub !== 'string' || !Number.isFinite(claims.exp)) throw new Error();
    return claims;
  } catch { throw new CliError('WRONG_TOKEN', 'Expected a Privy dashboard session token, not an app secret or agent-wallet token.', 2); }
}

export class DashboardClient {
  constructor(
    private store: CredentialStore,
    private config: ProfileConfig,
    private fetcher: Fetcher = (url, init) => fetch(url, init),
    private signal?: AbortSignal,
  ) {}
  assertAllowed(appId: string): void {
    validateId(appId);
    if (this.config.blockedAppIds.includes(appId)) throw new CliError('APP_PROTECTED', 'This app is protected by the local profile. No app-specific request was sent.', 2);
  }
  private async raw(path: string, method: string, credentials: Credentials, body?: unknown, text = false, acknowledgementOnly = false): Promise<any> {
    // Defense in depth: credentials are only ever sent to the fixed HTTPS origin.
    const pathname = path.split('?')[0];
    if (!pathname.startsWith('/api/') || pathname.includes('..') || path.includes('\\') || path.includes('#')) throw new CliError('INVALID_PATH', 'Invalid API path.', 2);
    for (const match of path.matchAll(/\/apps\/([^/?]+)/g)) this.assertAllowed(decodeURIComponent(match[1]));
    this.signal?.throwIfAborted();
    let response: Response;
    try {
      response = await this.fetcher(ORIGIN + path, {
        method,
        headers: {
          authorization: `Bearer ${credentials.accessToken}`,
          'privy-app-id': DASHBOARD_APP_ID,
          'privy-client': 'privy-cli-unofficial:0.1.0',
          origin: ORIGIN,
          accept: 'application/json',
          ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
        },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
        redirect: 'error',
        signal: AbortSignal.any([AbortSignal.timeout(20_000), ...(this.signal ? [this.signal] : [])]),
      });
    } catch (cause) {
      const error = new CliError('NETWORK_ERROR', 'Request failed or timed out. Writes are not automatically retried; check the remote state before retrying.');
      error.details = { method, path: path.split('?')[0], requestMayHaveMutated: method !== 'GET' };
      if (cause instanceof Error && cause.name === 'TimeoutError') error.hint = 'The request exceeded the 20-second transport timeout. No automatic retry was attempted.';
      const code = (cause as { cause?: { code?: unknown } })?.cause?.code;
      if (typeof code === 'string' && /^[A-Z_]{2,60}$/.test(code)) error.hint = `Transport error: ${code}. No automatic retry was attempted.`;
      throw error;
    }
    if (!response.ok) {
      let code = '', validationFields: string[] = [];
      try { const data = await response.json() as JsonObject; if (typeof data.code === 'string' && /^[a-z_]{1,80}$/.test(data.code)) code = data.code; if (path.endsWith('/oauth/custom')) validationFields = providerValidationFields(data); } catch {}
      const advice = response.status === 401 ? 'Run auth login again.' : response.status === 403 ? 'Access denied; your account may require MFA or additional permissions.' : response.status === 429 ? 'Rate limited. Wait before retrying.' : response.status >= 500 ? `Server or gateway failure; this alone does not establish invalid credentials or a changed API contract.${method !== 'GET' ? ' The write or session refresh may have reached the server; inspect state before deciding whether to retry.' : ''} No automatic retry was attempted.` : 'The undocumented API may have changed; inspect the request contract.';
      const error = new CliError(code || 'API_ERROR', `Privy returned HTTP ${response.status}.`, 1, response.status);
      error.details = { method, path: path.split('?')[0], requestMayHaveMutated: method !== 'GET', ...(validationFields.length ? { validationFields } : {}) };
      error.hint = advice;
      const requestId = response.headers.get('x-request-id') ?? response.headers.get('cf-ray');
      if (requestId && /^[a-zA-Z0-9_:\-.]{1,128}$/.test(requestId)) error.requestId = requestId;
      const retryAfter = response.headers.get('retry-after');
      if (retryAfter && /^\d{1,6}$/.test(retryAfter)) error.retryAfterSeconds = Number(retryAfter);
      throw error;
    }
    if (acknowledgementOnly) {
      // Dashboard void-response hooks accept successful status without a JSON body.
      await response.body?.cancel().catch(() => {});
      return { httpStatus: response.status };
    }
    if (response.status === 204) return {};
    if (text) {
      const reader = response.body?.getReader();
      if (!reader) throw new CliError('INVALID_RESPONSE', 'Empty export response.');
      const chunks: Uint8Array[] = []; let bytes = 0;
      try {
        while (true) {
          const part = await reader.read(); if (part.done) break;
          bytes += part.value.byteLength;
          if (bytes > 64 * 1024 * 1024) { await reader.cancel(); throw new CliError('EXPORT_TOO_LARGE', 'Export exceeds the 64 MiB CLI download limit. No file was retained.'); }
          chunks.push(part.value);
        }
      } finally { reader.releaseLock(); }
      const value = Buffer.concat(chunks).toString('utf8');
      if (response.headers.get('content-type')?.includes('application/json')) {
        let parsed; try { parsed = JSON.parse(value); } catch {}
        if (typeof parsed !== 'string') throw new CliError('INVALID_RESPONSE', 'Expected a CSV export, not a JSON object.');
        return parsed;
      }
      if (!value || /^\s*</.test(value)) throw new CliError('INVALID_RESPONSE', 'Expected CSV, not an empty or HTML export.');
      return value;
    }
    try { return await response.json() as JsonObject; }
    catch {
      const error = new CliError('INVALID_RESPONSE', 'Privy returned a successful HTTP status, but the response could not be read as JSON.');
      error.details = { method, path: path.split('?')[0], requestMayHaveMutated: method !== 'GET', httpStatusAcknowledged: response.status };
      error.hint = method === 'GET' ? 'No write was sent by this request.' : 'The write or session refresh may have completed. Inspect remote state before any retry; no automatic retry occurred.';
      throw error;
    }
  }
  private async credentials(): Promise<Credentials> {
    const stored = await this.store.load();
    if (!stored) throw new CliError('NOT_LOGGED_IN', 'Run auth login first.');
    tokenClaims(stored.accessToken);
    return stored;
  }
  async refresh(force = true): Promise<Credentials> {
    const current = await this.credentials();
    if (!force && tokenClaims(current.accessToken).exp > Date.now() / 1000 + 60) return current;
    const data = await this.raw('/api/v1/sessions', 'POST', current, { refresh_token: current.refreshToken });
    if (data.session_update_action === 'clear') {
      throw new CliError('SESSION_EXPIRED', 'Privy reported that this session has expired. The local entry was retained; use auth login --replace for a fresh sign-in.');
    }
    if (data.session_update_action === 'ignore') {
      if (tokenClaims(current.accessToken).exp <= Date.now() / 1000) throw new CliError('SESSION_EXPIRED', 'No renewed token was issued. Run auth login again.');
      return current;
    }
    if (data.session_update_action !== 'set' || typeof data.token !== 'string' || !data.token || typeof data.refresh_token !== 'string' || !data.refresh_token) {
      throw new CliError('INVALID_SESSION_RESPONSE', 'Unexpected refresh response. Existing credentials were left intact.');
    }
    const claims = tokenClaims(data.token);
    if (claims.sub !== tokenClaims(current.accessToken).sub || claims.exp <= Date.now() / 1000) throw new CliError('INVALID_SESSION_RESPONSE', 'Refresh returned an unexpected identity or expired token.');
    const next = { accessToken: data.token, refreshToken: data.refresh_token };
    // Persist rotated credentials before another request can use them.
    await this.store.save(next);
    return next;
  }
  /** One explicit renewal attempt, then a direct access check (never a second refresh). */
  async renewAndVerifySession(): Promise<JsonObject> {
    const before = await this.credentials();
    let renewed: Credentials;
    try { renewed = await this.refresh(); }
    catch (cause) {
      if (cause instanceof CliError && (cause.status === 401 || cause.code === 'SESSION_EXPIRED')) {
        const error = new CliError('LOGIN_REQUIRED', 'The saved session could not be renewed. Fresh sign-in is required; use auth login --replace. No automatic login, logout or credential deletion occurred.', 2);
        error.details = { refreshAttempted: true, credentialsChanged: false, requiresFreshLogin: true, reason: cause.code, ...(cause.status ? { httpStatus: cause.status } : {}) };
        throw error;
      }
      // Transport errors/5xx/save failures can leave renewal uncertain. Never retry or fall back to login.
      if (cause instanceof CliError) {
        cause.details = { ...cause.details, phase: 'session_renewal', refreshAttempted: true };
        cause.hint = 'Renewal did not complete reliably. Do not automatically retry, log out or replace the session. Inspect auth status --remote before deciding the next action.';
      }
      throw cause;
    }
    const changed = before.accessToken !== renewed.accessToken || before.refreshToken !== renewed.refreshToken;
    try { await this.validateLogin(renewed); }
    catch (cause) {
      const error = new CliError('SESSION_ACCESS_UNVERIFIED', 'Session renewal returned, but dashboard access could not be verified. Any saved renewal was retained. Inspect auth status --remote; no second refresh or fresh login was attempted.');
      error.details = { refreshAttempted: true, credentialsChanged: changed, remoteVerified: false, ...(cause instanceof CliError ? { reason: cause.code, ...(cause.status ? { httpStatus: cause.status } : {}) } : {}) };
      throw error;
    }
    return { authenticated: true, remoteVerified: true, refreshAttempted: true, credentialsChanged: changed, sessionAction: changed ? 'refreshed' : 'reused', expiresAt: new Date(tokenClaims(renewed.accessToken).exp * 1000).toISOString() };
  }
  private async request(path: string, method = 'GET', body?: unknown, text = false, acknowledgementOnly = false): Promise<any> {
    // No retry loop: avoid duplicating writes or burning rotating refresh tokens.
    return this.raw(path, method, await this.refresh(false), body, text, acknowledgementOnly);
  }
  async validateLogin(value: Credentials): Promise<void> {
    if (tokenClaims(value.accessToken).exp <= Date.now() / 1000) throw new CliError('SESSION_EXPIRED', 'Login token already expired.');
    const data = await this.raw('/api/v1/teams', 'GET', value);
    if (!Array.isArray(data.data)) throw new CliError('INVALID_RESPONSE', 'Dashboard account validation returned an unexpected shape.');
  }
  async logout(localOnly = false): Promise<{ revoked: boolean; localCredentialsRemoved: boolean }> {
    if (localOnly) {
      await this.store.clear(); // Works even when the saved JSON is malformed.
      return { revoked: false, localCredentialsRemoved: true };
    }
    const credentials = await this.store.load();
    if (!credentials) return { revoked: false, localCredentialsRemoved: true };
    // Preserve credentials on revocation failure so the user can retry or explicitly choose --local.
    await this.raw('/api/v1/sessions/logout', 'POST', credentials, { refresh_token: credentials.refreshToken });
    await this.store.clear();
    return { revoked: true, localCredentialsRemoved: true };
  }
  async teams(): Promise<JsonObject[]> {
    const plan = this.preview('accounts.list', {});
    const data = await this.request(plan.path);
    if (!Array.isArray(data.data)) throw new CliError('INVALID_RESPONSE', 'Expected a list of dashboard accounts.');
    return data.data;
  }
  async authStatus(remote = false): Promise<JsonObject> {
    const stored = await this.store.load();
    if (!stored) return { state: 'no_credentials', credentialsPresent: false, remote: { checked: false }, refreshAttempted: false, credentialsChanged: false, nextStep: 'No saved dashboard session. Run auth login in an interactive terminal.' };
    const claims = tokenClaims(stored.accessToken);
    const local = { credentialsPresent: true, accessExpiresAt: new Date(claims.exp * 1000).toISOString(), accessExpired: claims.exp <= Date.now() / 1000, refreshAttempted: false, credentialsChanged: false };
    if (!remote) return { ...local, state: local.accessExpired ? 'access_expired' : 'access_unverified', remote: { checked: false }, refreshValidity: 'not_checked', note: 'Saved credentials are not proof of current access. Access-token expiry does not establish whether the session can be renewed.', nextStep: local.accessExpired ? 'Saved session credentials exist, but the access token has expired. Run auth login to attempt renewal, or auth refresh explicitly.' : 'Use auth status --remote to check access without changing credentials.' };
    try {
      const data = await this.raw('/api/v1/teams', 'GET', stored);
      if (!Array.isArray(data.data)) throw new CliError('INVALID_RESPONSE', 'Account validation returned an unexpected shape.');
      return { ...local, state: 'authenticated', remote: { checked: true, authenticated: true }, refreshValidity: 'not_checked' };
    } catch (error) {
      if (!(error instanceof CliError) || error.status !== 401) throw error;
      return { ...local, state: local.accessExpired ? 'access_expired' : 'access_rejected', remote: { checked: true, authenticated: false, httpStatus: 401 }, refreshValidity: 'unknown', nextStep: 'Saved session credentials exist, but access was rejected. Renewal validity is unknown. Run auth login to attempt renewal, or auth refresh explicitly. This status check did not renew or delete credentials.' };
    }
  }
  async whoami(): Promise<JsonObject> {
    const teams = await this.teams(); // Server validation, not just decoded JWT claims.
    const claims = tokenClaims((await this.credentials()).accessToken);
    return { authenticated: true, userId: claims.sub, expiresAt: new Date(claims.exp * 1000).toISOString(), accounts: teams.map(t => ({ id: t.id, name: t.name })) };
  }
  preview(id: string, input: OperationInput): RequestPlan {
    const plan = planRequest(operation(id), input);
    if (plan.pathParams.app_id) this.assertAllowed(plan.pathParams.app_id);
    if (operation(id).ecosystemConnection) for (const key of ['provider_app_id', 'requester_app_id']) if (plan.body?.[key]) {
      this.assertAllowed(plan.body[key]);
      if (plan.body[key] === plan.pathParams.app_id) throw new CliError('SELF_CONNECTION_REFUSED', 'A cross-app counterpart must be a different app.', 2);
    }
    return plan;
  }
  async execute(id: string, input: OperationInput, options: ExecutionOptions = {}): Promise<any> {
    const op = operation(id);
    const plan = this.preview(id, input); // Protect/validate before loading credentials or refreshing.
    if (op.clientPreflight) await this.execute('clients.get', { appId: input.appId, params: { client_id: plan.pathParams.client_id } });
    if (op.behavior === 'create-app' || op.credentialWrite === 'create') {
      if (!options.appSecretStorage || !['env', 'keychain', 'both', 'none'].includes(options.appSecretStorage.mode) || typeof options.appSecretStorage.save !== 'function') throw new CliError('APP_SECRET_STORAGE_REQUIRED', 'Select app secret storage before creation: env, keychain, both or none. No remote write was sent.', 2);
    } else if (op.secretSave && !options.storeSecret) throw new CliError('SECRET_STORE_REQUIRED', 'This operation requires an OS credential-store sink; raw secrets are never returned.');
    if (op.behavior === 'wallet-export-download') {
      const job = await this.execute('wallets.exports.get', { appId: input.appId, params: { job_id: plan.pathParams.job_id } });
      if (job.status !== 'completed' || job.download_ready !== true) throw new CliError('EXPORT_NOT_READY', 'This job is not ready for download. Empty analytics exports may reflect the dashboard’s 1–3 hour data delay.', 2);
      if (job.download_path !== plan.path) throw new CliError('EXPORT_PATH_MISMATCH', 'Job download path does not match the selected app/job. No download request was sent.');
      const bytes = typeof job.file_size_bytes === 'number' || typeof job.file_size_bytes === 'string' && /^\d+$/.test(job.file_size_bytes) ? Number(job.file_size_bytes) : NaN;
      if (!Number.isSafeInteger(bytes) || bytes <= 0 || bytes > 64 * 1024 * 1024) throw new CliError('INVALID_EXPORT_SIZE', 'Expected a nonempty export no larger than 64 MiB. No download request was sent.');
      const response = await this.request(plan.path);
      return readSignedExport(response?.download_url, bytes, this.fetcher, this.signal);
    }
    if (op.securitySetting || op.jwtAction) {
      const appId = plan.pathParams.app_id, mutating = op.method !== 'GET';
      if (mutating && (!options.allowAccessChange || !options.confirmName)) throw new CliError('ACCESS_CHANGE_CONFIRMATION_REQUIRED', 'Security/authentication changes require exact --confirm-name and --allow-access-change as well as --yes. No request was sent.', 2);
      if (op.securitySetting?.action === 'rotate' && !options.allowSessionImpact) throw new CliError('SESSION_IMPACT_CONFIRMATION_REQUIRED', 'Rotation requires --allow-session-impact. Direct key consumers need updating; successive rotations can invalidate sessions. No request was sent.', 2);
      const context = async () => { const app = await this.app(appId); return { app, account: owningAccount(app, await this.teams()) }; };
      const request = async (path: string, method?: string, body?: JsonObject, ack?: boolean) => { if (method && method !== 'GET') await this.checkEnvironment(appId, options.allowProduction); return this.request(path, method, body, false, ack); };
      if (mutating) await this.checkEnvironment(appId, options.allowProduction);
      if (op.jwtAction) return op.jwtAction === 'read' ? publicJwt(await jwtState(await context(), request)) : writeJwt(op, plan, context, request, options);
      return op.securitySetting!.action === 'read' ? securityState(op.securitySetting!.kind, await context(), request) : writeSecurity(op, plan, context, request, options.confirmName!);
    }
    if (op.availabilityAction || op.advancedAction) {
      const appId = plan.pathParams.app_id;
      const mutating = op.availabilityAction === 'update' || op.advancedAction === 'merging-update' || op.advancedAction === 'captcha-update';
      if (mutating && (!options.allowAccessChange || !options.confirmName)) throw new CliError('ACCESS_CHANGE_CONFIRMATION_REQUIRED', 'This change requires --allow-access-change and exact --confirm-name as well as --yes. No request was sent.', 2);
      const app = await this.app(appId);
      const request = async (path: string, method?: string, body?: JsonObject, ack?: boolean) => {
        if (method && method !== 'GET') await this.checkEnvironment(appId, options.allowProduction);
        return this.request(path, method, body, false, ack);
      };
      if (mutating) await this.checkEnvironment(appId, options.allowProduction);
      if (op.availabilityAction) {
        const context = async () => ({ app: await this.app(appId), teams: await this.teams() });
        return op.availabilityAction === 'read' ? availabilityState({ app, teams: await this.teams() }, request) : writeAvailability(plan, context, request, options.confirmName);
      }
      if (op.advancedAction === 'captcha-read') return readCaptcha(plan.path, request);
      if (op.advancedAction === 'captcha-update') return writeCaptcha(plan, () => this.app(appId), request, options.confirmName);
      if (op.advancedAction === 'inspect') return inspectAdvanced(app, await this.teams(), request);
      if (op.advancedAction === 'merging-read') return mergingState(app);
      return writeMerging(plan, () => this.app(appId), request, options.confirmName);
    }
    if (op.ecosystemConnection) {
      const appId = plan.pathParams.app_id;
      if (op.ecosystemConnection.action === 'list') {
        await this.app(appId);
        return connectionList(await this.request(plan.path), op.ecosystemConnection.side, this.config.blockedAppIds, options.all);
      }
      if (!options.allowAccessChange) throw new CliError('ACCESS_CHANGE_CONFIRMATION_REQUIRED', 'Cross-app access changes require --allow-access-change as well as --yes. No request was sent.', 2);
      await this.checkEnvironment(appId, options.allowProduction);
      return writeConnection(op, plan, async (path, method, body, acknowledgementOnly) => {
        if (method && method !== 'GET') await this.checkEnvironment(appId, options.allowProduction);
        return this.request(path, method, body, false, acknowledgementOnly);
      }, options.allowAccessChange);
    }
    if (op.integration) {
      const appId = plan.pathParams.app_id;
      if (op.integration.action === 'read') {
        await this.app(appId);
        return readIntegration(op.integration.kind, plan.path, (path) => this.request(path));
      }
      const checkIntegrationEnvironment = async () => {
        const app = await this.checkEnvironment(appId, options.allowProduction);
        if (op.integration!.kind === 'blockaid' && app.env !== 'prod') throw new CliError('BLOCKAID_PRODUCTION_REQUIRED', 'Transaction-scanning configuration can only be changed on a production app. Verified cookies do not remove this restriction. No production conversion, billing change or write was submitted.', 2);
      };
      await checkIntegrationEnvironment();
      return writeIntegration(op, plan, async (path, method, body, acknowledgementOnly) => {
        if (method && method !== 'GET') await checkIntegrationEnvironment();
        return this.request(path, method, body, false, acknowledgementOnly);
      });
    }
    if (op.imageAction) {
      const appId = plan.pathParams.app_id;
      if (op.imageAction === 'upload' && (!options.imageFile || !options.storeSecret)) throw new CliError('IMAGE_INPUT_REQUIRED', 'A validated local image and OS-vault checkpoint sink are required before uploading.', 2);
      if (['status', 'finalize'].includes(op.imageAction) && (!options.imageReceipt || options.imageReceipt.appId !== appId || options.imageReceipt.id !== plan.pathParams.upload_id)) throw new CliError('UPLOAD_CHECKPOINT_REQUIRED', 'This app/profile upload checkpoint is required.', 2);
      if (op.imageAction === 'upload' || op.imageAction === 'finalize') await this.checkEnvironment(appId, options.allowProduction);
      else await this.app(appId);
      if (op.imageAction === 'get') {
        const current = imageState(await this.request(plan.path));
        return { appId, iconUrl: current.icon_url, availability: current.availability };
      }
      if (op.imageAction === 'status') return { appId, uploadId: plan.pathParams.upload_id, complete: uploadComplete(await this.request(plan.path)), file: imageInfo(options.imageReceipt!) };
      const request = async (path: string, method = 'GET', body?: JsonObject) => {
        if (method !== 'GET') await this.checkEnvironment(appId, options.allowProduction);
        return this.request(path, method, body);
      };
      if (op.imageAction === 'finalize') return finalizeImage(appId, options.imageReceipt!, request);
      return uploadImage(appId, options.imageFile!, request, this.fetcher, options.storeSecret!, this.signal, options.stageOnly);
    }
    if (op.accountJwtFeature) return this.accountJwtFeature(plan.pathParams.account_id, op.accountJwtFeature === 'update' ? plan.body : undefined, options);
    if (op.accountBillingRead) {
      accountState(await this.teams(), plan.pathParams.account_id);
      const data = await this.request(plan.path);
      if (!data || !['free', 'dev', 'pro', 'core', 'scale', 'enterprise'].includes(data.tier)) throw new CliError('INVALID_BILLING_STATE', 'Expected a known account billing tier; no billing state was invented.');
      const method = data.defaultPaymentMethod;
      const paymentMethod = method === null ? 'absent' : method === undefined ? 'not_returned' : typeof method === 'string' && method.length > 0 || method && typeof method === 'object' && !Array.isArray(method) && Object.keys(method).length > 0 ? 'present' : 'unknown';
      return { accountId: plan.pathParams.account_id, tier: data.tier, paymentMethod, accountWide: true, cardDetailsOmitted: true, writesPerformed: false };
    }
    if (op.accountView) return projectAccount(accountState(await this.teams(), plan.pathParams.account_id), op.accountView, this.config.blockedAppIds, options.includeIdentities);
    if (op.accountWrite) return this.writeAccount(op, plan, options);
    if (op.behavior === 'accounts') return (await this.teams()).map(t => ({ id: t.id, name: t.name }));
    if (op.behavior === 'apps') {
      return (await this.teams()).flatMap(t => (t.apps ?? [])
        .filter((a: JsonObject) => !this.config.blockedAppIds.includes(a.id))
        .map((a: JsonObject) => ({ id: a.id, name: a.name, env: a.env, accountId: t.id, accountName: t.name })));
    }
    if (op.behavior === 'get-user') {
      const user = await this.findUser(plan.pathParams.app_id, plan.pathParams.user_id);
      if (!user) throw new CliError('USER_NOT_FOUND', 'No user with this exact ID was found in the selected app.', 2);
      return user;
    }
    if (op.behavior === 'get-wallet' || op.behavior === 'get-organization') {
      const wallet = op.behavior === 'get-wallet';
      const result = await this.findListedResource(wallet ? 'wallets.list' : 'organizations.list', plan.pathParams.app_id, plan.pathParams[wallet ? 'wallet_id' : 'organization_id'], wallet && plan.query.include_balance !== undefined ? { include_balance: plan.query.include_balance } : {});
      if (!result) throw new CliError('RESOURCE_NOT_FOUND', 'No exact resource match was found in this app.', 2);
      return result;
    }
    if (op.behavior === 'get-quorum') {
      const quorum = await this.findListedResource('key-quorums.list', plan.pathParams.app_id, plan.pathParams.key_quorum_id);
      if (!quorum) throw new CliError('QUORUM_NOT_FOUND', 'No exact key quorum match was found.', 2);
      return quorum;
    }
    if (op.publicOrganizationDelete) {
      const appId = plan.pathParams.app_id, id = plan.pathParams.organization_id;
      if (!options.appCredential) throw new CliError('APP_CREDENTIAL_REQUIRED', 'A stored app credential is required.', 2);
      if (!options.confirmName) throw new CliError('NAME_CONFIRMATION_REQUIRED', 'Pass --confirm-name with the exact organization name.', 2);
      await this.checkEnvironment(appId, options.allowProduction);
      const organization = await this.findListedResource('organizations.list', appId, id);
      if (!organization || organization.display_name !== options.confirmName) throw new CliError('ORGANIZATION_NAME_MISMATCH', 'No organization with this ID and exact name was found in the selected app. No delete was sent.', 2);
      if (organization.wallet_count !== 0) throw new CliError('ORGANIZATION_NOT_EMPTY', 'Deletion requires a known zero wallet count. No implicit unbinding or deletion of wallets.', 2);
      const bindings = await this.requestAppApi(appId, options.appCredential, `/v1/wallets?entity_id=${id}&include_archived=true&limit=1`);
      if (!Array.isArray(bindings?.data) || bindings.data.length || bindings.next_cursor) throw new CliError('ORGANIZATION_NOT_EMPTY', 'Active/archived wallet bindings exist or absence is unverified. No delete was sent.', 2);
      const current = await this.requestAppApi(appId, options.appCredential, plan.path);
      if (current?.id !== id || current.display_name !== options.confirmName) throw new CliError('ORGANIZATION_NAME_MISMATCH', 'Public API organization does not match the confirmed name. No delete was sent.', 2);
      await this.requestAppApi(appId, options.appCredential, plan.path, 'DELETE', undefined, true);
      try {
        let absent = false;
        try { await this.requestAppApi(appId, options.appCredential, plan.path); }
        catch (error) { if (error instanceof CliError && error.status === 404) absent = true; else throw error; }
        const accessible = await this.requestAppApi(appId, options.appCredential, '/v1/organizations?limit=1');
        if (!absent || !Array.isArray(accessible?.data)) throw new Error();
        return { appId, organizationId: id, deleted: true, verified: true, walletsModified: false, quorumMutationRequested: false };
      } catch { throw new CliError('ORGANIZATION_DELETE_VERIFY_FAILED', 'Deletion was acknowledged but fresh absence/access could not be established. Inspect organizations list before retrying.'); }
    }
    if (op.publicWallet) {
      if (!options.appCredential) throw new CliError('APP_CREDENTIAL_REQUIRED', 'A stored app credential is required; dashboard tokens are never sent to the public API.', 2);
      const appId = plan.pathParams.app_id, walletId = plan.pathParams.wallet_id;
      if (op.publicWallet === 'get') await this.app(appId);
      else {
        if (options.confirmWallet !== walletId) throw new CliError('WALLET_CONFIRMATION_REQUIRED', 'Pass --confirm-wallet with the exact wallet ID. Archive prevents writes/signing; this CLI does not restore it.', 2);
        await this.checkEnvironment(appId, options.allowProduction);
        const wallet = await this.findListedResource('wallets.list', appId, walletId);
        if (!wallet) throw new CliError('WALLET_NOT_FOUND', 'No active wallet found in this app. Inspect archive-status before retrying.', 2);
        if (wallet.type !== 'server' || this.walletValues(wallet).owner_id !== null) throw new CliError('WALLET_OWNER_APPROVAL_REQUIRED', 'CLI archiving is restricted to unowned server wallets. No owner-authorized mutation was sent.', 2);
      }
      const read = async (): Promise<JsonObject> => {
        const wallet = await this.requestAppApi(appId, options.appCredential!, `/v1/wallets/${walletId}?include_archived=true`);
        if (wallet?.id !== walletId || typeof wallet.address !== 'string' || typeof wallet.chain_type !== 'string' || !(wallet.owner_id === null || typeof wallet.owner_id === 'string') || !(wallet.archived_at === null || Number.isSafeInteger(wallet.archived_at) && wallet.archived_at > 0)) throw new CliError('INVALID_WALLET_STATE', 'Public API did not return the exact wallet with a usable archive state.');
        return { id: wallet.id, address: wallet.address, chain_type: wallet.chain_type, display_name: wallet.display_name ?? null, owner_id: wallet.owner_id, archived_at: wallet.archived_at, archived: wallet.archived_at !== null };
      };
      const before = await read();
      if (op.publicWallet === 'get') return before;
      if (before.owner_id !== null) throw new CliError('WALLET_OWNER_APPROVAL_REQUIRED', 'Fresh public wallet state is owner-controlled. No archive was sent.', 2);
      if (before.archived) throw new CliError('WALLET_ALREADY_ARCHIVED', 'Wallet is already archived. No write was sent.', 2);
      await this.requestAppApi(appId, options.appCredential, plan.path, 'POST', undefined, true);
      try {
        const after = await read();
        if (!after.archived) throw new Error();
        return { appId, verified: true, wallet: after, signingAttempted: false, deleted: false, restorationImplemented: false };
      } catch { throw new CliError('WALLET_ARCHIVE_VERIFY_FAILED', 'Archive was acknowledged but fresh archive metadata could not be verified. Inspect archive-status; no retry occurred.'); }
    }
    if (op.publicUserMetadata) {
      if (!options.appCredential) throw new CliError('APP_CREDENTIAL_REQUIRED', 'A stored app credential is required; dashboard tokens are not app credentials.', 2);
      await this.checkEnvironment(plan.pathParams.app_id, options.allowProduction);
      const before = await this.findUser(plan.pathParams.app_id, plan.pathParams.user_id);
      if (!before) throw new CliError('USER_NOT_FOUND', 'User was not found in the selected app. No write was sent.', 2);
      const expected = op.method === 'PATCH' ? { ...(before.custom_metadata ?? {}), ...plan.body!.custom_metadata } : plan.body!.custom_metadata;
      validateUserMetadata(expected);
      await this.requestAppApi(plan.pathParams.app_id, options.appCredential, plan.path, op.method, plan.body, true);
      try {
        const after = await this.findUser(plan.pathParams.app_id, plan.pathParams.user_id);
        if (!after || !isDeepStrictEqual(after.custom_metadata ?? {}, expected)) throw new Error();
        return { appId: plan.pathParams.app_id, userId: plan.pathParams.user_id, verified: true, mode: op.method === 'PATCH' ? 'shallow-merge' : 'replace', custom_metadata: after.custom_metadata ?? {} };
      } catch { throw new CliError('METADATA_VERIFY_FAILED', 'App API write acknowledged but dashboard read-back did not match. Inspect metadata; no write was repeated.'); }
    }
    if (op.accessWrite) {
      await this.checkEnvironment(plan.pathParams.app_id, options.allowProduction);
      return writeAccess(op, plan, (path, method, body, ack) => this.request(path, method, body, false, ack));
    }
    if (op.telegram) {
      const app = op.telegram === 'read' ? await this.app(plan.pathParams.app_id) : await this.checkEnvironment(plan.pathParams.app_id, options.allowProduction);
      const request = async (path: string, method = 'GET', body?: JsonObject, ack?: boolean): Promise<any> => {
        try { return await this.request(path, method, body, false, ack); }
        catch (error) { if (method === 'GET' && error instanceof CliError && error.status === 404) return { absent: true }; throw error; }
      };
      if (op.telegram === 'read') return telegramMetadata(await request(plan.path));
      if (op.telegram === 'delete' && !plan.pathParams.client_id && app.telegram_auth) throw new CliError('PROVIDER_IN_USE', 'Disable bot-based telegram_auth before deleting app bot configuration. No implicit login toggle or write was sent.', 2);
      return writeTelegram(op, plan, request);
    }
    if (op.providerRead) {
      const raw = await this.request(plan.path);
      return op.providerRead === 'one' ? providerMetadata(raw) : { data: providerList(raw).map(providerMetadata) };
    }
    if (op.providerWrite) {
      const app = await this.checkEnvironment(plan.pathParams.app_id, options.allowProduction);
      const builtinName = plan.pathParams.provider;
      if (op.providerWrite === 'delete' && ['spotify', 'instagram', 'telegram'].includes(builtinName) && app[`${builtinName}_oauth`]) throw new CliError('PROVIDER_IN_USE', 'Disable this bring-your-own-only OAuth login method before removing its credentials. No implicit toggle or write was sent.', 2);
      if (op.providerWrite === 'create-custom' || op.providerWrite === 'enable-custom' && plan.body!.enabled === true) {
        await this.checkOAuthCompatibility(plan.pathParams.app_id);
        if (app.env !== 'dev') {
          const account = (await this.teams()).find(t => t.apps?.some((a: JsonObject) => a.id === app.id));
          if (account?.customOAuthEnabled !== true) throw new CliError('PROVIDER_FEATURE_UNAVAILABLE', 'Custom OAuth is not enabled for this production account. No feature/billing change or write was sent.', 2);
        }
      }
      return writeProvider(op, plan, (path, method, body, ack) => this.request(path, method, body, false, ack));
    }
    if (op.settingsWrite) return this.writeSetting(op, plan, options);
    if (op.domainWrite) return this.writeDomain(op, plan, options);
    if (op.appClientWrite) return this.writeAppClient(op, plan, options);
    if (op.credentialWrite) return this.writeCredential(op, plan, options);
    if (op.webhookWrite) return this.writeWebhook(op, plan, options);
    if (op.organizationWrite) return this.writeOrganization(op, plan, options);
    if (op.quorumWrite) return this.writeQuorum(plan, options);
    if (op.walletWrite) return this.writeWallet(op, plan, options);
    if (op.userWrite) return this.writeUser(op, plan, options.allowProduction);
    if (op.policyWrite) return this.writePolicy(op, plan, input, options.allowProduction, options.confirmOwner);
    if (op.pagination) {
      const maxPages = options.all ? options.maxPages ?? 10 : 1;
      if (!Number.isInteger(maxPages) || maxPages < 1 || maxPages > 100) throw new CliError('INVALID_INPUT', 'Maximum pages must be 1–100.', 2);
      const rows: JsonObject[] = [], seen = new Set<string>();
      const pageCounts: number[] = [], returnedPageCounts: number[] = [];
      let cursor = plan.query.cursor, nextCursor: string | null = null, pages = 0, pageSizeExceeded = false;
      if (cursor) seen.add(cursor);
      do {
        const pagePlan = this.preview(id, { ...input, query: { ...plan.query, ...(cursor ? { cursor } : {}) } });
        const page = await this.request(pagePlan.path);
        const continuation = op.pagination.doneField && page?.[op.pagination.doneField] === true ? null : page?.[op.pagination.nextCursor];
        if (!page || !Array.isArray(page[op.pagination.items]) || op.pagination.doneField && typeof page[op.pagination.doneField] !== 'boolean' || !(continuation === null || typeof continuation === 'string' && continuation.length > 0)) throw new CliError('INVALID_PAGE', 'The API returned an unexpected pagination envelope. No incomplete result was reported as complete.');
        const items = op.pagination.cursorMode === 'last-item-id' ? page[op.pagination.items].slice(0, pagePlan.query.limit) : page[op.pagination.items];
        if (items.length > pagePlan.query.limit) pageSizeExceeded = true;
        rows.push(...items);
        pageCounts.push(items.length); returnedPageCounts.push(page[op.pagination.items].length);
        pages++;
        nextCursor = continuation;
        if (op.pagination.cursorMode === 'last-item-id') {
          // Wallet cursors point to an omitted row; quorum pages can include a lookahead row.
          // Both consume cursors exclusively. Match the dashboard's last-displayed-ID continuation.
          if (items.length && (items.length >= pagePlan.query.limit || nextCursor)) {
            const last = items.at(-1)?.id;
            if (typeof last !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(last)) throw new CliError('INVALID_PAGE', 'Cannot derive a safe continuation ID from this page.');
            nextCursor = last;
          } else if (!items.length && nextCursor) throw new CliError('INVALID_PAGE', 'Empty page contained an unexplained continuation cursor.');
        }
        if (nextCursor && seen.has(nextCursor)) throw new CliError('PAGINATION_LOOP', 'The API repeated a cursor. Pagination stopped; results were not reported as complete.');
        if (nextCursor) seen.add(nextCursor);
        cursor = nextCursor;
      } while (cursor && pages < maxPages);
      return { data: op.approvalSummary ? rows.map(row => summarizeApproval(row, plan.pathParams.app_id)) : rows, next_cursor: nextCursor, has_more: Boolean(nextCursor), pages_read: pages,
        pagination: { requested_limit: plan.query.limit, page_counts: pageCounts, returned_page_counts: returnedPageCounts, continuation_available: Boolean(nextCursor), end_reason: nextCursor ? options.all ? 'max_pages_reached' : 'single_page' : 'cursor_exhausted', continuation_basis: op.pagination.cursorMode === 'last-item-id' ? 'last_displayed_id' : op.pagination.doneField ? 'server_done_and_cursor' : 'server_cursor', has_more_meaning: 'A continuation is available; another nonempty page is not guaranteed.' },
        ...(pageSizeExceeded ? { requested_page_size: plan.query.limit, page_size_warning: 'The API returned more rows than requested for this query mode. Rows were retained rather than silently discarded.' } : {}),
        ...(options.all ? { truncated: Boolean(nextCursor), max_pages: maxPages } : {}) };
    }
    if (op.behavior === 'delete-app') {
      if (typeof options.confirmName !== 'string' || !options.confirmName.length || options.confirmName.length > 100) {
        throw new CliError('NAME_CONFIRMATION_REQUIRED', 'Deletion requires --confirm-name with the exact current app name. No request was sent.', 2);
      }
      const current = await this.app(input.appId!);
      if (current.env !== 'dev') throw new CliError('APP_DELETE_DEV_ONLY', 'Only development (dev) apps can be deleted with this CLI. No write was sent.', 2);
      if (current.name !== options.confirmName) throw new CliError('APP_NAME_MISMATCH', 'The confirmation name does not match the app. No write was sent.', 2);
      const accounts = await this.teams();
      const account = accounts.find(t => Array.isArray(t.apps) && t.apps.some((a: JsonObject) => a.id === input.appId));
      if (typeof account?.id !== 'string') throw new CliError('APP_ACCOUNT_UNVERIFIED', 'Cannot verify the app account before deletion. No write was sent.');
      await this.request(plan.path, plan.method, plan.body);
      // Deleted dashboard config reads return HTTP 400, not a reliable 404 contract.
      // Verify disappearance from the same account while requiring that account to remain visible.
      try {
        const after = (await this.teams()).find(t => t.id === account.id);
        if (after && Array.isArray(after.apps) && !after.apps.some((a: JsonObject) => a.id === input.appId)) {
          return { appId: input.appId, deleted: true, verified: true, verification: 'account-app-list' };
        }
      } catch { /* Do not interpret permission/network failures as successful deletion. */ }
      throw new CliError('DELETE_VERIFY_FAILED', 'Deletion request succeeded but absence from the same account could not be verified. Inspect remote state before retrying.');
    }
    if (op.behavior === 'update-app') {
      const current = await this.checkEnvironment(input.appId!, options.allowProduction);
      if (Object.entries(plan.body!).some(([key, value]) => key.endsWith('_oauth') && value === true)) await this.checkOAuthCompatibility(plan.pathParams.app_id);
      for (const provider of ['spotify', 'instagram', 'telegram']) if (plan.body![`${provider}_oauth`] === true) {
        const state = await readProvider((path) => this.request(path), plan.pathParams.app_id, provider);
        if (state.editable !== true || !state.config?.client_id || !state.config?.client_secret) throw new CliError('PROVIDER_CREDENTIALS_REQUIRED', `${provider} requires own OAuth configuration before enabling. No write was sent.`, 2);
      }
      if (plan.body!.telegram_auth === true && !telegramMetadata(await this.request(`/api/v1/apps/${plan.pathParams.app_id}/telegram/configuration`)).configured) throw new CliError('TELEGRAM_CONFIG_REQUIRED', 'Configure an app Telegram bot before enabling bot-based login. No write was sent.', 2);
      if (['farcaster_link_wallets_enabled', 'wallet_auth'].some(key => Object.hasOwn(plan.body!, key))) {
        const next = { ...current, ...plan.body };
        if (next.farcaster_link_wallets_enabled && !next.wallet_auth) throw new CliError('FARCASTER_WALLET_AUTH_REQUIRED', 'Farcaster wallet linking requires Ethereum external-wallet login. Disable linking before turning wallet login off.', 2);
      }
      if (['passkey_auth', 'passkeys_for_signup_enabled'].some(key => Object.hasOwn(plan.body!, key))) {
        const next = { ...current, ...plan.body };
        if (next.passkeys_for_signup_enabled && !next.passkey_auth) throw new CliError('PASSKEY_AUTH_REQUIRED', 'Passkey signup requires passkey login. Explicitly enable login, or disable signup when turning passkey login off. No write was sent.', 2);
      }
      if (['require_users_accept_terms', 'terms_and_conditions_url', 'privacy_policy_url'].some(key => Object.hasOwn(plan.body!, key))) {
        const next = { ...current, ...plan.body };
        if (next.require_users_accept_terms && !next.terms_and_conditions_url && !next.privacy_policy_url) throw new CliError('LEGAL_LINK_REQUIRED', 'Affirmative consent requires at least one legal link. Configure a link or explicitly disable consent before clearing both. No write was sent.', 2);
      }
    }
    let data = await this.request(plan.path, plan.method, plan.body, Boolean(op.download));
    if (op.selectFields) {
      if (!data || typeof data !== 'object' || Array.isArray(data) || op.selectFields.some(key => !Object.hasOwn(data, key))) throw new CliError('INVALID_RESPONSE', 'Expected configuration fields are missing.');
      data = Object.fromEntries(op.selectFields.map(key => [key, data[key]]));
    }
    if (op.appClientSummary) data = appClientMetadata(data, plan.pathParams.app_id);
    if (op.approvalSummary) return summarizeApproval(data, plan.pathParams.app_id, plan.pathParams.intent_id);
    if (op.behavior === 'credential-metadata') return credentialMetadata(data);
    if (op.behavior === 'webhook-subscriptions') return this.webhookSubscriptions(data);
    if (op.selectFromArray) {
      if (!Array.isArray(data)) throw new CliError('INVALID_RESPONSE', 'Expected a resource list for exact-ID lookup.');
      const found = data.filter(row => row?.[op.selectArrayId ?? 'id'] === plan.pathParams[op.selectFromArray!]);
      if (found.length !== 1) throw new CliError('RESOURCE_NOT_FOUND', 'No unique resource with this ID was found in the selected app.', 2);
      return found[0];
    }
    if (op.behavior === 'create-app') {
      if (typeof data.app?.id !== 'string') throw new CliError('INVALID_RESPONSE', 'Unexpected creation response. Check the dashboard before retrying.');
      const id = validateId(data.app.id);
      this.assertAllowed(id);
      // Older create responses return a string; richer responses may include credential metadata.
      const generated = data.secret;
      let ref: SecretRef = { appId: id, kind: 'app-secret', id: 'initial' };
      if (generated && typeof generated === 'object' && typeof generated.id === 'string') {
        try { ref = { appId: id, kind: 'app-credential', id: validateId(generated.id) }; } catch { /* Retain under the explicit initial-key reference, not an invented remote ID. */ }
      }
      const storage = await options.appSecretStorage!.save(ref, typeof generated === 'string' ? generated : generated?.plain_text_secret);
      let created: JsonObject;
      try {
        created = await this.app(id);
        if (created.id !== id || created.name !== plan.body!.name || typeof created.env !== 'string') throw new Error();
      } catch {
        const error = new CliError('CREATE_VERIFY_FAILED', `App ${id} was created but read-back failed or differed. Inspect apps list and the reported storage; do not repeat creation.`);
        error.details = { appId: id, storage, remoteCreated: true, valuePrinted: false }; throw error;
      }
      return { id, name: created.name, env: created.env, verified: true, storage, valuePrinted: false };
    }
    if (op.behavior === 'update-app') {
      const actual = await this.app(input.appId!);
      const fields = Object.keys(plan.body!);
      const mismatches = fields.filter(k => JSON.stringify(actual[k]) !== JSON.stringify(plan.body![k]));
      if (mismatches.length) throw new CliError('VERIFY_FAILED', `Read-back differed for: ${mismatches.join(', ')}. Inspect config before retrying.`);
      return { appId: input.appId, verified: true, values: Object.fromEntries(fields.map(k => [k, actual[k]])) };
    }
    return data;
  }
  private async findListedResource(list: string, appId: string, id: string, query: JsonObject = {}): Promise<JsonObject | null> {
    const page = await this.execute(list, { appId, query: { query: id, limit: 100, ...query } }, { all: true, maxPages: 10 });
    const matches = page.data.filter((row: JsonObject) => row?.id === id);
    if (matches.length > 1) throw new CliError('INVALID_RESPONSE', 'Exact lookup returned duplicate IDs.');
    if (matches.length === 1) return matches[0];
    if (page.has_more) throw new CliError('LOOKUP_INCOMPLETE', 'Lookup reached its page bound; absence was not established.');
    return null;
  }
  private async findUser(appId: string, id: string): Promise<JsonObject | null> {
    return this.findListedResource('users.list', appId, validateUserId(id));
  }
  private async requestAppApi(appId: string, credential: string, path: string, method = 'GET', body?: JsonObject, acknowledgementOnly = false): Promise<any> {
    if (!path.startsWith('/v1/') || path.includes('://')) throw new CliError('INVALID_APP_API_PATH', 'Refusing an unexpected public API path.');
    let response: Response;
    try {
      response = await this.fetcher(`https://api.privy.io${path}`, { method, headers: { authorization: `Basic ${Buffer.from(`${appId}:${credential}`).toString('base64')}`, 'privy-app-id': appId, 'content-type': 'application/json' }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}), redirect: 'error', credentials: 'omit', signal: this.signal ? AbortSignal.any([this.signal, AbortSignal.timeout(20000)]) : AbortSignal.timeout(20000) });
    } catch {
      const error = new CliError('APP_API_NETWORK_ERROR', 'App API request failed or timed out. Writes may have mutated; inspect remote state before retrying. No automatic retry occurred.');
      error.details = { method, path: path.split('?')[0], requestMayHaveMutated: method !== 'GET' }; throw error;
    }
    if (!response.ok || acknowledgementOnly) await response.body?.cancel().catch(() => {});
    if (!response.ok) {
      const error = new CliError('APP_API_ERROR', `App API returned HTTP ${response.status}. No raw response or credentials are exposed. Inspect remote state before retrying.`, 1, response.status);
      error.details = { method, path: path.split('?')[0], requestMayHaveMutated: method !== 'GET' }; throw error;
    }
    if (acknowledgementOnly) return null;
    try { return await response.json(); } catch { throw new CliError('INVALID_APP_API_RESPONSE', 'Public API returned an unreadable response. No retry occurred.'); }
  }
  private async checkOAuthCompatibility(appId: string): Promise<void> {
    let state: JsonObject;
    try { state = await this.request(`/api/v1/apps/${appId}/mfa_configuration`); }
    catch (error) {
      // Fresh app access was established by the caller. Unconfigured MFA returns 404;
      // the dashboard's optional configuration hook treats this as inactive too.
      if (error instanceof CliError && error.status === 404) return;
      throw error;
    }
    if (typeof state?.enabled !== 'boolean' || state.enabled && typeof state?.email_enabled !== 'boolean') throw new CliError('AUTH_CONSTRAINT_UNVERIFIED', 'Cannot establish the dashboard OAuth/email-MFA compatibility constraint. No write was sent.');
    if (state.enabled && state.email_enabled) throw new CliError('AUTH_METHOD_CONFLICT', 'Dashboard disallows enabling this OAuth method while email MFA is active. No MFA configuration or login setting was changed.', 2);
  }
  private async accountJwtFeature(accountId: string, body?: JsonObject, options: ExecutionOptions = {}): Promise<JsonObject> {
    if (body && (!options.confirmAccount || !options.allowAccessChange)) throw new CliError('ACCOUNT_CONFIRMATION_REQUIRED', 'Account JWT capability changes require exact --confirm-account and --allow-access-change as well as --yes. No request was sent.', 2);
    const load = async () => accountState(await this.teams(), accountId);
    const before = await load();
    const protectedAccount = before.apps.some((a: JsonObject) => this.config.blockedAppIds.includes(a.id));
    const validApps = before.apps.every((a: JsonObject) => typeof a.id === 'string' && ['dev', 'prod'].includes(a.env)) && new Set(before.apps.map((a: JsonObject) => a.id)).size === before.apps.length;
    if (body) {
      if (protectedAccount) throw new CliError('PROTECTED_ACCOUNT', 'This account contains a protected app. No app-specific reads or account write were sent.', 2);
      if (options.confirmAccount !== before.name || !options.allowAccessChange) throw new CliError('ACCOUNT_CONFIRMATION_REQUIRED', 'Account JWT capability changes require exact --confirm-account and --allow-access-change as well as --yes. No write was sent.', 2);
      if (!validApps || before.apps.length > 100 || before.members.some((m: JsonObject) => typeof m.id !== 'string' || typeof m.user?.id !== 'string' || typeof m.role !== 'string')) throw new CliError('INVALID_ACCOUNT_STATE', 'Cannot establish bounded complete app/member state (maximum100 apps). No write was sent.', 2);
    }
    const billing = await this.request(`/api/v1/teams/${accountId}/billing`);
    const enabled = typeof before.customJwtAccountEnabled === 'boolean' ? before.customJwtAccountEnabled : null;
    const allDevelopment = validApps && before.apps.every((a: JsonObject) => a.env === 'dev');
    const state = { accountId, feature: 'custom_jwt_auth', enabled, accountWide: true, appCount: before.apps.length, tier: ['free', 'dev', 'pro', 'core', 'scale', 'enterprise'].includes(billing?.tier) ? billing.tier : null, allDevelopment, protectedAccount, eligibleForCliMutation: enabled !== null && billing?.tier === 'free' && allDevelopment && !protectedAccount && before.apps.length <= 100 };
    if (!body) return { ...state, writesPerformed: false, note: 'Account capability only. App authentication and verifier setup are separate. Mutation support is deliberately limited to free, all-development workspaces.' };
    if (!state.eligibleForCliMutation) throw new CliError('JWT_FEATURE_SCOPE_UNSUPPORTED', 'This command only changes a known JWT feature in free, all-development workspaces. No checkout, production override or approval request; no write was sent.', 2);
    const authority = (a: JsonObject) => ({ name: a.name, apps: a.apps.map((v: JsonObject) => [v.id, v.env]).sort(), members: a.members.map((m: JsonObject) => [m.id, m.user?.id, m.role]).sort(), flags: Object.fromEntries(['customOAuthEnabled', 'clientKeyExportAllowed', 'keyExportToggleAllowed', 'globalWalletConnectEnabledAt'].map(k => [k, a[k]])) });
    const appFlags = async (account: JsonObject) => {
      const rows = [];
      for (const row of [...account.apps].sort((a, b) => a.id.localeCompare(b.id))) {
        const app = await this.app(row.id);
        if (app.env !== 'dev' || typeof app.custom_jwt_auth !== 'boolean') throw new CliError('INVALID_APP_STATE', 'Cannot establish development app JWT state. No further feature write was sent.');
        rows.push({ id: app.id, enabled: app.custom_jwt_auth });
      }
      return rows;
    };
    const apps = await appFlags(before);
    if (!body.enabled && apps.some(a => a.enabled)) throw new CliError('JWT_FEATURE_IN_USE', 'Disable JWT authentication explicitly on each active app before disabling the account capability. No account write was sent.', 2);
    const latest = await load();
    if (!isDeepStrictEqual(authority(before), authority(latest)) || latest.customJwtAccountEnabled !== enabled || (await this.request(`/api/v1/teams/${accountId}/billing`))?.tier !== 'free' || !isDeepStrictEqual(apps, await appFlags(latest))) throw new CliError('ACCOUNT_STATE_CHANGED', 'Account/app JWT, membership or billing state changed during preflight. No write was sent.', 2);
    if (enabled === body.enabled) return { ...state, verified: true, alreadyApplied: true, writesPerformed: false };
    await this.request(`/api/v1/teams/${accountId}/features`, 'POST', { feature_name: 'custom_jwt_auth', enabled: body.enabled }, false, true);
    try {
      const after = await load();
      if (after.customJwtAccountEnabled !== body.enabled || !isDeepStrictEqual(authority(before), authority(after)) || (await this.request(`/api/v1/teams/${accountId}/billing`))?.tier !== 'free' || !isDeepStrictEqual(apps, await appFlags(after))) throw new Error();
      return { ...state, enabled: after.customJwtAccountEnabled, verified: true, writesPerformed: true, appAuthenticationUnchanged: true, billingTierUnchanged: true, billingWriteSent: false, externalLoginVerified: false };
    } catch { const error = new CliError('ACCOUNT_FEATURE_VERIFY_FAILED', 'Feature write acknowledged but unchanged account/app/billing state could not be verified. Inspect current state; no retry or rollback occurred.'); error.details = { accountId, requestMayHaveMutated: true }; throw error; }
  }
  private async writeAccount(op: Operation, plan: RequestPlan, options: ExecutionOptions): Promise<JsonObject> {
    const accountId = plan.pathParams.account_id, before = accountState(await this.teams(), accountId), body = plan.body!;
    if (before.apps.some((app: JsonObject) => typeof app.id !== 'string' || !['dev', 'prod'].includes(app.env))) throw new CliError('INVALID_ACCOUNT_STATE', 'Cannot establish every account app identity/environment. No write was sent.');
    if (before.apps.some((app: JsonObject) => this.config.blockedAppIds.includes(app.id))) throw new CliError('PROTECTED_ACCOUNT', 'This account contains a protected app. Account-wide mutations are refused; no app-specific dependency reads or writes were sent.', 2);
    if (options.confirmAccount !== before.name) throw new CliError('ACCOUNT_CONFIRMATION_REQUIRED', 'Pass --confirm-account with the exact current account name. No write was sent.', 2);
    if (before.apps.some((app: JsonObject) => app.env === 'prod') && !options.allowProduction) throw new CliError('PRODUCTION_CONFIRMATION_REQUIRED', 'This account contains production apps; --allow-production is also required.', 2);
    const matches = op.accountWrite === 'role' ? before.members.filter((m: JsonObject) => m.id === body.admin_id) : op.accountWrite === 'remove' ? before.members.filter((m: JsonObject) => m.user?.id && validateUserId(m.user.id) === body.user_id) : [];
    const member = matches[0];
    if (op.accountWrite === 'role' || op.accountWrite === 'remove') {
      if (matches.length !== 1 || typeof member.user?.id !== 'string' || !['admin', 'developer', 'billing', 'viewer'].includes(member.role)) throw new CliError('MEMBER_NOT_FOUND', 'No unique complete membership matches this ID.', 2);
      if (member.role === 'admin' && (op.accountWrite === 'remove' || body.role !== 'admin') && before.members.filter((m: JsonObject) => m.role === 'admin').length <= 1) throw new CliError('LAST_ADMIN', 'Cannot remove or demote the last account admin.', 2);
      if (validateUserId(member.user.id) === validateUserId(tokenClaims((await this.credentials()).accessToken).sub) && !options.allowSelfImpact) throw new CliError('SELF_IMPACT_CONFIRMATION_REQUIRED', 'Changing your own membership requires --allow-self-impact; access may be lost.', 2);
      if (op.accountWrite === 'remove' && before.apps.length > 100) throw new CliError('ACCOUNT_SCOPE_TOO_LARGE', 'Member-removal dependency checks are capped at 100 apps. No app-specific requests or write were sent.', 2);
      if (op.accountWrite === 'remove') for (const app of before.apps) {
        const dependencies = await this.execute('key-quorums.list', { appId: app.id, query: { member_id: member.user.id.replace(/^did:privy:/, ''), limit: 100 } }, { all: true, maxPages: 10 });
        if (dependencies.has_more || dependencies.data.length) throw new CliError('MEMBER_QUORUM_DEPENDENCY', 'Member has quorum dependencies or the lookup is incomplete. Resolve owner authorization separately; no member removal was sent.', 2);
      }
    }
    const email = body.email_address?.toLowerCase();
    const pending = before.invitedMembers.filter((m: JsonObject) => typeof m.address === 'string' && m.address.toLowerCase() === email);
    if (op.accountWrite === 'invite' && (pending.length || before.members.some((m: JsonObject) => m.user?.linked_accounts?.some((a: JsonObject) => (a.address ?? a.email)?.toLowerCase() === email)))) throw new CliError('INVITATION_OR_MEMBER_EXISTS', 'This identity is already invited or a member. No duplicate invitation was sent.', 2);
    if (op.accountWrite === 'revoke' && pending.length !== 1) throw new CliError('INVITATION_NOT_FOUND', 'No unique pending invitation matches this email.', 2);
    const authorityState = (account: JsonObject): JsonObject => ({ name: account.name, apps: account.apps.map((app: JsonObject) => [app.id, app.env]).sort(), members: account.members.map((member: JsonObject) => [member.id, member.user?.id, member.role]).sort(), invitations: account.invitedMembers.map((invite: JsonObject) => [invite.type, invite.address, invite.role]).sort() });
    const latest = accountState(await this.teams(), accountId);
    if (!isDeepStrictEqual(authorityState(latest), authorityState(before))) throw new CliError('ACCOUNT_STATE_CHANGED', 'Account apps or membership changed during preflight. Review fresh state; no write was sent.', 2);
    await this.request(plan.path, plan.method, body, false, true);
    try {
      const after = accountState(await this.teams(), accountId);
      if (op.accountWrite === 'role' && after.members.filter((m: JsonObject) => m.id === body.admin_id && m.role === body.role).length !== 1) throw new Error();
      if (op.accountWrite === 'remove' && after.members.some((m: JsonObject) => m.user?.id && validateUserId(m.user.id) === body.user_id)) throw new Error();
      const invitations = after.invitedMembers.filter((m: JsonObject) => m.address?.toLowerCase() === email);
      if (op.accountWrite === 'invite' && (invitations.length !== 1 || invitations[0].role !== body.role) || op.accountWrite === 'revoke' && invitations.length) throw new Error();
      return { accountId, verified: true, action: op.accountWrite, ...(member ? { membershipId: member.id } : {}), ...(op.accountWrite === 'invite' ? { deliveryVerified: false } : {}) };
    } catch { throw new CliError('ACCOUNT_VERIFY_FAILED', 'Account write acknowledged but fresh verification failed or access was lost. No automatic retry occurred.'); }
  }
  private async writeSetting(op: Operation, plan: RequestPlan, options: ExecutionOptions): Promise<JsonObject> {
    const appId = plan.pathParams.app_id, spec = op.settingsWrite!;
    await this.checkEnvironment(appId, options.allowProduction);
    const before = await this.execute(spec.read, { appId });
    const fields = Object.keys(plan.body!);
    if (!before || typeof before !== 'object' || fields.some(key => !Object.hasOwn(before, key) || spec.unordered?.includes(key) && !Array.isArray(before[key]))) throw new CliError('INVALID_SETTING_STATE', 'Cannot establish current setting values. No write was sent.');
    const resolved = spec.embeddedWallet ? prepareEmbeddedWalletUpdate(before, plan.body!) : { request: plan.body!, expected: plan.body! };
    await this.request(plan.path, plan.method, resolved.request, false, true);
    try {
      const after = await this.execute(spec.read, { appId });
      for (const key of fields) {
        const expected = resolved.expected[key], actual = after?.[key];
        if (spec.unordered?.includes(key)) {
          if (!Array.isArray(actual) || !isDeepStrictEqual([...actual].sort(), [...expected].sort())) throw new Error();
        } else if (!isDeepStrictEqual(actual, expected)) throw new Error();
      }
      return { appId, verified: true, changes: Object.fromEntries(fields.map(key => [key, after[key]])), ...(spec.externalIntegration ? { externalIntegrationVerified: false } : {}) };
    } catch { throw new CliError('SETTING_VERIFY_FAILED', 'Write succeeded but settings read-back did not match. Inspect current settings; no write was repeated.'); }
  }
  private async writeDomain(op: Operation, plan: RequestPlan, options: ExecutionOptions): Promise<JsonObject> {
    const appId = plan.pathParams.app_id, clientId = plan.pathParams.client_id;
    if ((op.domainWrite === 'delete' || plan.body?.enabled === false) && !options.allowSessionImpact) throw new CliError('SESSION_IMPACT_CONFIRMATION_REQUIRED', 'Disabling/deleting cookie domains may log out app users. Add --allow-session-impact. No request was sent.', 2);
    let confirmedDomain: string | undefined;
    if (op.domainWrite === 'delete') {
      if (!options.confirmDomain) throw new CliError('DOMAIN_CONFIRMATION_REQUIRED', 'Deletion requires --confirm-domain with the current hostname. No request was sent.', 2);
      confirmedDomain = normalizeCookieDomain(options.confirmDomain);
    }
    await this.checkEnvironment(appId, options.allowProduction);
    if (clientId) {
      const client = await this.execute('clients.get', { appId, params: { client_id: clientId } });
      if (client.client_type !== 'web' || client.use_app_cookie_domain_settings !== false) throw new CliError('CUSTOM_COOKIE_DOMAIN_UNAVAILABLE', 'Custom cookie domains require a web client with app-domain inheritance explicitly disabled. No write was sent.', 2);
    }
    const before = domainState(await this.request(plan.path));
    if (op.domainWrite !== 'configure' && before.status === 'unset') return { appId, ...(clientId ? { clientId } : {}), writesPerformed: false, domain: before, domainVerified: false, hint: 'No domain is configured.' };
    if (confirmedDomain && before.base_cookie_domain !== confirmedDomain) throw new CliError('DOMAIN_MISMATCH', 'Confirmation does not match the current cookie domain. No write was sent.', 2);
    if (op.domainWrite === 'configure' && before.base_cookie_domain && before.base_cookie_domain !== plan.body!.cookie_domain) throw new CliError('DOMAIN_REPLACEMENT_REQUIRES_DELETE', 'An existing domain must be explicitly deleted with session-impact confirmation before changing its hostname. No write was sent.', 2);
    if (clientId && op.domainWrite === 'configure' && before.base_cookie_domain) {
      if (before.enabled !== plan.body!.enabled) throw new CliError('CLIENT_DOMAIN_SETUP_ONLY', 'An existing client cookie domain cannot be toggled with configure. Inspect clients domains get; removal requires explicit clients domains delete with session-impact confirmation. No write was sent.', 2);
      return { appId, clientId, writesPerformed: false, alreadyApplied: true, domain: before, configurationVerified: true, domainVerified: before.status === 'verified', externalDnsModified: false, allowedOriginsModified: false };
    }
    await this.request(plan.path, plan.method, plan.body, false, true);
    try {
      const after = domainState(await this.request(plan.path));
      if (op.domainWrite === 'delete' && (after.status !== 'unset' || after.base_cookie_domain !== null || after.enabled)) throw new Error();
      if (op.domainWrite === 'configure' && (after.base_cookie_domain !== plan.body!.cookie_domain || after.enabled !== plan.body!.enabled || Object.hasOwn(plan.body!, 'cookie_same_site_lax') && after.cookie_same_site_lax !== plan.body!.cookie_same_site_lax)) throw new Error();
      return { appId, ...(clientId ? { clientId } : {}), domain: after, configurationVerified: true, domainVerified: after.status === 'verified', ...(op.domainWrite === 'delete' ? { deleted: true } : {}), externalDnsModified: false, allowedOriginsModified: false };
    } catch { throw new CliError('DOMAIN_VERIFY_FAILED', 'Request succeeded but fresh domain state could not be verified. Inspect domain status; no write was repeated.'); }
  }
  private async writeAppClient(op: Operation, plan: RequestPlan, options: ExecutionOptions): Promise<JsonObject> {
    const appId = plan.pathParams.app_id;
    const app = await this.checkEnvironment(appId, options.allowProduction);
    let id = plan.pathParams.client_id;
    const before = id ? await this.execute('clients.get', { appId, params: { client_id: id } }) : undefined;
    if (op.appClientWrite === 'create' || plan.body && (Object.hasOwn(plan.body, 'client_type') || Object.hasOwn(plan.body, 'use_app_cookie_domain_settings'))) {
      const type = plan.body?.client_type ?? before?.client_type;
      const inherit = plan.body?.use_app_cookie_domain_settings ?? before?.use_app_cookie_domain_settings;
      if (!['web', 'mobile'].includes(type) || typeof inherit !== 'boolean') throw new CliError('INVALID_CLIENT', 'Cannot establish client type/cookie configuration. No write was sent.');
      if (type === 'mobile' && inherit) throw new CliError('INVALID_CLIENT_COOKIES', 'Mobile clients cannot inherit web cookie settings. Explicitly disable inheritance in this update.', 2);
      if (inherit && (typeof app.cookie_domain !== 'string' || !app.cookie_domain)) throw new CliError('COOKIE_DOMAIN_REQUIRED', 'Configure an app cookie domain before inheriting it. No write was sent.', 2);
    }
    const result = await this.request(plan.path, plan.method, plan.body, false, op.appClientWrite !== 'create');
    if (op.appClientWrite === 'create') {
      try { id = validateId(result?.id); }
      catch { throw new CliError('CLIENT_VERIFY_FAILED', 'Creation returned an unexpected client ID. Inspect clients list before retrying.'); }
    }
    try {
      const clients: JsonObject[] = await this.execute('clients.list', { appId });
      const matches = clients.filter(c => c.id === id);
      if (op.appClientWrite === 'delete') {
        if (matches.length) throw new Error();
        return { appId, clientId: id, deleted: true, verified: true };
      }
      if (matches.length !== 1 || Object.entries(plan.body!).some(([key, value]) => !isDeepStrictEqual(matches[0][key], value))) throw new Error();
      return { appId, client: matches[0], verified: true };
    } catch { throw new CliError('CLIENT_VERIFY_FAILED', 'Write succeeded but client read-back did not match. Inspect clients list/get; no write was repeated.'); }
  }
  private async writeCredential(op: Operation, plan: RequestPlan, options: ExecutionOptions): Promise<JsonObject> {
    const appId = plan.pathParams.app_id;
    await this.checkEnvironment(appId, options.allowProduction);
    const before: JsonObject[] = await this.execute('credentials.list', { appId });
    let id = plan.pathParams.credential_id;
    if (op.credentialWrite === 'delete' && !before.some(r => r.id === id)) throw new CliError('CREDENTIAL_NOT_FOUND', 'Credential ID is not in this app. No write was sent.', 2);
    if (op.credentialWrite === 'create' && before.length >= 5) throw new CliError('CREDENTIAL_LIMIT', 'The dashboard supports five app secrets. Inspect existing credentials before creating another.', 2);
    const result = await this.request(plan.path, plan.method, plan.body, false, op.credentialWrite === 'delete');
    let storage: JsonObject | undefined;
    if (op.credentialWrite === 'create') {
      try { id = validateId(result?.[op.secretSave!.idField!]); }
      catch { throw new CliError('CREDENTIAL_VERIFY_FAILED', 'Creation returned an unexpected ID. Inspect credentials list before retrying; a credential may have been created. No value was printed.'); }
      const ref = { appId, kind: op.secretSave!.kind, id };
      const secret = result?.[op.secretSave!.responseField];
      storage = await options.appSecretStorage!.save(ref, secret);
    }
    try {
      const after: JsonObject[] = await this.execute('credentials.list', { appId });
      const current = after.find(r => r.id === id);
      if (op.credentialWrite === 'delete') {
        if (current) throw new Error();
        return { appId, credentialId: id, deleted: true, verified: true };
      }
      if (!current || current.access_mode !== plan.body!.access_mode) throw new Error();
      return { appId, credential: current, storage, verified: true };
    } catch {
      const error = new CliError('CREDENTIAL_VERIFY_FAILED', 'Write succeeded but credential metadata could not be verified. Inspect credentials list and the reported storage destinations; no write was repeated or rolled back.');
      error.details = { reference: { appId, kind: 'app-credential', id }, storage, valuePrinted: false };
      throw error;
    }
  }
  private webhookEndpoints(value: unknown): JsonObject[] {
    if (!Array.isArray(value) || value.some(e => !e || typeof e.endpointId !== 'string' || typeof e.endpointUrl !== 'string') || new Set(value.map(e => e.endpointId)).size !== value.length) throw new CliError('INVALID_WEBHOOKS', 'Endpoint response is incomplete or ambiguous.');
    return value;
  }
  private webhookSubscriptions(value: unknown): JsonObject {
    const endpoints = this.webhookEndpoints(value);
    if (!endpoints.length) return { configured: false, consistent: true, subscriptions: [], endpoints: [] };
    if (endpoints.some(e => !Array.isArray(e.subscriptions) || e.subscriptions.some((s: unknown) => typeof s !== 'string'))) throw new CliError('INVALID_WEBHOOKS', 'Endpoint subscription state is incomplete.');
    const subscriptions = [...endpoints[0].subscriptions].sort();
    const consistent = endpoints.every(e => isDeepStrictEqual([...e.subscriptions].sort(), subscriptions));
    return { configured: true, consistent, subscriptions: consistent ? subscriptions : null,
      endpoints: endpoints.map(e => ({ endpointId: e.endpointId, endpointUrl: e.endpointUrl, subscriptions: e.subscriptions })) };
  }
  private async writeWebhook(op: Operation, plan: RequestPlan, options: ExecutionOptions): Promise<JsonObject> {
    const appId = plan.pathParams.app_id;
    let id = plan.pathParams.endpoint_id, confirmedUrl: string | undefined;
    if (op.confirmUrl) {
      try {
        const url = new URL(options.confirmUrl!);
        if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new Error();
        confirmedUrl = url.href;
      } catch { throw new CliError('URL_CONFIRMATION_REQUIRED', 'This operation requires --confirm-url with the exact current HTTPS receiver. No request was sent.', 2); }
    }
    await this.checkEnvironment(appId, options.allowProduction);
    if (op.webhookWrite === 'watchlist') {
      const expected = watchlistValues(plan.body);
      const current = watchlistValues((await this.execute('webhooks.watchlist.get', { appId })).data, true);
      if (isDeepStrictEqual(current, expected)) return { appId, assets: current, unchanged: true, writesPerformed: false };
      const pipelines = await this.execute('webhooks.chains', {});
      if (!Array.isArray(pipelines?.data) || pipelines.data.some((p: JsonObject) => typeof p?.caip2 !== 'string')) throw new CliError('INVALID_PIPELINES', 'Cannot establish supported webhook chains. No write was sent.');
      const chains = new Set(pipelines.data.map((p: JsonObject) => p.caip2));
      if (expected.some(asset => !chains.has(asset.caip2))) throw new CliError('UNSUPPORTED_WATCH_CHAIN', 'A requested chain has no supported event pipeline. Inspect webhooks chains. No write was sent.', 2);
      await this.request(plan.path, plan.method, plan.body, false, true);
      try {
        const after = watchlistValues((await this.execute('webhooks.watchlist.get', { appId })).data, true);
        if (!isDeepStrictEqual(after, expected)) throw new Error();
        return { appId, assets: after, verified: true };
      } catch { throw new CliError('WATCHLIST_VERIFY_FAILED', 'Write succeeded but watchlist read-back did not match. Inspect webhooks watchlist get and auto-enrolled app assets; no write was repeated.'); }
    }
    const before = this.webhookEndpoints(await this.execute('webhooks.list', { appId }));
    const endpoint = id ? before.find(e => e.endpointId === id) : undefined;
    if (id && !endpoint) throw new CliError('WEBHOOK_NOT_FOUND', 'Endpoint not found in this app. No write was sent.', 2);
    if (endpoint && confirmedUrl && new URL(endpoint.endpointUrl).href !== confirmedUrl) throw new CliError('WEBHOOK_URL_MISMATCH', 'Confirmation URL does not match the current endpoint. No write was sent.', 2);
    if (op.webhookWrite === 'create') {
      if (before.length >= 5) throw new CliError('WEBHOOK_LIMIT', 'The dashboard supports at most five endpoints. No write was sent.', 2);
      if (before.some(e => new URL(e.endpointUrl).href === new URL(plan.body!.url).href)) throw new CliError('WEBHOOK_ALREADY_EXISTS', 'An endpoint already uses this URL. Inspect webhooks list instead of creating a duplicate.', 2);
    }
    if (op.webhookWrite === 'subscriptions' && !before.length) throw new CliError('WEBHOOK_NOT_CONFIGURED', 'Create an endpoint before configuring app-wide subscriptions. No write was sent.', 2);
    if (op.webhookWrite === 'enable') {
      const status = await this.execute('webhooks.status', { appId });
      const health = Array.isArray(status?.data) ? status.data.find((e: JsonObject) => e.endpoint_id === id) : undefined;
      if (typeof health?.state !== 'string') throw new CliError('INVALID_WEBHOOK_HEALTH', 'Cannot establish endpoint state. No write was sent.');
      if (health.state !== 'disabled') return { appId, endpointId: id, unchanged: true, writesPerformed: false, reportedState: health.state, deliveryVerified: false };
    }
    if (op.webhookWrite === 'resend') {
      const history = await this.execute('webhooks.history.list', { appId, query: { msgId: plan.pathParams.message_id, limit: 100 } }, { all: true, maxPages: 10 });
      if (!history.data.some((e: JsonObject) => e.msgId === plan.pathParams.message_id && e.endpointUrl === endpoint!.endpointUrl)) throw new CliError(history.has_more ? 'HISTORY_LOOKUP_INCOMPLETE' : 'NO_PRIOR_DELIVERY', 'Could not confirm a prior attempt for this message at the current destination. No replay was sent.', 2);
    }
    const result = await this.request(plan.path, plan.method, plan.body, false, op.webhookWrite !== 'create' && op.webhookWrite !== 'secret');
    if (op.secretSave) {
      const secret = result?.[op.secretSave.responseField];
      if (typeof secret !== 'string' || !/^whsec_[A-Za-z0-9+/=]+$/.test(secret)) throw new CliError('INVALID_SECRET_RESPONSE', 'Signing-key response was unexpected; no value was printed or written to plaintext.');
      return options.storeSecret!({ appId, kind: op.secretSave.kind, id: plan.pathParams[op.secretSave.idParam!] }, secret);
    }
    if (op.webhookWrite === 'test' || op.webhookWrite === 'resend') return { appId, endpointId: id, ...(plan.pathParams.message_id ? { messageId: plan.pathParams.message_id } : {}), apiAcknowledged: true, httpStatus: result.httpStatus, deliveryVerified: false, hint: 'Inspect webhooks history and your receiver. No automatic retries were attempted.' };
    if (op.webhookWrite === 'create') {
      try { id = validateId(result.endpointId); }
      catch { throw new CliError('WEBHOOK_VERIFY_FAILED', 'Creation returned an unexpected endpoint ID. Inspect webhooks list before retrying.'); }
    }
    try {
      const after = this.webhookEndpoints(await this.execute('webhooks.list', { appId }));
      if (op.webhookWrite === 'subscriptions') {
        const state = this.webhookSubscriptions(after);
        if (!state.configured || !state.consistent || !isDeepStrictEqual(state.subscriptions, [...plan.body!.subscriptions].sort())) throw new Error();
        return { appId, verified: true, ...state };
      }
      const current = after.find(e => e.endpointId === id);
      if (op.webhookWrite === 'delete') {
        if (current) throw new Error();
        return { appId, endpointId: id, deleted: true, verified: true };
      }
      if (!current) throw new Error();
      if (op.webhookWrite === 'create' && new URL(current.endpointUrl).href !== new URL(plan.body!.url).href) throw new Error();
      if (op.webhookWrite === 'enable') {
        const status = await this.execute('webhooks.status', { appId });
        const health = status?.data?.find((e: JsonObject) => e.endpoint_id === id);
        if (typeof health?.state !== 'string' || health.state === 'disabled') throw new Error();
        return { appId, endpointId: id, verifiedNotDisabled: true, health, deliveryVerified: false };
      }
      return { appId, endpointId: id, verified: true, endpoint: current, signingKeyStored: false };
    } catch { throw new CliError('WEBHOOK_VERIFY_FAILED', 'Write succeeded but read-back could not be verified. Inspect webhooks list/status; no write was repeated.'); }
  }
  private async writeOrganization(op: Operation, plan: RequestPlan, options: { allowProduction?: boolean }): Promise<JsonObject> {
    const appId = plan.pathParams.app_id, body = plan.body!;
    let id = plan.pathParams.organization_id;
    await this.checkEnvironment(appId, options.allowProduction);
    if (op.organizationWrite === 'update' && !await this.findListedResource('organizations.list', appId, id)) throw new CliError('ORGANIZATION_NOT_FOUND', 'Organization not found in this app. No write was sent.', 2);
    if (body.default_key_quorum_id && !await this.findListedResource('key-quorums.list', appId, body.default_key_quorum_id)) throw new CliError('QUORUM_NOT_FOUND', 'Default key quorum not found in this app. No write was sent.', 2);
    for (const walletId of body.wallet_ids ?? []) {
      const wallet = await this.findListedResource('wallets.list', appId, walletId);
      if (!wallet) throw new CliError('WALLET_NOT_FOUND', 'A requested wallet was not found. No write was sent.', 2);
      if (wallet.entity !== null) throw new CliError('WALLET_ENTITY_IMMUTABLE', 'A requested wallet already has an entity binding or its state is unknown. No write was sent.', 2);
    }
    const result = await this.request(plan.path, plan.method, body);
    if (op.organizationWrite === 'create') {
      try { id = validateId(result.id); }
      catch { throw new CliError('ORGANIZATION_VERIFY_FAILED', 'Creation returned an unexpected organization ID. Inspect organizations list before retrying.'); }
    }
    try {
      const organization = await this.findListedResource('organizations.list', appId, id);
      if (!organization) throw new Error();
      for (const field of ['display_name', 'default_key_quorum_id']) if (Object.hasOwn(body, field) && !isDeepStrictEqual(organization[field], body[field])) throw new Error();
      for (const walletId of body.wallet_ids ?? []) {
        const wallet = await this.findListedResource('wallets.list', appId, walletId);
        if (wallet?.entity?.id !== id) throw new Error();
      }
      return { appId, organizationId: id, verified: true, organization, ...(body.wallet_ids ? { walletBindingsVerified: body.wallet_ids } : {}) };
    } catch { throw new CliError('ORGANIZATION_VERIFY_FAILED', `Write succeeded for organization ${id}, but read-back could not be verified. Inspect organizations get and member wallets; no write was repeated.`); }
  }
  private async writeQuorum(plan: RequestPlan, options: { allowProduction?: boolean }): Promise<JsonObject> {
    const appId = plan.pathParams.app_id, body = plan.body!;
    await this.checkEnvironment(appId, options.allowProduction);
    for (const id of body.key_quorum_ids ?? []) {
      const member = await this.findListedResource('key-quorums.list', appId, id);
      if (!member) throw new CliError('QUORUM_NOT_FOUND', 'Nested quorum not found in this app. No write was sent.', 2);
      if (!Array.isArray(member.key_quorum_ids)) throw new CliError('INVALID_QUORUM', 'Cannot establish nested quorum depth. No write was sent.');
      if (member.key_quorum_ids.length) throw new CliError('QUORUM_NESTING_LIMIT', 'Quorums can only be nested one level deep. No write was sent.', 2);
    }
    const result = await this.request(plan.path, plan.method, body);
    let id: string;
    try { id = validateId(result.id); }
    catch { throw new CliError('QUORUM_VERIFY_FAILED', 'Quorum creation returned an unexpected ID. Inspect key-quorums list before retrying.'); }
    try {
      const quorum = await this.findListedResource('key-quorums.list', appId, id);
      if (!quorum || !Array.isArray(quorum.authorization_keys)) throw new Error();
      const actual = { display_name: quorum.display_name, authorization_threshold: quorum.authorization_threshold,
        public_keys: quorum.authorization_keys.map((k: JsonObject) => k.public_key).sort(), key_quorum_ids: [...(quorum.key_quorum_ids ?? [])].sort() } as JsonObject;
      if (Object.entries(body).some(([k, v]) => !isDeepStrictEqual(actual[k], Array.isArray(v) ? [...v].sort() : v))) throw new Error();
      return { appId, keyQuorumId: id, verified: true, quorum };
    } catch { throw new CliError('QUORUM_VERIFY_FAILED', `Quorum ${id} was created, but read-back could not be verified. Inspect key-quorums get/list; no write was repeated.`); }
  }
  private walletValues(wallet: JsonObject): JsonObject {
    if (!(wallet.auth_key === null || typeof wallet.auth_key?.id === 'string')
      || !(wallet.user_id === null || typeof wallet.user_id === 'string' && wallet.user_id.length > 0)
      || !(wallet.entity === null || typeof wallet.entity?.id === 'string' && ['organization', 'user'].includes(wallet.entity.type))
      || !(wallet.policy === null || typeof wallet.policy?.id === 'string')
      || !Array.isArray(wallet.additional_signers)
      || wallet.additional_signers.some((s: JsonObject) => typeof s?.signer?.key_quorum_id !== 'string' || !Array.isArray(s.override_policies) || s.override_policies.some((p: JsonObject) => typeof p?.id !== 'string'))) throw new CliError('INVALID_WALLET', 'Wallet ownership/entity/policy/signer response is incomplete.');
    return { display_name: wallet.display_name, chain_type: wallet.chain_type,
      owner_id: wallet.auth_key?.id ?? wallet.user_id ?? null,
      policy_ids: wallet.policy ? [wallet.policy.id] : [],
      entity: wallet.entity ? { type: wallet.entity.type ?? 'organization', id: wallet.entity.id } : null,
      additional_signers: wallet.additional_signers.map((s: JsonObject) => ({ signer_id: s.signer?.key_quorum_id, override_policy_ids: s.override_policies?.map((p: JsonObject) => p.id) })),
    };
  }
  private async writeWallet(op: Operation, plan: RequestPlan, options: { allowProduction?: boolean; confirmOwner?: string }): Promise<JsonObject> {
    const appId = plan.pathParams.app_id, body = plan.body!;
    let walletId = plan.pathParams.wallet_id;
    if (body.owner_id && options.confirmOwner !== body.owner_id) throw new CliError('OWNER_CONFIRMATION_REQUIRED', 'Assigning ownership requires --confirm-owner matching owner_id. Future control changes require owner authorization. No request was sent.', 2);
    await this.checkEnvironment(appId, options.allowProduction);
    let before: JsonObject | null = null;
    if (op.walletWrite === 'update') {
      before = await this.findListedResource('wallets.list', appId, walletId);
      if (!before) throw new CliError('WALLET_NOT_FOUND', 'Wallet not found. No write was sent.', 2);
      const state = this.walletValues(before);
      const controlChange = Object.keys(body).some(k => !['display_name', 'entity'].includes(k));
      if (controlChange && (before.type !== 'server' || state.owner_id !== null)) throw new CliError('WALLET_OWNER_APPROVAL_REQUIRED', 'Wallet control changes require owner authorization or a dashboard proposal. No write was sent.', 2);
      if (body.entity && before.entity !== null) throw new CliError('WALLET_ENTITY_IMMUTABLE', 'An existing organization binding cannot be changed. Omit entity when changing other fields.', 2);
    }
    const chain = before?.chain_type ?? body.chain_type;
    const policyIds = new Set<string>([...(body.policy_ids ?? []), ...(body.additional_signers ?? []).flatMap((s: JsonObject) => s.override_policy_ids)]);
    for (const id of policyIds) {
      const policy = await this.readPolicy(appId, id);
      if (policy.chain_type !== chain) throw new CliError('POLICY_CHAIN_MISMATCH', 'Policy and wallet chain types differ. No write was sent.', 2);
    }
    for (const id of new Set<string>([...(body.owner_id ? [body.owner_id] : []), ...(body.additional_signers ?? []).map((s: JsonObject) => s.signer_id)])) {
      const owner = id.startsWith('did:privy:') ? await this.findUser(appId, id) : await this.findListedResource('key-quorums.list', appId, id);
      if (!owner) throw new CliError('OWNER_NOT_FOUND', 'Owner/signer was not found in this app. No write was sent.', 2);
    }
    if (body.entity && !await this.findListedResource('organizations.list', appId, body.entity.id)) throw new CliError('ORGANIZATION_NOT_FOUND', 'Organization not found in this app. No write was sent.', 2);
    const result = await this.request(plan.path, plan.method, body);
    if (op.walletWrite === 'export') return { appId, submitted: true, completed: false, job: result };
    if (op.walletWrite === 'create') {
      try { walletId = validateId(result.id); }
      catch { throw new CliError('WALLET_VERIFY_FAILED', 'Wallet creation returned an unexpected ID. Inspect wallets list before retrying.'); }
    }
    try {
      const after = await this.findListedResource('wallets.list', appId, walletId);
      if (!after) throw new Error();
      const values = this.walletValues(after);
      if (Object.entries(body).some(([key, expected]) => !isDeepStrictEqual(values[key], expected))) throw new Error();
      return { appId, walletId, verified: true, wallet: after };
    } catch { throw new CliError('WALLET_VERIFY_FAILED', `Write succeeded for wallet ${walletId}, but read-back could not be verified. Inspect wallets get/list; no write was repeated.`); }
  }
  private linkedHandle(account: JsonObject): unknown {
    switch (account.type) {
      case 'email': case 'wallet': case 'smart_wallet': return account.address;
      case 'phone': return account.phoneNumber ?? account.number;
      case 'farcaster': return account.fid?.toString();
      case 'telegram': return account.telegramUserId;
      case 'custom_auth': return account.custom_user_id;
      case 'passkey': return account.credential_id;
      case 'authorization_key': return account.public_key;
      default: return account.subject;
    }
  }
  private async writeUser(op: Operation, plan: RequestPlan, allowProduction?: boolean): Promise<JsonObject> {
    const appId = plan.pathParams.app_id, userId = plan.pathParams.user_id;
    await this.checkEnvironment(appId, allowProduction);
    const matchesAccount = (a: JsonObject) => a.type === plan.body!.type && this.linkedHandle(a) === plan.body!.handle && (a.type !== 'cross_app' || a.provider_app_id === plan.body!.provider);
    if (userId) {
      const before = await this.findUser(appId, userId);
      if (!before) throw new CliError('USER_NOT_FOUND', 'User not found in the selected app. No write was sent.', 2);
      if (op.userWrite === 'unlink') {
        if (!Array.isArray(before.linked_accounts)) throw new CliError('INVALID_RESPONSE', 'Cannot inspect linked accounts. No write was sent.');
        if (before.linked_accounts.filter(matchesAccount).length !== 1) throw new CliError('LINKED_ACCOUNT_NOT_FOUND', 'Exactly one matching linked account is required. No write was sent.', 2);
        const loginAccounts = before.linked_accounts.filter((a: JsonObject) => !(a.type === 'wallet' && a.wallet_client === 'privy') && a.type !== 'smart_wallet');
        if (loginAccounts.length < 2) throw new CliError('LAST_LINKED_ACCOUNT', 'Refusing to unlink the last login account. No write was sent.', 2);
      }
    }
    const result = await this.request(plan.path, plan.method, plan.body);
    if (op.userWrite === 'bulk-import') return { appId, submitted: true, completed: false, response: result, verification: 'Inspect users imports list for job progress; submission is not completed user creation.' };
    if (op.userWrite === 'import') {
      if (!Array.isArray(result.results) || result.results.length !== plan.body!.users.length) throw new CliError('IMPORT_VERIFY_FAILED', 'Import returned an unexpected result count. Inspect users list before retrying; some records may have been created.');
      const outcomes: JsonObject[] = [], seen = new Set<number>();
      for (const row of result.results) {
        if (!row || !Number.isInteger(row.index) || row.index < 0 || row.index >= plan.body!.users.length || seen.has(row.index) || typeof row.success !== 'boolean') throw new CliError('IMPORT_VERIFY_FAILED', 'Import returned an unexpected result envelope. Inspect users list before retrying.');
        seen.add(row.index);
        if (!row.success) { outcomes.push({ index: row.index, success: false, verified: false }); continue; }
        let id: string | undefined, verified = false;
        try {
          id = validateUserId(row.id);
          const actual = await this.findUser(appId, id), requested = plan.body!.users[row.index];
          verified = Boolean(actual && Array.isArray(actual.linked_accounts) && requested.linked_accounts.every((expected: JsonObject) => actual.linked_accounts.some((account: JsonObject) => {
            if (account.type !== expected.type) return false;
            return Object.entries(expected).every(([key, value]) => {
              if (key === 'number' && expected.type === 'phone') return String(account.number ?? account.phoneNumber).replace(/\D/g, '') === String(value).replace(/\D/g, '');
              if (key === 'address' && (expected.type === 'email' || expected.type === 'wallet' && /^0x[0-9a-fA-F]{40}$/.test(String(value)))) return typeof account.address === 'string' && account.address.toLowerCase() === String(value).toLowerCase();
              return isDeepStrictEqual(account[key], value);
            });
          })));
          if (requested.custom_metadata !== undefined && !isDeepStrictEqual(actual?.custom_metadata, requested.custom_metadata)) verified = false;
          if (requested.wallets !== undefined) {
            if (!Array.isArray(requested.wallets) || !Array.isArray(actual?.linked_accounts)) verified = false;
            else for (const wallet of requested.wallets) {
              const wanted = requested.wallets.filter((w: JsonObject) => w.chain_type === wallet.chain_type).length;
              const present = new Set(actual.linked_accounts.filter((a: JsonObject) => a.type === 'wallet' && a.wallet_client === 'privy' && a.chain_type === wallet.chain_type).map((a: JsonObject) => a.id ?? a.address));
              if (present.size < wanted) verified = false;
            }
          }
        } catch { /* Preserve safe per-record status; never retry creation. */ }
        outcomes.push({ index: row.index, success: true, ...(typeof row.action === 'string' && /^[a-z_]{1,40}$/.test(row.action) ? { apiAction: row.action } : {}), ...(id ? { userId: id } : {}), verified });
      }
      if (outcomes.some(r => !r.success || !r.verified)) {
        const error = new CliError('IMPORT_PARTIAL_OR_UNVERIFIED', 'Some imports failed or could not be read back. Inspect per-record results and users list; do not blindly repeat the batch.');
        error.details = { appId, results: outcomes }; throw error;
      }
      return { appId, results: outcomes, verified: true, verification: 'Exact-ID read-back, supplied linked-account fields and metadata compared. Wallet presence is checked by chain, not full wallet configuration. An existing identity can be returned unchanged; API action is not proof a new user was created.' };
    }
    try {
      const after = await this.findUser(appId, userId);
      if (op.userWrite === 'delete') {
        if (after || (await this.app(appId)).id !== appId) throw new Error();
        return { appId, userId, deleted: true, verified: true };
      }
      if (!after) throw new Error();
      if (op.userWrite === 'update' && !isDeepStrictEqual(after.display_name, plan.body!.display_name)) throw new Error();
      if (op.userWrite === 'freeze' && !(typeof after.frozen_at === 'number' && after.frozen_at > 0)) throw new Error();
      if (op.userWrite === 'restore' && after.frozen_at !== null) throw new Error();
      if (op.userWrite === 'unlink' && (!Array.isArray(after.linked_accounts) || after.linked_accounts.some(matchesAccount))) throw new Error();
      if (op.userWrite === 'revoke') return { appId, userId, acknowledged: true, verified: false, observed: { is_active: after.is_active, latest_session_at: after.latest_session_at, latest_session_revoked_reason: after.latest_session_revoked_reason }, verification: 'Read-back reports dashboard state; a real end-user session was not exercised.' };
      return { appId, userId, verified: true, user: after };
    } catch { throw new CliError('USER_VERIFY_FAILED', `Write succeeded for user ${userId}, but read-back could not be verified. Inspect users get/list before retrying; no write was repeated.`); }
  }
  private async checkEnvironment(appId: string, allowProduction?: boolean): Promise<JsonObject> {
    const app = await this.app(appId);
    const env = String(app?.env).toLowerCase();
    if (!['dev', 'development', 'prod', 'production'].includes(env)) throw new CliError('UNKNOWN_ENVIRONMENT', 'Cannot determine the target app environment. No write was sent.');
    if (['prod', 'production'].includes(env) && !allowProduction) throw new CliError('PRODUCTION_CONFIRMATION_REQUIRED', 'This is a production app. Use --allow-production together with --yes to confirm the target.', 2);
    return app;
  }
  private async readPolicy(appId: string, policyId: string): Promise<JsonObject> {
    const value = await this.execute('policies.get', { appId, params: { policy_id: policyId } });
    if (!value || value.id !== policyId || !Array.isArray(value.rules) || !Object.hasOwn(value, 'owner_id')) throw new CliError('INVALID_POLICY', 'Unexpected policy response. Inspect remote state before retrying.');
    return value;
  }
  private async writePolicy(op: Operation, plan: RequestPlan, input: OperationInput, allowProduction?: boolean, confirmOwner?: string): Promise<JsonObject> {
    const appId = plan.pathParams.app_id;
    let policyId = plan.pathParams.policy_id, ruleId = plan.pathParams.rule_id;
    const expectedOwner = op.policyWrite === 'create' ? plan.body!.owner_id ?? null : null;
    if (expectedOwner !== null && confirmOwner !== expectedOwner) throw new CliError('OWNER_CONFIRMATION_REQUIRED', 'Creating an owned policy requires --confirm-owner matching owner_id. Subsequent changes require owner authorization. No request was sent.', 2);
    await this.checkEnvironment(appId, allowProduction);
    if (expectedOwner !== null && !await this.findListedResource('key-quorums.list', appId, expectedOwner)) throw new CliError('QUORUM_NOT_FOUND', 'Policy owner quorum was not found in this app. No write was sent.', 2);
    if (op.policyWrite !== 'create') {
      const before = await this.readPolicy(appId, policyId);
      if (before.owner_id !== null) throw new CliError('POLICY_OWNER_APPROVAL_REQUIRED', 'Owner-managed policies require owner authorization or a dashboard approval flow. This CLI does not bypass it. No write was sent.', 2);
      if (ruleId && !before.rules.some((r: JsonObject) => r?.id === ruleId)) throw new CliError('RULE_NOT_FOUND', 'The rule was not found in this policy. No write was sent.', 2);
      if (op.policyWrite === 'delete') {
        if (before.name !== plan.body!.name) throw new CliError('POLICY_NAME_MISMATCH', 'The confirmation name does not match the current policy. No write was sent.', 2);
        const eligibility = await this.request(plan.path + '/deletable');
        if (eligibility.deletable !== true) throw new CliError('POLICY_NOT_DELETABLE', 'Privy did not confirm this policy can be deleted. It may be in use. No write was sent.', 2);
      }
    }
    const result = await this.request(plan.path, plan.method, plan.body); // One write; never retry automatically.
    if (op.policyWrite === 'create' || op.policyWrite === 'create-rule') {
      try {
        const createdId = validateId(result?.id);
        if (op.policyWrite === 'create') policyId = createdId; else ruleId = createdId;
      } catch { throw new CliError('POLICY_VERIFY_FAILED', 'Write succeeded but returned no valid resource ID. Inspect policies list before retrying.'); }
    }
    try {
      if (op.policyWrite === 'delete') {
        let missing = false;
        try { await this.readPolicy(appId, policyId); }
        catch (error) { if (error instanceof CliError && error.status === 404) missing = true; else throw error; }
        if (!missing) throw new Error('Policy still exists');
        // A 404 alone is insufficient: app access must still work after deletion.
        const app = await this.app(appId);
        if (app.id !== appId) throw new Error('App access unverified');
        return { appId, policyId, deleted: true, verified: true };
      }
      const after = await this.readPolicy(appId, policyId);
      if (after.owner_id !== expectedOwner) throw new Error('Owner changed');
      const rule = ruleId ? after.rules.find((r: JsonObject) => r?.id === ruleId) : undefined;
      if (op.policyWrite === 'delete-rule') {
        if (rule) throw new Error('Rule still exists');
        return { appId, policyId, ruleId, deleted: true, verified: true };
      }
      const value = op.policyWrite!.endsWith('-rule') ? rule : after;
      if (!value || Object.entries(plan.body!).some(([key, expected]) => {
        if (op.policyWrite === 'create' && key === 'rules') return value.rules.length !== expected.length || expected.some((rule: JsonObject, i: number) => Object.entries(rule).some(([field, v]) => !isDeepStrictEqual(value.rules[i]?.[field], v)));
        return !isDeepStrictEqual(value[key], expected);
      })) throw new Error('Read-back mismatch');
      return { appId, policyId, ...(ruleId ? { ruleId, rule: value } : { policy: value }), verified: true };
    } catch {
      throw new CliError('POLICY_VERIFY_FAILED', `Write succeeded but read-back for policy ${policyId}${ruleId ? ` / rule ${ruleId}` : ''} could not be verified. Inspect remote state before retrying; no write was repeated.`);
    }
  }
  async diff(input: OperationInput, id = 'config.update'): Promise<JsonObject> {
    const plan = this.preview(id, input);
    const op = operation(id);
    if (op.accountJwtFeature === 'update') {
      const before = await this.accountJwtFeature(plan.pathParams.account_id);
      return { accountId: plan.pathParams.account_id, writesPerformed: false, before, requested: plan.body, changes: { enabled: { before: before.enabled, after: plan.body!.enabled } }, note: 'Read-only capability diff; execution additionally checks every app for active JWT authentication and fresh state.' };
    }
    if (id !== 'config.update' && op.userWrite !== 'update' && op.walletWrite !== 'update' && op.organizationWrite !== 'update' && op.appClientWrite !== 'update' && op.domainWrite !== 'configure' && !op.settingsWrite && !op.publicUserMetadata && op.providerWrite !== 'update' && op.telegram !== 'update' && op.integration?.action !== 'update' && op.availabilityAction !== 'update' && op.advancedAction !== 'merging-update' && op.advancedAction !== 'captcha-update' && op.securitySetting?.action !== 'update' && op.jwtAction !== 'configure' && op.webhookWrite !== 'subscriptions' && op.webhookWrite !== 'watchlist' && op.policyWrite !== 'update' && op.policyWrite !== 'update-rule') throw new CliError('DIFF_NOT_SUPPORTED', 'This operation does not support a diff.', 2);
    const app = await this.app(input.appId!);
    if (op.securitySetting?.action === 'update' || op.jwtAction === 'configure') {
      const context = { app, account: owningAccount(app, await this.teams()) }, request = (path: string) => this.request(path);
      if (op.securitySetting?.kind === 'redirects') redirectsAllowed(app, plan.body!.allowed_oauth_redirect_urls);
      const before = op.jwtAction ? publicJwt(await jwtState(context, request)) : await securityState(op.securitySetting!.kind, context, request);
      return { appId: input.appId, env: app.env, writesPerformed: false, before, requested: plan.body, ...(op.jwtAction ? { requiresEnableAuth: !before.enabled, workflow: 'Initial configure may require explicit --enable-auth and two non-atomic writes. No account feature activation.' } : {}), externalIntegrationVerified: false };
    }
    if (op.availabilityAction === 'update') {
      const state = await this.execute('global-wallet.availability.get', { appId: input.appId });
      return { appId: input.appId, env: app.env, writesPerformed: false, changes: { availability: { before: state.config.availability, after: plan.body!.availability } }, eligibility: plan.body!.availability === 'public' ? state.publish : state.unpublish, prerequisites: state.prerequisites, accessImpact: 'Public availability allows cross-app integration; private pauses existing integrations. No account approval or billing request is submitted.' };
    }
    if (op.advancedAction === 'captcha-update') return { appId: input.appId, env: app.env, writesPerformed: false, before: await readCaptcha(plan.path, path => this.request(path)), requested: plan.body, warning: 'Customer login behavior changes; hCaptcha needs compatible frontend SDKs (React react-auth@3.9.0+). No challenge or external login is exercised.' };
    if (op.advancedAction === 'merging-update') return { appId: input.appId, env: app.env, writesPerformed: false, before: mergingState(app), requested: plan.body, warning: 'Affects future identity linking; does not retroactively merge users or undo previous links.' };
    if (op.integration?.action === 'update') {
      const before = await this.execute(id.replace(/\.update$/, '.get'), { appId: input.appId });
      return { appId: input.appId, env: app.env, writesPerformed: false, before, requested: plan.body, credentialComparison: 'Supplied sensitive values are redacted; presence is not an exact-value comparison', externalIntegrationVerified: false };
    }
    if (op.publicUserMetadata) {
      const user = await this.findUser(input.appId!, plan.pathParams.user_id);
      if (!user) throw new CliError('USER_NOT_FOUND', 'User not found in the selected app.', 2);
      const after = op.method === 'PATCH' ? { ...(user.custom_metadata ?? {}), ...plan.body!.custom_metadata } : plan.body!.custom_metadata;
      validateUserMetadata(after);
      return { appId: input.appId, env: app.env, userId: user.id, writesPerformed: false, changes: { custom_metadata: { before: user.custom_metadata ?? {}, after } } };
    }
    if (op.providerWrite === 'update') {
      const patch = plan.body!.config;
      const before = await readProvider((path, method, body, ack) => this.request(path, method, body, false, ack), input.appId!, patch.provider);
      return { appId: input.appId, env: app.env, writesPerformed: false, editable: before.editable, changes: Object.fromEntries(Object.keys(patch).filter(k => k !== 'provider').map(key => [key, { before: before.config?.[key] ?? null, after: patch[key] }])) };
    }
    if (op.telegram === 'update') {
      const before = await this.execute(id.replace(/\.update$/, '.get'), { appId: input.appId, ...(plan.pathParams.client_id ? { params: { client_id: plan.pathParams.client_id } } : {}) });
      return { appId: input.appId, env: app.env, ...(plan.pathParams.client_id ? { clientId: plan.pathParams.client_id } : {}), writesPerformed: false, configured: before.configured, runtimePreserves: plan.runtimePreserves, changes: Object.fromEntries(Object.entries(plan.body!).map(([key, after]) => [key, { before: before.config?.[key] ?? null, after }])) };
    }
    if (op.domainWrite === 'configure') {
      const clientId = plan.pathParams.client_id;
      const state = domainState(await this.execute(clientId ? 'clients.domains.get' : 'domains.get', { appId: input.appId, ...(clientId ? { params: { client_id: clientId } } : {}) }));
      const current: JsonObject = { ...state, cookie_domain: state.base_cookie_domain };
      return { appId: input.appId, ...(clientId ? { clientId } : {}), env: app.env, writesPerformed: false, sessionImpactPossible: plan.body!.enabled === false, changes: Object.fromEntries(Object.entries(plan.body!).map(([key, after]) => [key, { before: current[key], after }])) };
    }
    if (op.webhookWrite === 'watchlist') return { appId: input.appId, env: app.env, writesPerformed: false, changes: { assets: { before: watchlistValues((await this.execute('webhooks.watchlist.get', { appId: input.appId! })).data, true), after: watchlistValues(plan.body) } } };
    let current = app, owner: JsonObject = {};
    if (op.settingsWrite) {
      current = await this.execute(op.settingsWrite.read, { appId: input.appId });
      if (op.settingsWrite.embeddedWallet) {
        const resolved = prepareEmbeddedWalletUpdate(current, plan.body!);
        return { appId: input.appId, env: app.env, writesPerformed: false, request: { method: plan.method, path: plan.path, body: resolved.request }, changes: { embedded_wallet_config: { before: current.embedded_wallet_config, after: resolved.expected.embedded_wallet_config } } };
      }
    }
    if (op.appClientWrite === 'update') { current = await this.execute('clients.get', { appId: input.appId!, params: { client_id: plan.pathParams.client_id } }); owner = { clientId: current.id, sdkClientId: current.sdk_client_id }; }
    if (op.webhookWrite === 'subscriptions') current = this.webhookSubscriptions(await this.execute('webhooks.list', { appId: input.appId! }));
    if (op.organizationWrite === 'update') {
      const organization = await this.findListedResource('organizations.list', input.appId!, plan.pathParams.organization_id);
      if (!organization) throw new CliError('ORGANIZATION_NOT_FOUND', 'Organization not found in this app.', 2);
      current = organization; owner = { organizationId: organization.id };
    }
    if (op.walletWrite === 'update') {
      const wallet = await this.findListedResource('wallets.list', input.appId!, plan.pathParams.wallet_id);
      if (!wallet) throw new CliError('WALLET_NOT_FOUND', 'No exact wallet match was found.', 2);
      current = this.walletValues(wallet); owner = { walletId: wallet.id, ownerId: current.owner_id, entity: current.entity, ownerApprovalRequiredForControls: current.owner_id !== null || wallet.type !== 'server' };
    }
    if (op.userWrite === 'update') {
      const user = await this.findUser(input.appId!, plan.pathParams.user_id);
      if (!user) throw new CliError('USER_NOT_FOUND', 'No exact user match was found.', 2);
      current = user; owner = { userId: user.id };
    }
    if (op.policyWrite) {
      const policy = await this.readPolicy(input.appId!, plan.pathParams.policy_id);
      owner = { policyId: policy.id, ownerId: policy.owner_id, ownerApprovalRequired: policy.owner_id !== null };
      current = op.policyWrite === 'update-rule' ? policy.rules.find((r: JsonObject) => r?.id === plan.pathParams.rule_id) : policy;
      if (!current) throw new CliError('RULE_NOT_FOUND', 'The rule was not found in this policy.', 2);
      if (op.policyWrite === 'update-rule') owner.ruleId = current.id;
    }
    return { appId: input.appId, env: app.env, ...owner, writesPerformed: false, changes: Object.fromEntries(Object.entries(plan.body!).map(([k, after]) => [k, { before: current[k], after }])) };
  }
  async apps(): Promise<JsonObject[]> { return this.execute('apps.list', {}); }
  async app(appId: string): Promise<JsonObject> {
    const app = await this.execute('apps.get', { appId });
    if (!app || app.id !== appId) throw new CliError('INVALID_APP_STATE', 'App response does not match the explicitly selected app. No further resource requests or writes were sent.');
    return app;
  }
  async createApp(accountId: string, name: string, options: ExecutionOptions = {}): Promise<JsonObject> { return this.execute('apps.create', { accountId, body: { name } }, options); }
  async updateApp(appId: string, body: JsonObject): Promise<JsonObject> { return this.execute('config.update', { appId, body }); }
  async resource(appId: string, resource: 'users/count' | 'app_client' | 'key_quorums' | 'analytics/wallet-summary'): Promise<JsonObject> {
    const ids = { 'users/count': 'users.count', app_client: 'clients.list', key_quorums: 'key-quorums.list', 'analytics/wallet-summary': 'analytics.wallets' };
    return this.execute(ids[resource], { appId });
  }
}
