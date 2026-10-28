import { createHash, createPublicKey } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { CliError } from './errors.ts';
import type { JsonObject, Operation, RequestPlan } from './operations.ts';
export type SecurityKind = 'redirects' | 'key-export' | 'client-key-export' | 'privy-home' | 'verification-key';
export interface SecurityContext { app: JsonObject; account: JsonObject }
export type SecurityRequest = (path: string, method?: string, body?: JsonObject, ack?: boolean) => Promise<any>;
export function owningAccount(app: JsonObject, teams: JsonObject[]): JsonObject {
  const owners = teams.filter(t => Array.isArray(t.apps) && t.apps.some((a: JsonObject) => a.id === app.id));
  if (owners.length !== 1 || typeof owners[0].id !== 'string') throw new CliError('ACCOUNT_SCOPE_UNVERIFIED', 'Cannot establish the selected app’s owning account.');
  return owners[0];
}
const spec = [
  { kind: 'redirects', path: 'url_restriction', field: 'allowed_oauth_redirect_urls', type: 'array', description: 'Full OAuth redirect URL/path allowlist. Must match existing allowed origins; no implicit origin widening. [] clears path restrictions.' },
  { kind: 'key-export', path: 'toggle_key_export', field: 'disabled', type: 'boolean', description: 'Block all wallet-key exports for this app. This configures export permission; never retrieves a key.' },
  { kind: 'client-key-export', path: 'client_key_export', field: 'enabled', type: 'boolean', description: 'Allow client-side wallet-key export. Account feature and nonlegacy wallet mode required; no actual export.' },
  { kind: 'privy-home', path: 'recovery_config', field: 'enabled', type: 'boolean', description: 'Allow customer key export through Privy Home. Not a wallet recovery operation; requires a supported Privy login method.' },
] as const;
const common = { scope: 'app' as const, keywords: ['security', 'settings'], evidence: 'Actual Settings/Wallets Advanced loaded forms, confirmation copy and POST hooks; see management-map.' };
export const securityOperations: Operation[] = [
  ...spec.flatMap(s => (['read', 'update'] as const).map(action => ({ ...common, keywords: [...common.keywords, ...(s.kind === 'redirects' ? ['OAuth callback', 'redirect restrictions', 'redirect URI', 'callback URL', 'origin', 'allowlist'] : ['key export', 'export permission', 'wallet', ...(s.kind === 'privy-home' ? ['Privy Home', 'recovery'] : [])])], id: `config.${s.kind}.${action === 'read' ? 'get' : action}`, command: `config ${s.kind} ${action === 'read' ? 'get' : action}`, method: action === 'read' ? 'GET' as const : 'POST' as const, path: action === 'read' && s.kind !== 'privy-home' ? '/api/dashboard/apps/{app_id}' : `/api/v1/apps/{app_id}/${s.path}`, securitySetting: { kind: s.kind, action }, ...(action === 'update' ? { body: { type: 'object' as const, additionalProperties: false as const, required: [s.field], properties: { [s.field]: s.type === 'array' ? { type: 'array' as const, maxItems: 100, items: { type: 'string' as const, maxLength: 2048 }, description: s.description } : { type: 'boolean' as const, description: s.description } } } } : {}), summary: `${action === 'read' ? 'Inspect' : 'Configure'} ${s.kind}. ${s.description}`, response: 'Writes need exact --confirm-name, --allow-access-change, --yes and production opt-in. Feature gates, fresh state and read-back; no keys, signing, billing or account-wide enablement.', examples: [`privy config ${s.kind} ${action === 'read' ? 'get' : `update --body '${JSON.stringify({ [s.field]: s.type === 'array' ? [] : true })}' --dry-run`}`] }))),
  ...(['read', 'rotate'] as const).map(action => ({ ...common, keywords: [...common.keywords, 'key rotation', 'JWT rotation', 'verification', 'JWKS', 'sessions'], id: `config.verification-key.${action === 'read' ? 'get' : action}`, command: `config verification-key ${action === 'read' ? 'get' : action}`, method: action === 'read' ? 'GET' as const : 'POST' as const, path: action === 'read' ? '/api/dashboard/apps/{app_id}' : '/api/v1/apps/{app_id}/rotate_keys', securitySetting: { kind: 'verification-key' as const, action }, ...(action === 'rotate' ? { body: { type: 'object' as const, properties: {}, additionalProperties: false as const } } : {}), summary: action === 'read' ? 'Read app token-verification public-key fingerprint; no signing/private key.' : 'Rotate this app’s token-signing/verification key ONCE; not app API-secret rotation.', response: 'Rotation requires --confirm-name --allow-access-change --allow-session-impact --yes, plus production opt-in. Existing rotated key remains valid per dashboard; a second rotation can invalidate its sessions. Direct-key consumers must update manually. Changed public-key fingerprint verified; token/session effects not exercised. No retry.', examples: [`privy config verification-key ${action === 'read' ? 'get' : 'rotate --dry-run'}`] })),
];
function redirectUrl(value: string): { value: string; origin: string; http: boolean } {
  try {
    const u = new URL(value), native = ['chrome-extension:', 'capacitor:', 'ionic:'].includes(u.protocol);
    if ((!native && !['https:', 'http:'].includes(u.protocol)) || !u.hostname || u.username || u.password || u.search || u.hash || /\s/.test(value) || value.includes('\\') || value.includes('*')) throw new Error();
    const origin = native ? `${u.protocol}//${u.host}` : u.origin;
    if (u.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(u.hostname)) throw new Error();
    return { value: origin + (u.pathname === '/' ? '' : u.pathname), origin, http: u.protocol === 'http:' };
  } catch { throw new CliError('INVALID_REDIRECT_URL', 'Use a concrete HTTPS, loopback HTTP or supported native (chrome-extension/capacitor/ionic) redirect URL without credentials, query, fragment, wildcard or whitespace. No URL parts are silently discarded.', 2); }
}
export function validateSecurity(op: Operation, body: JsonObject): void {
  if (op.securitySetting?.kind !== 'redirects' || op.securitySetting.action !== 'update') return;
  body.allowed_oauth_redirect_urls = body.allowed_oauth_redirect_urls.map((v: string) => redirectUrl(v).value);
  if (new Set(body.allowed_oauth_redirect_urls).size !== body.allowed_oauth_redirect_urls.length) throw new CliError('DUPLICATE_REDIRECT', 'Redirect URLs must be distinct after URL normalization.', 2);
}
export function redirectsAllowed(app: JsonObject, urls: string[]): void {
  if (!Array.isArray(app.allowed_domains) || !app.allowed_domains.every((v: unknown) => typeof v === 'string')) throw new CliError('INVALID_ORIGIN_STATE', 'Cannot establish existing allowed origins. No write was sent.');
  for (const value of urls) {
    const u = redirectUrl(value);
    if (u.http && !['dev', 'development'].includes(app.env)) throw new CliError('INSECURE_REDIRECT', 'Loopback HTTP redirects are supported only on development apps.', 2);
    // Dashboard FN matcher requires a matching entry even when the origin list is empty.
    // Escape all regex metacharacters, not just dots. Each * matches within one dot-delimited segment.
    const matches = app.allowed_domains.some((rule: string) => rule !== '*' && new RegExp('^' + rule.split('*').map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('[^.]*') + '$').test(u.origin));
    if (!matches) throw new CliError('REDIRECT_ORIGIN_NOT_ALLOWED', 'Every redirect must match an explicitly configured allowed origin. Empty origins or a bare * are not accepted as redirect authorization; configure intended origins separately. No write was sent.', 2);
  }
}
function bool(value: unknown): boolean | null {
  if (value == null) return null;
  if (typeof value !== 'boolean') throw new CliError('INVALID_SECURITY_STATE', 'Unexpected security setting type; no values exposed.');
  return value;
}
function fingerprint(value: unknown): string {
  try {
    if (typeof value !== 'string' || !value || value.includes('PRIVATE KEY')) throw new Error();
    if (value.length > 32768) throw new Error();
    const packed = value.match(/^-----BEGIN PUBLIC KEY-----\s*([A-Za-z0-9+/=\s]+)\s*-----END PUBLIC KEY-----$/);
    const pem = packed ? `-----BEGIN PUBLIC KEY-----\n${packed[1].replace(/\s/g, '')}\n-----END PUBLIC KEY-----` : value;
    const key = value.startsWith('-----BEGIN') ? createPublicKey(pem) : createPublicKey({ key: Buffer.from(value, 'base64'), format: 'der', type: 'spki' });
    return createHash('sha256').update(key.export({ format: 'der', type: 'spki' })).digest('hex');
  } catch { throw new CliError('INVALID_VERIFICATION_KEY', 'Cannot establish the app’s public verification-key fingerprint. No key material exposed.'); }
}
export async function securityState(kind: SecurityKind, context: SecurityContext, request: SecurityRequest): Promise<JsonObject> {
  const { app, account } = context;
  if (kind === 'redirects') {
    if (!Array.isArray(app.allowed_oauth_redirect_urls) || !app.allowed_oauth_redirect_urls.every((v: unknown) => typeof v === 'string')) throw new CliError('INVALID_REDIRECT_STATE', 'Cannot establish current OAuth redirect restrictions.');
    return { allowed_oauth_redirect_urls: app.allowed_oauth_redirect_urls, pathRestrictionActive: app.allowed_oauth_redirect_urls.length > 0 };
  }
  if (kind === 'verification-key') return { sha256: fingerprint(app.verification_key), publicKeyOnly: true };
  if (kind === 'privy-home') {
    const raw = await request(`/api/v1/apps/${app.id}/recovery_config`);
    if (typeof raw?.enabled !== 'boolean') throw new CliError('INVALID_SECURITY_STATE', 'Cannot establish Privy Home key-export configuration.');
    return { enabled: raw.enabled, eligible: ['email_auth', 'sms_auth', 'google_oauth', 'twitter_oauth', 'farcaster_auth'].some(k => app[k] === true) };
  }
  if (kind === 'key-export') return { disabled: bool(app.key_export_disabled), eligible: account.keyExportToggleAllowed === true || app.key_export_disabled === true };
  return { enabled: bool(app.client_key_export_enabled), eligible: account.clientKeyExportAllowed === true && app.embedded_wallet_config?.mode === 'user-controlled-server-wallets-only' };
}
export async function writeSecurity(op: Operation, plan: RequestPlan, context: () => Promise<SecurityContext>, request: SecurityRequest, confirmName: string): Promise<JsonObject> {
  const kind = op.securitySetting!.kind, before = await context(), state = await securityState(kind, before, request);
  if (before.app.name !== confirmName) throw new CliError('APP_NAME_MISMATCH', 'Use --confirm-name with the exact app name. No write was sent.', 2);
  if ('eligible' in state && state.eligible !== true) throw new CliError('SECURITY_FEATURE_UNAVAILABLE', 'This security control is not eligible in the observed dashboard/account/wallet-mode state. No account feature or ownership mode was changed; no write was sent.', 2);
  if (kind === 'redirects') redirectsAllowed(before.app, plan.body!.allowed_oauth_redirect_urls);
  const control = (c: SecurityContext) => ({ name: c.app.name, env: c.app.env, accountId: c.account.id, exportDisabled: c.app.key_export_disabled, clientExport: c.app.client_key_export_enabled, mode: c.app.embedded_wallet_config?.mode, origins: c.app.allowed_domains, login: ['email_auth', 'sms_auth', 'google_oauth', 'twitter_oauth', 'farcaster_auth'].map(k => c.app[k]), features: [c.account.keyExportToggleAllowed, c.account.clientKeyExportAllowed] });
  const latest = await context();
  if (!isDeepStrictEqual(control(before), control(latest)) || !isDeepStrictEqual(state, await securityState(kind, latest, request))) throw new CliError('SECURITY_STATE_CHANGED', 'App security configuration changed during preflight. No write was sent.', 2);
  if (kind !== 'verification-key' && Object.entries(plan.body!).every(([k, v]) => isDeepStrictEqual(state[k], v))) return { appId: before.app.id, state, verified: true, writesPerformed: false };
  await request(plan.path, 'POST', plan.body ?? {}, true);
  try {
    const afterContext = await context(), after = await securityState(kind, afterContext, request);
    if (kind === 'verification-key' ? after.sha256 === state.sha256 : !Object.entries(plan.body!).every(([k, v]) => isDeepStrictEqual(after[k], v))) throw new Error();
    if (kind === 'redirects' && !isDeepStrictEqual(before.app.allowed_domains, afterContext.app.allowed_domains)) throw new Error();
    if (!isDeepStrictEqual(before.app.embedded_wallet_config, afterContext.app.embedded_wallet_config)) throw new Error();
    return { appId: before.app.id, verified: true, writesPerformed: true, state: after, externalIntegrationVerified: false, ...(kind === 'verification-key' ? { previousSha256: state.sha256, rotationsPerformed: 1, sessionInvalidationVerified: false, consumerKeyUpdateRequired: true } : {}) };
  } catch { throw new CliError('SECURITY_VERIFY_FAILED', 'Security-setting write acknowledged but fresh state did not match. Inspect current settings; no retry or rollback occurred.'); }
}
