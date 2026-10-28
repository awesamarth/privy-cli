import { isDeepStrictEqual } from 'node:util';
import { CliError } from './errors.ts';
import type { Operation, JsonObject, RequestPlan } from './operations.ts';
const common = { scope: 'app' as const, keywords: ['advanced', 'authentication', 'merging', 'recovery', 'export', 'security'], evidence: 'Loaded Settings Advanced account-merging confirmation, Privy Home recovery_config, Wallets Advanced export controls and custom-JWT account gate.' };
export const advancedOperations: Operation[] = [
  ...(['get', 'update'] as const).map(action => ({ ...common, keywords: [...common.keywords, 'captcha', 'bots', 'login', 'turnstile', 'hcaptcha'], id: `config.captcha.${action}`, command: `config captcha ${action}`, method: action === 'get' ? 'GET' as const : 'POST' as const, path: '/api/v1/apps/{app_id}/captcha_configuration', advancedAction: action === 'get' ? 'captcha-read' as const : 'captcha-update' as const, ...(action === 'update' ? { body: { type: 'object' as const, additionalProperties: false as const, required: ['enabled_provider'], properties: { enabled_provider: { type: 'string' as const, nullable: true, enum: ['turnstile', 'hcaptcha'], description: 'Customer-app CAPTCHA provider; JSON null disables it. Not the dashboard/CLI login challenge. hCaptcha requires compatible frontend SDKs (React react-auth@3.9.0+ in the inspected UI).' }, risk_tolerance: { type: 'string' as const, enum: ['lenient', 'balanced', 'strict'], description: 'Required with hcaptcha; omit for Turnstile or disabling.' } } } } : {}), summary: `${action === 'get' ? 'Read' : 'Configure'} customer-app CAPTCHA protection; no challenge solving or dashboard-auth changes.`, response: 'Writes require --confirm-name --allow-access-change --yes and production opt-in where applicable. Provider/risk and app flags read-back; external login behavior unverified.', examples: [`privy config captcha ${action}${action === 'update' ? ' --enabled-provider hcaptcha --risk-tolerance strict --diff' : ''}`] })),
  { ...common, keywords: [...common.keywords, 'android', 'native', 'passkeys', 'certificate', 'fingerprint'], id: 'config.android-key-hashes.get', command: 'config android-key-hashes get', method: 'GET', path: '/api/dashboard/apps/{app_id}', selectFields: ['allowed_android_signing_key_hashes'], summary: 'Read Android app signing-certificate SHA-256 fingerprints (public metadata, not signing keys).', response: 'Configured fingerprints; no private-key access or native-app authentication test.', examples: ['privy config android-key-hashes get'] },
  { ...common, keywords: [...common.keywords, 'android', 'native', 'passkeys', 'certificate', 'fingerprint'], id: 'config.android-key-hashes.update', command: 'config android-key-hashes update', method: 'POST', path: '/api/v1/apps/{app_id}', settingsWrite: { read: 'config.android-key-hashes.get', unordered: ['allowed_android_signing_key_hashes'], externalIntegration: true }, body: { type: 'object', additionalProperties: false, required: ['allowed_android_signing_key_hashes'], properties: { allowed_android_signing_key_hashes: { type: 'array', maxItems: 100, items: { type: 'string', pattern: '^([A-F0-9]{2}:){31}[A-F0-9]{2}$' }, description: 'Full replacement, up to100 uppercase colon-separated SHA-256 certificate fingerprints. [] clears the list and may break native passkey/auth flows. No signing or key export.' } } }, summary: 'Replace Android signing-certificate fingerprints with diff and fresh set verification.', response: 'Configuration persistence only, not certificate ownership or native-app login proof.', examples: ['privy config android-key-hashes update --allowed-android-signing-key-hashes "[]" --diff'] },
  { ...common, id: 'config.advanced.get', command: 'config advanced get', method: 'GET', path: '/api/dashboard/apps/{app_id}', advancedAction: 'inspect', summary: 'Inspect account-merging, wallet export/recovery and custom-auth settings without exposing keys or changing ownership.', response: 'Safe selected-app controls and owning-account capability flags. Missing values stay unknown; no account enablement, private keys, signing or recovery operation.', examples: ['privy config advanced get'] },
  { ...common, id: 'config.account-merging.get', command: 'config account-merging get', method: 'GET', path: '/api/dashboard/apps/{app_id}', advancedAction: 'merging-read', summary: 'Read same-email customer-account merging across login methods; not dashboard team membership.', response: 'Stored setting and separately labelled dashboard default. Existing separately-created users are not retroactively merged.', examples: ['privy config account-merging get'] },
  { ...common, id: 'config.account-merging.update', command: 'config account-merging update', method: 'POST', path: '/api/v1/apps/{app_id}/merge_accounts_config', advancedAction: 'merging-update', body: { type: 'object', additionalProperties: false, required: ['merge_accounts_by_email'], properties: { merge_accounts_by_email: { type: 'boolean', description: 'Merge customer identities sharing an email across login methods on subsequent logins. Does not retroactively merge existing separate users; changing back does not undo identities already linked.' } } }, summary: 'Configure future same-email login linking with explicit identity-impact acknowledgement.', response: 'Requires --confirm-name, --allow-access-change, --yes; production requires --allow-production. Fresh setting verification, not end-user login proof. No direct user merge, unlink, session revocation or owner change.', examples: ['privy config account-merging update --merge-accounts-by-email false --diff'] },
];
export function validateAdvanced(op: Operation, body: JsonObject): void {
  if (op.advancedAction === 'captcha-update' && (body.enabled_provider === 'hcaptcha' ? !body.risk_tolerance : Object.hasOwn(body, 'risk_tolerance'))) throw new CliError('INVALID_CAPTCHA_CONFIG', 'Supply explicit risk_tolerance with hcaptcha only; omit it for Turnstile or disabling.', 2);
  if (op.id === 'config.android-key-hashes.update' && new Set(body.allowed_android_signing_key_hashes).size !== body.allowed_android_signing_key_hashes.length) throw new CliError('DUPLICATE_FINGERPRINT', 'Android certificate fingerprints must be distinct.', 2);
}
function flag(record: JsonObject, key: string): boolean | null {
  if (record[key] == null) return null;
  if (typeof record[key] !== 'boolean') throw new CliError('INVALID_ADVANCED_STATE', 'Unexpected advanced-setting type. No raw values are exposed.');
  return record[key];
}
export function mergingState(app: JsonObject): JsonObject {
  const stored = flag(app, 'merge_accounts_by_email');
  return { appId: app.id, stored, dashboardEffective: stored ?? true, usesDashboardDefault: stored === null, retroactiveMerge: false, externalLoginVerified: false };
}
type Request = (path: string, method?: string, body?: JsonObject, acknowledgementOnly?: boolean) => Promise<any>;
export async function inspectAdvanced(app: JsonObject, teams: JsonObject[], request: Request): Promise<JsonObject> {
  const accounts = teams.filter(team => Array.isArray(team.apps) && team.apps.some((row: JsonObject) => row.id === app.id));
  if (accounts.length !== 1) throw new CliError('ACCOUNT_SCOPE_UNVERIFIED', 'Cannot establish the selected app’s owning account.');
  const account = accounts[0];
  let home: JsonObject;
  try {
    const raw = await request(`/api/v1/apps/${app.id}/recovery_config`);
    if (!raw || typeof raw.enabled !== 'boolean') throw new CliError('INVALID_ADVANCED_STATE', 'Unexpected Privy Home configuration; no values exposed.');
    home = { configurationReturned: true, keyExportEnabled: raw.enabled };
  } catch (error) {
    if (!(error instanceof CliError) || error.status !== 404) throw error;
    home = { configurationReturned: false, keyExportEnabled: null, httpStatus: 404 };
  }
  return { appId: app.id, env: app.env, accountMerging: mergingState(app), keyExport: { clientSideEnabled: flag(app, 'client_key_export_enabled'), disabled: flag(app, 'key_export_disabled'), clientSideFeatureAllowed: flag(account, 'clientKeyExportAllowed'), disableFeatureAllowed: flag(account, 'keyExportToggleAllowed'), writesSupported: true }, privyHome: { ...home, writesSupported: true }, customAuthentication: { enabled: flag(app, 'custom_jwt_auth'), accountFeatureEnabled: flag(account, 'customJwtAccountEnabled'), verifierManagementImplemented: true }, writesPerformed: false, note: 'This command only inspects controls. Dedicated guarded commands configure export permissions or JWT verifiers. No key material is fetched, no account feature is enabled, and no wallet-owner authorization is performed.' };
}
export async function readCaptcha(path: string, request: Request): Promise<JsonObject> {
  const raw = await request(path);
  if (!raw || !Object.hasOwn(raw, 'enabled_provider') || raw.enabled_provider !== null && !['turnstile', 'hcaptcha'].includes(raw.enabled_provider)) throw new CliError('INVALID_CAPTCHA_STATE', 'Cannot establish customer-app CAPTCHA provider.');
  const risk = raw.enabled_provider === 'hcaptcha' ? raw.config?.risk_tolerance : null;
  if (raw.enabled_provider === 'hcaptcha' && !['lenient', 'balanced', 'strict'].includes(risk)) throw new CliError('INVALID_CAPTCHA_STATE', 'Cannot establish hCaptcha risk configuration.');
  return { enabled_provider: raw.enabled_provider, risk_tolerance: risk, externalLoginVerified: false };
}
export async function writeCaptcha(plan: RequestPlan, app: () => Promise<JsonObject>, request: Request, confirmName?: string): Promise<JsonObject> {
  const beforeApp = await app(), before = await readCaptcha(plan.path, request);
  if (typeof beforeApp.name !== 'string' || beforeApp.name !== confirmName) throw new CliError('APP_NAME_MISMATCH', 'Use --confirm-name with the exact app name. No write was sent.', 2);
  const desired = { enabled_provider: plan.body!.enabled_provider, risk_tolerance: plan.body!.risk_tolerance ?? null, externalLoginVerified: false };
  if (isDeepStrictEqual(before, desired)) return { appId: beforeApp.id, verified: true, writesPerformed: false, state: before };
  const latest = await app();
  if (latest.name !== beforeApp.name || latest.env !== beforeApp.env || !isDeepStrictEqual(await readCaptcha(plan.path, request), before)) throw new CliError('ADVANCED_STATE_CHANGED', 'CAPTCHA configuration/app context changed during preflight. No write was sent.', 2);
  await request(plan.path, 'POST', plan.body, true);
  try {
    const after = await readCaptcha(plan.path, request), current = await app();
    if (!isDeepStrictEqual(after, desired) || current.captcha_enabled !== (desired.enabled_provider !== null) || desired.enabled_provider !== null && current.enabled_captcha_provider !== desired.enabled_provider) throw new Error();
    return { appId: beforeApp.id, verified: true, writesPerformed: true, state: after, externalLoginVerified: false };
  } catch { throw new CliError('CAPTCHA_VERIFY_FAILED', 'Customer-app CAPTCHA write acknowledged but fresh read-back did not match. Inspect config captcha get; no retry occurred.'); }
}
export async function writeMerging(plan: RequestPlan, app: () => Promise<JsonObject>, request: Request, confirmName?: string): Promise<JsonObject> {
  const before = await app();
  if (typeof before.name !== 'string' || before.name !== confirmName) throw new CliError('APP_NAME_MISMATCH', 'Use --confirm-name with the exact selected app name. No write was sent.', 2);
  const state = mergingState(before), desired = plan.body!.merge_accounts_by_email;
  if (state.stored === desired) return { ...state, verified: true, writesPerformed: false };
  const relevant = (a: JsonObject) => ({ id: a.id, name: a.name, env: a.env, merging: mergingState(a), embedded: a.embedded_wallet_config, auth: Object.fromEntries(Object.entries(a).filter(([key]) => /(_auth|_oauth)$/.test(key))) });
  if (!isDeepStrictEqual(relevant(before), relevant(await app()))) throw new CliError('ADVANCED_STATE_CHANGED', 'Authentication or wallet configuration changed during preflight. No write was sent.', 2);
  await request(plan.path, 'POST', plan.body, true);
  try {
    const after = await app();
    if (!isDeepStrictEqual(relevant(after), relevant({ ...before, merge_accounts_by_email: desired }))) throw new Error();
    return { ...mergingState(after), verified: true, writesPerformed: true, externalLoginVerified: false };
  } catch { throw new CliError('ADVANCED_VERIFY_FAILED', 'Account-merging write acknowledged but fresh settings did not match. Inspect current state; no write was repeated.'); }
}
