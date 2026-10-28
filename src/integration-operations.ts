import { isDeepStrictEqual } from 'node:util';
import { CliError } from './errors.ts';
import { domainState } from './domain-operations.ts';
import { appClientMetadata } from './app-client-operations.ts';
import { smartWalletFields, validateSmartWallet, smartWalletMetadata, verifySmartWallet } from './smart-wallet-settings.ts';
import type { Operation, Field, JsonObject, RequestPlan } from './operations.ts';

export type IntegrationKind = 'coinbase' | 'kraken' | 'blockaid' | 'smart-wallets' | 'ecosystem';
const credential: Field = { type: 'string', minLength: 1, maxLength: 32768, sensitive: true, description: 'Sensitive provider configuration. Piped JSON only; never argv/plaintext body files or normal output.' };
const text = (description: string): Field => ({ type: 'string', minLength: 1, maxLength: 256, pattern: '^\\S+$', description });
const ecosystemUrls = ['custom_connect_url', 'custom_transact_url', 'custom_auth_authorize_url', 'custom_auth_transact_url'];
const specs: { kind: IntegrationKind; command: string; path: string; fields: Record<string, Field>; required: string[]; description: string }[] = [
  { kind: 'coinbase', command: 'integrations coinbase', path: 'coinbase_onramp_keys', required: ['coinbase_app_id', 'coinbase_key_id', 'private_key'], fields: { coinbase_app_id: text('Coinbase CDP App ID.'), coinbase_key_id: text('Coinbase CDP Key ID.'), private_key: credential }, description: 'Coinbase Onramp own credentials. Does not enable a funding method, start onboarding, buy assets or transfer funds.' },
  { kind: 'kraken', command: 'integrations kraken', path: 'kraken_embed', required: ['api_key', 'api_secret', 'master_account_iiban', 'enabled', 'is_staging'], fields: { api_key: credential, api_secret: credential, master_account_iiban: { ...credential, minLength: 0, maxLength: 256 }, enabled: { type: 'boolean', description: 'Explicit integration enabled state; credentials are not silently reused from masked read-back.' }, is_staging: { type: 'boolean', description: 'Explicit Kraken staging versus production provider environment. Separate from Privy app dev/prod.' } }, description: 'Complete Kraken Embed configuration; requires explicit provider environment and credentials. No purchases or transfers.' },
  { kind: 'blockaid', command: 'integrations blockaid', path: 'transaction_scanning/config', required: [], fields: { scanning_enabled: { type: 'boolean', description: 'Enable transaction scanning for the cross-app wallet ecosystem.' }, ofac_screening_enabled: { type: 'boolean', description: 'Enable OFAC screening. Does not perform a screening request now.' }, blockaid_api_key: { ...credential, nullable: true, description: 'Own Blockaid key, stdin only. JSON null requests removal of the override; built-in service is separate.' } }, description: 'Production-app-only cross-app scanning configuration; also requires an enabled verified cookie domain or non-private ecosystem. No production conversion, billing change, domain, account approval or publishing is performed implicitly.' },
  { kind: 'ecosystem', command: 'global-wallet config', path: 'cross-app/configuration', required: [], fields: { allowed_permissions: { type: 'string', enum: ['read_only', 'read_write'], description: 'Cross-app wallet permission mode; requires enabled verified HttpOnly cookies, like the dashboard.' }, signups_allowed: { type: 'boolean', description: 'Allow signup through integrating apps; requires enabled verified HttpOnly cookies.' }, ...Object.fromEntries(ecosystemUrls.map(key => [key, { type: 'string', nullable: true, minLength: 1, maxLength: 2048, description: 'Public HTTPS custom-experience frontend URL. Null clears this URL only; does not publish the app.' } as Field])) }, description: 'Cross-app permissions/signup/custom frontend URLs. Availability/publishing and logo are not writable here; no account approval request.' },
  { kind: 'smart-wallets', command: 'config smart-wallets', path: 'smart_wallets', required: ['enabled'], fields: smartWalletFields, description: 'Complete enabled smart-wallet configuration or enabled:false. Does not deploy wallets, contact a bundler, sign, transact or provision/fund sponsorship.' },
];

const walletConnect = { scope: 'app' as const, keywords: ['integration', 'WalletConnect', 'Reown', 'project'], evidence: 'actual Integrations WalletConnect form: wallet_connect_cloud_project_id string or null through app update; see management-map' };
export function validateIntegration(op: Operation, body: JsonObject): void {
  if (op.integration?.kind === 'smart-wallets') validateSmartWallet(body);
  if (op.integration?.kind === 'ecosystem') for (const key of ecosystemUrls) if (body[key] != null) {
    try { const url = new URL(body[key]); if (url.protocol !== 'https:' || url.username || url.password || url.hash || body[key] !== body[key].trim()) throw new Error(); }
    catch { throw new CliError('INVALID_ECOSYSTEM_URL', 'Custom experience URLs must be public HTTPS URLs without userinfo, fragments or surrounding whitespace.', 2); }
  }
}
export function integrationMetadata(kind: IntegrationKind, raw: any): JsonObject {
  if (kind === 'smart-wallets') return smartWalletMetadata(raw);
  if (kind === 'ecosystem') {
    if (!raw || !['private', 'public', 'public_pending_approval', 'invite_only'].includes(raw.availability) || !['read_only', 'read_write'].includes(raw.allowed_permissions) || typeof raw.signups_allowed !== 'boolean' || ![...ecosystemUrls, 'icon_url'].every(key => raw[key] == null || typeof raw[key] === 'string')) throw new CliError('INVALID_ECOSYSTEM_STATE', 'Expected explicit cross-app availability, permission and signup controls.');
    return { config: { availability: raw.availability, allowed_permissions: raw.allowed_permissions, signups_allowed: raw.signups_allowed, ...Object.fromEntries([...ecosystemUrls, 'icon_url'].map(key => [key, raw[key] ?? null])) }, externalIntegrationVerified: false };
  }
  if (raw === null || raw && typeof raw === 'object' && !Array.isArray(raw) && !Object.keys(raw).length) return { configured: false, config: null, externalIntegrationVerified: false };
  const fail = () => { const error = new CliError('INVALID_INTEGRATION_STATE', 'Unexpected provider configuration; no credentials or response values are exposed.'); error.details = { provider: kind, responseType: typeof raw, fieldTypes: Object.fromEntries(['enabled', 'coinbaseAppId', 'coinbaseKeyId', 'scanning_enabled', 'ofac_screening_enabled'].map(key => [key, typeof raw?.[key]])) }; throw error; };
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return fail();
  if (kind === 'coinbase') {
    if (typeof raw.coinbaseAppId !== 'string' || typeof raw.coinbaseKeyId !== 'string') return fail();
    return { configured: true, config: { coinbase_app_id: raw.coinbaseAppId, coinbase_key_id: raw.coinbaseKeyId }, externalIntegrationVerified: false };
  }
  if (kind === 'kraken') {
    if (typeof raw.enabled !== 'boolean' || ['api_base_url', 'api_key', 'api_secret', 'master_account_iiban'].some(key => raw[key] != null && typeof raw[key] !== 'string')) return fail();
    return { configured: Boolean(raw.api_key || raw.api_secret || raw.enabled), config: { enabled: raw.enabled, is_staging: raw.api_base_url ? raw.api_base_url === 'https://nexus-api.sandbox.services.payward.com' : null }, credentialPresence: { identifier: Boolean(raw.api_key), material: Boolean(raw.api_secret), fundingAccount: Boolean(raw.master_account_iiban) }, externalIntegrationVerified: false };
  }
  if (typeof raw.scanning_enabled !== 'boolean' || typeof raw.ofac_screening_enabled !== 'boolean' || raw.blockaid_api_key != null && typeof raw.blockaid_api_key !== 'string') return fail();
  return { configured: true, config: { scanning_enabled: raw.scanning_enabled, ofac_screening_enabled: raw.ofac_screening_enabled }, credentialPresence: { custom: Boolean(raw.blockaid_api_key) }, externalIntegrationVerified: false };
}
type Request = (path: string, method?: string, body?: JsonObject, acknowledgementOnly?: boolean) => Promise<any>;
export async function readIntegration(kind: IntegrationKind, path: string, request: Request): Promise<JsonObject> {
  try { return integrationMetadata(kind, await request(path)); }
  catch (error) {
    if (kind === 'kraken' && error instanceof CliError && error.status === 404) return { configured: null, config: null, configurationState: 'not_returned', httpStatus: 404, externalIntegrationVerified: false, note: 'Dashboard GET returned 404 after app access was established. This does not prove absence or endpoint removal; an explicit complete configuration is required for writes.' };
    throw error;
  }
}
async function requireScanningEligibility(appId: string, request: Request): Promise<void> {
  const root = `/api/v1/apps/${appId}`, cross = await request(root + '/cross-app/configuration');
  if (['public', 'public_pending_approval', 'invite_only'].includes(cross?.availability)) return;
  if (cross?.availability !== 'private') throw new CliError('INVALID_ECOSYSTEM_STATE', 'Cannot establish cross-app availability. No scanning write was sent.');
  await requireCookieDomain(appId, request);
}
export async function cookieDomainEnabled(appId: string, request: Request): Promise<boolean> {
  const root = `/api/v1/apps/${appId}`;
  const domain = domainState(await request(root + '/domains'));
  if (domain?.status === 'verified' && domain.enabled === true && typeof domain.base_cookie_domain === 'string' && domain.base_cookie_domain.length > 0) return true;
  const clients = appClientMetadata(await request(root + '/app_client'), appId);
  return clients.some(row => row.cookie_auth_enabled === true && typeof row.cookie_domain === 'string' && row.cookie_domain && typeof row.cookie_auth_toggled_at === 'string' && Number.isFinite(Date.parse(row.cookie_auth_toggled_at)) && typeof row.cookie_domain_verified_at === 'string' && Number.isFinite(Date.parse(row.cookie_domain_verified_at)));
}
async function requireCookieDomain(appId: string, request: Request): Promise<void> {
  if (await cookieDomainEnabled(appId, request)) return;
  throw new CliError('COOKIE_DOMAIN_REQUIRED', 'This dashboard-gated cross-app setting requires an enabled verified cookie domain in the current state. No domain, publishing or account approval was enabled; no write was sent.', 2);
}
export async function writeIntegration(op: Operation, plan: RequestPlan, request: Request): Promise<JsonObject> {
  const kind = op.integration!.kind, body = plan.body!, appId = plan.pathParams.app_id;
  const before = await readIntegration(kind, plan.path, request);
  if (kind === 'blockaid') {
    if (!before.configured) throw new CliError('INVALID_INTEGRATION_STATE', 'Cannot establish existing scanning controls. No write was sent.');
    await requireScanningEligibility(appId, request);
  }
  if (kind === 'ecosystem' && ['allowed_permissions', 'signups_allowed'].some(key => Object.hasOwn(body, key))) await requireCookieDomain(appId, request);
  await request(plan.path, 'POST', body, true);
  try {
    const raw = await request(plan.path), after = integrationMetadata(kind, raw);
    let exact = false;
    if (kind === 'smart-wallets') { verifySmartWallet(body, raw); exact = true; }
    else if (kind === 'ecosystem') {
      if (!isDeepStrictEqual(after.config, { ...before.config, ...body })) throw new Error();
      exact = true;
    } else if (kind === 'coinbase') {
      if (!after.configured || after.config.coinbase_app_id !== body.coinbase_app_id || after.config.coinbase_key_id !== body.coinbase_key_id) throw new Error();
    } else if (kind === 'kraken') {
      if (after.config?.enabled !== body.enabled || after.config?.is_staging !== body.is_staging || !after.credentialPresence.identifier || !after.credentialPresence.material || after.credentialPresence.fundingAccount !== Boolean(body.master_account_iiban)) throw new Error();
    } else {
      for (const key of ['scanning_enabled', 'ofac_screening_enabled']) if (!isDeepStrictEqual(after.config?.[key], Object.hasOwn(body, key) ? body[key] : before.config?.[key])) throw new Error();
      if (Object.hasOwn(body, 'blockaid_api_key') ? after.credentialPresence.custom !== Boolean(body.blockaid_api_key) : after.credentialPresence.custom !== before.credentialPresence.custom) throw new Error();
      exact = !Object.hasOwn(body, 'blockaid_api_key') || body.blockaid_api_key === null;
    }
    return { appId, acknowledged: true, verified: exact, metadataVerified: true, ...(!exact ? { secretValuesVerified: false } : {}), state: after, externalIntegrationVerified: false };
  } catch { throw new CliError('INTEGRATION_VERIFY_FAILED', 'Provider configuration write was acknowledged but fresh read-back did not match. Inspect current metadata; no write was repeated.'); }
}
export const integrationOperations: Operation[] = [
  ...specs.flatMap((spec): Operation[] => (['read', 'update'] as const).map(action => ({
    scope: 'app', id: `${spec.command.replaceAll(' ', '.')}.${action === 'read' ? 'get' : 'update'}`, command: `${spec.command} ${action === 'read' ? 'get' : 'update'}`, method: action === 'read' ? 'GET' : 'POST', path: `/api/v1/apps/{app_id}/${spec.path}`, integration: { kind: spec.kind, action }, keywords: ['integration', 'settings', spec.kind, 'provider'], evidence: 'actual Integrations/Ecosystem/Wallets Advanced forms and loaded handlers; see management-map', summary: `${action === 'read' ? 'Read safe metadata for' : 'Configure'} ${spec.kind}. ${spec.description}`,
    ...(action === 'update' ? { body: { type: 'object' as const, additionalProperties: false as const, minProperties: 1, required: spec.required, properties: spec.fields } } : {}), response: 'Allowlisted public metadata/credential presence only. Fresh write verification distinguishes exact configuration from masked credentials. externalIntegrationVerified:false; no automatic retries.', examples: [`privy ${spec.command} ${action === 'read' ? 'get' : 'update --body - --dry-run'}`],
  }))),
  { ...walletConnect, id: 'integrations.walletconnect.get', command: 'integrations walletconnect get', method: 'GET', path: '/api/dashboard/apps/{app_id}', selectFields: ['wallet_connect_cloud_project_id'], summary: 'Read the public WalletConnect/Reown project ID configured for this app.', response: 'Public project ID or null. Does not create a Reown project or establish a wallet connection.', examples: ['privy integrations walletconnect get'] },
  { ...walletConnect, id: 'integrations.walletconnect.update', command: 'integrations walletconnect update', method: 'POST', path: '/api/v1/apps/{app_id}', settingsWrite: { read: 'integrations.walletconnect.get', externalIntegration: true }, body: { type: 'object', additionalProperties: false, required: ['wallet_connect_cloud_project_id'], properties: { wallet_connect_cloud_project_id: { type: 'string', nullable: true, minLength: 1, maxLength: 128, pattern: '^\\S+$', description: 'Public WalletConnect/Reown project ID (not a secret). JSON null removes the app override; does not delete the provider project.' } } }, summary: 'Set or clear the WalletConnect project ID; preview/diff, environment guard and fresh read-back.', response: 'Configuration persistence only; externalIntegrationVerified:false. Does not test provider ownership, origin allowlisting, wallet pairing, signing or transactions.', examples: ['privy integrations walletconnect update --wallet-connect-cloud-project-id <project-id> --diff', 'privy integrations walletconnect update --body \'{"wallet_connect_cloud_project_id":null}\' --yes'] },
];
