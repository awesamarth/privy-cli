import { isDeepStrictEqual } from 'node:util';
import { CliError, redact } from './errors.ts';
import type { Field, JsonObject, Operation, RequestPlan } from './operations.ts';

export const builtinProviders = ['google', 'apple', 'twitter', 'github', 'discord', 'linkedin', 'tiktok', 'line', 'twitch', 'spotify', 'instagram', 'telegram'];
const text = (description: string): Field => ({ type: 'string', minLength: 1, maxLength: 4096, description });
const provider: Field = { ...text('Builtin provider identifier.'), enum: builtinProviders };
const secret: Field = { ...text('Credential material: piped JSON only; never echoed or saved to a plaintext file.'), sensitive: true, maxLength: 32768 };
const properties: Record<string, Field> = {
  provider, client_id: text('Provider client ID. Configure together with client_secret.'), client_secret: secret,
  scopes: { type: 'array', items: { type: 'string', maxLength: 2048 }, maxItems: 100, description: 'Replace configured additional scopes; does not silently widen them.' },
  return_oauth_tokens: { type: 'boolean', description: 'Return provider tokens to the app after user authorization; does not fetch tokens now.' },
  apple: { type: 'object', additionalProperties: false, required: ['key_id', 'team_id'], properties: { key_id: text('Apple key ID.'), team_id: text('Apple developer team ID.') }, description: 'Apple-specific key metadata; client_secret contains the signing-key material. No signatures performed by CLI.' },
  twitter: { type: 'object', sensitive: true, additionalProperties: false, required: ['oauth_1_enabled'], properties: { oauth_1_enabled: { type: 'boolean', description: 'Enable optional OAuth1.' }, oauth_1_api_key: secret, oauth_1_api_secret: secret }, description: 'Optional Twitter OAuth1 configuration; stdin only.' },
};
const customProperties: Record<string, Field> = {
  provider: { ...text('Immutable custom provider ID, custom:<lowercase-slug>.'), pattern: '^custom:[a-z0-9]+(?:-[a-z0-9]+)*$', maxLength: 128 },
  provider_display_name: { ...text('Display name used in the login UI.'), pattern: '^[a-zA-Z0-9 -]+$', maxLength: 100 },
  provider_icon_url: text('HTTPS provider icon URL.'), client_id: properties.client_id, client_secret: secret,
  authorization_url: text('HTTPS authorization URL.'), token_url: text('HTTPS token URL.'), jwks_url: text('HTTPS JWKS URL.'),
  scopes: { ...properties.scopes, minItems: 1, description: 'Explicit nonempty scope array. For OIDC id_token providers include the required openid scope.' }, scopes_delimiter: { type: 'string', enum: [' '], default: ' ', description: 'Space delimiter used by the dashboard custom-provider form.' },
  pkce_enabled: { type: 'boolean', default: true, description: 'Use PKCE. Defaults on.' },
  user_info_source: { type: 'string', enum: ['id_token', 'profile_endpoint', 'access_token_jwt'], description: 'Source from which the provider user profile is extracted.' },
  profile_url: text('HTTPS profile URL, required for profile_endpoint.'),
  path_to_name: text('Profile name extraction path.'), path_to_username: text('Username extraction path.'), path_to_email: text('Email extraction path.'), path_to_profile_picture_url: text('Picture extraction path.'),
  return_oauth_tokens: { ...properties.return_oauth_tokens, default: false },
  use_cookie_domain_for_oauth_redirect: { type: 'boolean', enum: [false], default: false, description: 'False, matching the observed dashboard custom-provider creation contract.' },
};
const common = { scope: 'app' as const, keywords: ['authentication', 'OAuth', 'provider', 'credentials', 'social', 'login'], evidence: 'actual Authentication provider/custom-provider forms and loaded OAuth GET/POST/DELETE/PATCH handlers; see management-map' };
const root = '/api/v1/apps/{app_id}/oauth';
export const providerOperations: Operation[] = [
  { ...common, id: 'providers.get', command: 'providers get', method: 'GET', path: root, params: ['provider'], queryFromParams: { provider: 'provider' }, query: { provider }, providerRead: 'one', summary: 'Read builtin OAuth configuration metadata without revealing credentials.', response: 'Editable/configuration metadata only; optional own credentials are distinct from enabling a login method.', examples: ['privy providers get google'] },
  { ...common, id: 'providers.update', command: 'providers update', method: 'POST', path: root, params: ['provider'], bodyFromParams: { provider: 'provider' }, bodyEnvelope: 'config', body: { type: 'object', additionalProperties: false, required: ['provider'], minProperties: 2, properties }, providerWrite: 'update', summary: 'Configure builtin OAuth credentials/options; does not silently enable login.', response: 'Fresh public metadata and masked-secret presence verification. Secret values/external login are not verified. Secret input must arrive through stdin; no automatic retries.', examples: ['privy providers update google --scopes "[]" --diff', 'privy providers update google --body - --yes < /dev/stdin'] },
  { ...common, id: 'providers.delete', command: 'providers delete', method: 'DELETE', path: root, params: ['provider'], bodyFromParams: { provider: 'provider' }, body: { type: 'object', additionalProperties: false, required: ['provider'], properties: { provider } }, providerWrite: 'delete', summary: 'Remove editable own OAuth configuration; shared/default fallback is provider-specific.', response: 'Verified absence of own configuration. Does not disable the app login method or revoke sessions.', examples: ['privy providers delete google --dry-run'] },
  { ...common, id: 'providers.custom.list', command: 'providers custom list', method: 'GET', path: root + '/custom', providerRead: 'list', summary: 'List custom OAuth provider metadata, never credentials.', response: 'Provider metadata array. Not an external sign-in verification.', examples: ['privy providers custom list'] },
  { ...common, id: 'providers.custom.create', command: 'providers custom create', method: 'POST', path: root + '/custom', bodyEnvelope: 'config', body: { type: 'object', additionalProperties: false, required: ['provider', 'provider_display_name', 'provider_icon_url', 'client_id', 'client_secret', 'authorization_url', 'token_url', 'jwks_url', 'user_info_source', 'scopes'], properties: customProperties }, providerWrite: 'create-custom', summary: 'Create an enabled, immutable custom OAuth provider; deletion may become unavailable after signup.', response: 'Fresh public configuration and masked-credential presence verification; creates an enabled provider. Secret values and external login are not verified. No paid feature enablement or account modification.', examples: ['privy providers custom create --body - --yes < /dev/stdin'] },
  ...(['enable', 'delete'] as const).map(action => ({ ...common, id: `providers.custom.${action}`, command: `providers custom ${action}`, method: action === 'enable' ? 'PATCH' as const : 'DELETE' as const, path: root + '/custom', params: ['provider'], bodyFromParams: { provider: 'provider' }, body: { type: 'object' as const, additionalProperties: false as const, required: ['provider', ...(action === 'enable' ? ['enabled'] : [])], properties: { provider: customProperties.provider, ...(action === 'enable' ? { enabled: { type: 'boolean' as const, description: 'Explicit true to enable or false to disable.' } } : {}) } }, providerWrite: action === 'enable' ? 'enable-custom' as const : 'delete-custom' as const, summary: action === 'enable' ? 'Enable or disable an existing custom OAuth provider.' : 'Delete an editable unused custom OAuth provider; refuse when deletion is unavailable.', response: 'Fresh state/absence verification; no authorization bypass.', examples: [`privy providers custom ${action} custom:example ${action === 'enable' ? '--enabled false ' : ''}--dry-run`] })),
];
export const telegramOperations: Operation[] = [false, true].flatMap((client): Operation[] => {
  const stem = client ? 'clients.telegram' : 'providers.telegram', command = stem.replaceAll('.', ' '), path = `/api/v1/apps/{app_id}/${client ? 'app_client/{client_id}/' : ''}telegram/configuration`;
  const shared = { ...common, ...(client ? { params: ['client_id'], clientPreflight: true } : {}) };
  return [
    { ...shared, id: `${stem}.get`, command: `${command} get`, method: 'GET', path, telegram: 'read', summary: 'Read explicit Telegram bot configuration metadata without the bot secret.', response: 'Own configuration only; a client without an override may inherit app-level configuration.', examples: [`privy ${command} get${client ? ' <client-id>' : ''}`] },
    { ...shared, id: `${stem}.update`, command: `${command} update`, method: 'POST', path, telegram: 'update', body: { type: 'object', additionalProperties: false, minProperties: 1, properties: { bot_id: { ...text('Bot token numeric prefix; supply with bot_secret through stdin.'), pattern: '^[0-9]+$', maxLength: 32 }, bot_secret: secret, bot_name: { type: 'string', minLength: 1, maxLength: 100, description: 'Telegram bot username.' }, seamless_auth_enabled: { type: 'boolean', description: 'Enable seamless Telegram authentication for this configuration.' } } }, summary: 'Configure an app Telegram bot or client override; does not silently enable app login.', response: 'Read-back of public bot fields. Bot secret and real Telegram authentication are not verified.', examples: [`privy ${command} update${client ? ' <client-id>' : ''} --body - --yes < /dev/stdin`] },
    { ...shared, id: `${stem}.delete`, command: `${command} delete`, method: 'DELETE', path, telegram: 'delete', ...(!client ? { body: { type: 'object' as const, additionalProperties: false as const, properties: { provider: { type: 'string' as const, enum: ['telegram'], default: 'telegram', description: 'Observed app-level deletion body.' } } } } : {}), summary: client ? 'Remove a Telegram client override; falls back to app settings or disables Telegram for that client.' : 'Remove app Telegram bot configuration; can affect clients inheriting it.', response: 'Own configuration absence with retained app access. No session revocation or login-method toggle.', examples: [`privy ${command} delete${client ? ' <client-id>' : ''} --dry-run`] },
  ];
});
export function validateTelegramBody(op: Operation, body: JsonObject): void {
  if (op.telegram === 'update' && (body.bot_id !== undefined) !== (body.bot_secret !== undefined)) throw new CliError('TELEGRAM_TOKEN_PAIR_REQUIRED', 'Supply bot_id and bot_secret together through stdin. Public-only updates can omit both.', 2);
}
export async function writeTelegram(op: Operation, plan: RequestPlan, request: ProviderRequest): Promise<JsonObject> {
  const before = telegramMetadata(await request(plan.path));
  if (op.telegram === 'delete' && !before.configured) throw new CliError('TELEGRAM_NOT_CONFIGURED', 'No explicit Telegram bot configuration exists here. No delete was sent.', 2);
  if (op.telegram === 'update' && !before.configured && !['bot_id', 'bot_secret', 'bot_name', 'seamless_auth_enabled'].every(key => plan.body?.[key] !== undefined)) throw new CliError('TELEGRAM_CONFIG_REQUIRED', 'Initial Telegram configuration needs bot_id, bot_secret, bot_name and seamless_auth_enabled. No write was sent.', 2);
  const body = op.telegram === 'update' ? { ...(before.configured ? { bot_name: before.config.bot_name, seamless_auth_enabled: before.config.seamless_auth_enabled } : {}), ...plan.body } : plan.body;
  await request(plan.path, op.method, body, true);
  try {
    const after = telegramMetadata(await request(plan.path));
    if (op.telegram === 'delete' ? after.configured : !after.configured || Object.entries(body!).some(([key, value]) => key !== 'bot_secret' && !isDeepStrictEqual(after.config?.[key], value))) throw new Error();
    const secretInput = op.telegram === 'update' && body?.bot_secret !== undefined;
    return { appId: plan.pathParams.app_id, ...(plan.pathParams.client_id ? { clientId: plan.pathParams.client_id, fallbackToAppPossible: !after.configured } : {}), acknowledged: true, verified: !secretInput, metadataVerified: true, ...(secretInput ? { secretValuesVerified: false } : {}), externalLoginVerified: false, ...after };
  } catch { throw new CliError('TELEGRAM_VERIFY_FAILED', 'Telegram write acknowledged but metadata read-back did not match. No automatic retry occurred.'); }
}
export function telegramMetadata(data: any): JsonObject {
  const config = data && Object.hasOwn(data, 'config') ? data.config : data;
  if (config === null || data?.absent === true) return { configured: false, config: null };
  if (!config || typeof config !== 'object' || Array.isArray(config) || ![null, undefined].includes(config.bot_id) && typeof config.bot_id !== 'string' || typeof config.seamless_auth_enabled !== 'boolean') {
    const error = new CliError('INVALID_TELEGRAM_STATE', 'Unexpected Telegram configuration.');
    error.details = { responseType: data === null ? 'null' : typeof data, configType: typeof data?.config, botIdType: typeof config?.bot_id, seamlessType: typeof config?.seamless_auth_enabled };
    throw error;
  }
  return { configured: Boolean(config.bot_id), config: { bot_id: config.bot_id ?? null, bot_name: config.bot_name ?? null, seamless_auth_enabled: config.seamless_auth_enabled } };
}
export function providerValidationFields(data: unknown): string[] {
  // Only schema-owned field names, never response text, supplied values or credentials.
  const text = JSON.stringify(data);
  return ['config', ...Object.keys(customProperties)].filter(key => new RegExp(`(^|[^a-z_])${key}([^a-z_]|$)`, 'i').test(text));
}
export function validateProviderBody(op: Operation, planBody: JsonObject): void {
  if (op.providerWrite === 'update') {
    if ((planBody.client_id !== undefined) !== (planBody.client_secret !== undefined)) throw new CliError('OAUTH_CREDENTIAL_PAIR_REQUIRED', 'Supply client_id and client_secret together through stdin.', 2);
    if (planBody.apple && planBody.provider !== 'apple' || planBody.twitter && planBody.provider !== 'twitter') throw new CliError('INVALID_PROVIDER_OPTIONS', 'Provider-specific options must match the selected provider.', 2);
    if (planBody.provider === 'apple' && planBody.client_secret && !planBody.apple) throw new CliError('APPLE_METADATA_REQUIRED', 'Apple credentials require apple.key_id and apple.team_id.', 2);
  }
  if (op.providerWrite === 'create-custom') {
    for (const key of ['provider_icon_url', 'authorization_url', 'token_url', 'jwks_url', 'profile_url']) if (planBody[key] !== undefined) {
      let url: URL; try { url = new URL(planBody[key]); } catch { throw new CliError('INVALID_PROVIDER_URL', `Expected HTTPS ${key}.`, 2); }
      if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new CliError('INVALID_PROVIDER_URL', `Expected HTTPS ${key} without credentials/fragments.`, 2);
    }
    if (planBody.user_info_source === 'profile_endpoint' && !planBody.profile_url) throw new CliError('PROFILE_URL_REQUIRED', 'profile_endpoint requires profile_url.', 2);
  }
}
export function providerRecord(value: any): JsonObject {
  if (!value || typeof value !== 'object' || typeof value.editable !== 'boolean' || !(value.config === undefined || value.config === null || value.config && typeof value.config === 'object' && !Array.isArray(value.config))) {
    const error = new CliError('INVALID_PROVIDER_STATE', 'Unexpected provider state; no default/fallback state was invented.');
    error.details = { responseType: typeof value, editableType: typeof value?.editable, configType: value?.config === null ? 'null' : typeof value?.config, dataType: Array.isArray(value?.data) ? 'array' : typeof value?.data };
    throw error;
  }
  return { ...value, config: value.config ?? null };
}
export function providerMetadata(value: any): JsonObject {
  const row = providerRecord(value), config = row.config;
  const names = ['provider', 'provider_display_name', 'provider_icon_url', 'client_id', 'authorization_url', 'token_url', 'jwks_url', 'profile_url', 'scopes', 'scopes_delimiter', 'pkce_enabled', 'user_info_source', 'path_to_name', 'path_to_username', 'path_to_email', 'path_to_profile_picture_url', 'return_oauth_tokens', 'use_cookie_domain_for_oauth_redirect'];
  const visible: JsonObject = config ? Object.fromEntries(names.filter(k => Object.hasOwn(config, k)).map(k => [k, config[k]])) : {};
  if (config?.apple && typeof config.apple === 'object') visible.apple = Object.fromEntries(['key_id', 'team_id'].filter(key => typeof config.apple[key] === 'string').map(key => [key, config.apple[key]]));
  if (config?.twitter && typeof config.twitter === 'object') visible.twitter = { ...(typeof config.twitter.oauth_1_enabled === 'boolean' ? { oauth_1_enabled: config.twitter.oauth_1_enabled } : {}), apiKeyPresent: typeof config.twitter.oauth_1_api_key === 'string' && config.twitter.oauth_1_api_key.length > 0, apiSecretPresent: typeof config.twitter.oauth_1_api_secret === 'string' && config.twitter.oauth_1_api_secret.length > 0 };
  return { editable: row.editable, ...(typeof row.enabled === 'boolean' ? { enabled: row.enabled } : {}), configured: config !== null, config: config ? redact(visible) : null, credentialPresent: typeof config?.client_secret === 'string' && config.client_secret.length > 0 };
}
export function providerList(value: any): JsonObject[] {
  if (!value || !Array.isArray(value.data)) throw new CliError('INVALID_PROVIDER_STATE', 'Expected custom-provider data array.');
  return value.data.map(providerRecord);
}
export type ProviderRequest = (path: string, method?: string, body?: JsonObject, acknowledgementOnly?: boolean) => Promise<any>;
export async function readProvider(request: ProviderRequest, appId: string, name: string): Promise<JsonObject> {
  if (name.startsWith('custom:')) {
    const matches = providerList(await request(`/api/v1/apps/${appId}/oauth/custom`)).filter(r => r.config?.provider === name);
    if (matches.length > 1) throw new CliError('INVALID_PROVIDER_STATE', 'Duplicate provider IDs.');
    return matches[0] ?? { editable: true, config: null };
  }
  return providerRecord(await request(`/api/v1/apps/${appId}/oauth?provider=${encodeURIComponent(name)}`));
}
export async function writeProvider(op: Operation, plan: RequestPlan, request: ProviderRequest): Promise<JsonObject> {
  const body = plan.body!, patch = body.config ?? body, name = patch.provider, appId = plan.pathParams.app_id;
  const before = await readProvider(request, appId, name);
  if (op.providerWrite === 'create-custom' && before.config) throw new CliError('PROVIDER_EXISTS', 'Provider already exists. Do not repeat creation.', 2);
  if (op.providerWrite !== 'enable-custom' && before.editable !== true) throw new CliError('PROVIDER_NOT_EDITABLE', 'Dashboard marks this provider non-editable. No write was sent.', 2);
  if (op.providerWrite?.startsWith('delete') && !before.config) return { appId, provider: name, writesPerformed: false, absent: true };
  if (op.providerWrite === 'enable-custom' && !before.config) throw new CliError('PROVIDER_NOT_FOUND', 'Custom provider does not exist.', 2);
  if (op.providerWrite === 'update' && !before.config && !patch.client_secret) throw new CliError('PROVIDER_CREDENTIALS_REQUIRED', 'Creating own configuration requires a credential pair; shared/default login is separate.', 2);
  await request(plan.path, plan.method, body, true);
  try {
    const after = await readProvider(request, appId, name);
    if (op.providerWrite?.startsWith('delete')) { if (after.config !== null) throw new Error(); }
    else if (op.providerWrite === 'enable-custom') { if (after.enabled !== patch.enabled) throw new Error(); }
    else {
      const compare = (actual: any, expected: JsonObject): void => {
        for (const [key, value] of Object.entries(expected)) {
          if (['client_secret', 'oauth_1_api_key', 'oauth_1_api_secret'].includes(key)) { if (typeof actual?.[key] !== 'string' || !actual[key].length) throw new Error(); }
          else if (value && typeof value === 'object' && !Array.isArray(value)) compare(actual?.[key], value);
          else if (!isDeepStrictEqual(actual?.[key], value)) throw new Error();
        }
      };
      compare(after.config, patch);
    }
    const secretInput = patch.client_secret !== undefined || patch.twitter?.oauth_1_api_key !== undefined || patch.twitter?.oauth_1_api_secret !== undefined;
    return { appId, provider: name, acknowledged: true, verified: !secretInput, metadataVerified: true, ...(secretInput ? { secretValuesVerified: false, verificationNote: 'API masks credential material. Only presence and public configuration were read-verified; do not repeat the write to chase an unmasked value.' } : {}), externalLoginVerified: false, ...providerMetadata(after) };
  } catch { throw new CliError('PROVIDER_VERIFY_FAILED', 'Write was acknowledged but provider verification failed. Inspect remote metadata; no write was repeated.'); }
}
