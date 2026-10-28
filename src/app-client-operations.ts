import type { Operation, JsonObject } from './operations.ts';
import { CliError } from './errors.ts';
export function appClientMetadata(value: unknown, appId: string): JsonObject[] {
  if (!Array.isArray(value) || value.some(row => !row || row.app_id !== appId || typeof row.id !== 'string' || typeof row.short_id !== 'string' || !/^[a-z0-9]{8}$/.test(row.short_id)) || !/^[a-z0-9]{25}$/.test(appId)) throw new CliError('INVALID_CLIENTS', 'Client identity metadata is incomplete or belongs to another app.');
  return value.map(row => {
    // Dashboard's public client ID: Bitcoin-base58 of UTF-8 (app ID + 8-character short ID).
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let number = BigInt(`0x${Buffer.from(appId + row.short_id).toString('hex')}`), encoded = '';
    while (number > 0n) { encoded = alphabet[Number(number % 58n)] + encoded; number /= 58n; }
    return { ...row, sdk_client_id: `client-${encoded}` };
  });
}
const common = { scope: 'app' as const, keywords: ['client', 'web', 'mobile', 'origins', 'configuration'], evidence: 'actual Basics Domains and clients create dialog and loaded 8101 hooks; see management-map' };
const root = '/api/v1/apps/{app_id}/app_client';
const array = (description: string) => ({ type: 'array' as const, maxItems: 1000, items: { type: 'string' as const, maxLength: 2048 }, description });
export const appClientOperations: Operation[] = [
  { ...common, id: 'clients.get', command: 'clients get', summary: 'Inspect a frontend app client by exact internal ID.', method: 'GET', path: root, params: ['client_id'], selectFromArray: 'client_id', appClientSummary: true, response: 'Exact same-app client from the dashboard list. Client IDs are public identifiers, not API secrets.', examples: ['privy clients get <client-id>'] },
  { ...common, id: 'clients.create', command: 'clients create', summary: 'Create a separate web/mobile frontend configuration sharing this app’s users and wallets.', method: 'POST', path: root, appClientWrite: 'create', body: { type: 'object', additionalProperties: false, required: ['name', 'client_type', 'use_app_cookie_domain_settings'], properties: {
    name: { type: 'string', minLength: 1, maxLength: 100, pattern: '\\S', description: 'Internal client name.' },
    client_type: { type: 'string', enum: ['web', 'mobile'], description: 'Frontend environment, not dev/production app tier.' },
    use_app_cookie_domain_settings: { type: 'boolean', description: 'Explicitly inherit the configured app cookie domain. Web only; false leaves custom client cookie setup separate.' },
  } }, response: 'Fresh exact-ID list read-back of creation fields. Does not register DNS records, verify a domain, send login codes or create separate user storage.', examples: ['privy clients create --name cli-web --client-type web --use-app-cookie-domain-settings false --dry-run'] },
  { ...common, id: 'clients.update', command: 'clients update', summary: 'Update client origins, identity and app-user session settings; supports read-only diff.', method: 'PATCH', path: `${root}/{client_id}`, params: ['client_id'], appClientWrite: 'update', body: { type: 'object', additionalProperties: false, minProperties: 1, properties: {
    name: { type: 'string', minLength: 1, maxLength: 100, pattern: '\\S', description: 'Internal client name.' },
    display_name: { type: 'string', minLength: 1, maxLength: 50, description: 'User-facing login-message name. Domains/URLs and control characters are not valid names; Privy validates content.' },
    client_type: { type: 'string', enum: ['web', 'mobile'], description: 'Client frontend environment.' },
    allowed_domains: array('Complete allowed-origin array; backend validates wildcard/origin syntax. [] removes restrictions in permitted environments.'),
    allowed_native_app_ids: array('Complete mobile app-identifier array, e.g. io.example.privycli.'),
    allowed_native_app_url_schemes: array('Complete mobile URL-scheme array.'),
    use_app_cookie_domain_settings: { type: 'boolean', description: 'Web-only inheritance of configured app cookie domain. Setting false requires separate client cookie setup.' },
    session_timeout_minutes: { type: 'integer', minimum: 1440, maximum: 576000, description: 'App-user session duration: 1–400 days, in minutes. Does not modify dashboard login.' },
    session_inactivity_window_minutes: { type: 'integer', minimum: 1440, maximum: 576000, description: 'App-user session inactivity duration: 1–400 days, in minutes.' },
    access_token_lifetime_minutes: { type: 'integer', minimum: 10, maximum: 1440, description: 'App-user access-token lifetime: 10 minutes–24 hours. Public configuration, not a token.' },
    id_token_lifetime_minutes: { type: 'integer', minimum: 10, maximum: 1440, description: 'App-user identity-token lifetime: 10 minutes–24 hours. Public configuration, not a token.' },
    apple_oauth_client_id_override: { type: 'string', maxLength: 80, description: 'Apple OAuth client-ID override; provider configuration is separate.' },
  } }, response: 'Fresh exact-ID read-back comparing requested fields. Cookie domains and Telegram credential overrides use separate dashboard endpoints, not this patch.', examples: ['privy clients update <client-id> --name renamed-client --diff', 'privy clients update <client-id> --allowed-domains \'["https://example.invalid"]\' --yes'] },
  { ...common, id: 'clients.delete', command: 'clients delete', summary: 'Delete a frontend client configuration; app users and wallets remain shared and are not deleted.', method: 'DELETE', path: `${root}/{client_id}`, params: ['client_id'], appClientWrite: 'delete', response: 'Absence in a fresh same-app client list. Applications using the public client ID will lose this configuration.', examples: ['privy clients delete <client-id> --yes'] },
];
