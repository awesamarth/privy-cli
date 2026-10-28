import type { Operation, JsonObject, Field } from './operations.ts';
import { CliError } from './errors.ts';
export function normalizeCookieDomain(value: string): string {
  try {
    const url = new URL(`https://${value}`);
    if (url.username || url.password || url.port || url.pathname !== '/' || url.search || url.hash || url.hostname.length > 253 || !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$/.test(url.hostname) || url.hostname.split('.').some(label => label.length > 63)) throw new Error();
    return url.hostname;
  } catch { throw new CliError('INVALID_COOKIE_DOMAIN', 'Use a public DNS hostname you control, without a URL scheme, port, path or credentials. Privy validates domain eligibility and DNS ownership.', 2); }
}
export function domainState(value: unknown): JsonObject {
  const state = value as JsonObject;
  if (!state || !['unset', 'pending', 'awaiting_refresh', 'verified', 'error'].includes(state.status) || typeof state.enabled !== 'boolean' || typeof state.cookie_same_site_lax !== 'boolean' || !(state.base_cookie_domain === null || typeof state.base_cookie_domain === 'string')) throw new CliError('INVALID_DOMAIN_STATE', 'Cannot establish the current cookie-domain state.');
  if (state.status === 'verified' && (typeof state.base_cookie_domain !== 'string' || !state.base_cookie_domain)) throw new CliError('INVALID_DOMAIN_STATE', 'Verified status is missing its domain identity.');
  return state;
}
const targets = [
  { id: 'domains', command: 'domains', path: '/api/v1/apps/{app_id}/domains', params: [] },
  { id: 'clients.domains', command: 'clients domains', path: '/api/v1/apps/{app_id}/app_client/{client_id}/domains', params: ['client_id'] },
];
const common = { scope: 'app' as const, keywords: ['domain', 'DNS', 'cookies', 'HTTP-only', 'verification'], evidence: 'actual Domains and clients / client HttpOnly UI, loaded module59473; see management-map' };
export const domainOperations: Operation[] = [
  ...targets.flatMap((target): Operation[] => {
    const properties: Record<string, Field> = {
      cookie_domain: { type: 'string', minLength: 3, maxLength: 253, description: 'Owned DNS hostname, not an origin URL. Normalized to lowercase/ASCII. Changing an existing hostname requires explicit deletion first.' },
      enabled: { type: 'boolean', description: target.params.length ? 'Initial client cookie setting. Configure is setup-only: an existing client domain cannot be toggled here. Removal requires explicit delete and session-impact confirmation.' : 'Enable HTTP-only cookies for this domain. Disabling requires --allow-session-impact and may log out app users.' },
    };
    if (!target.params.length) properties.cookie_same_site_lax = { type: 'boolean', description: 'Explicit app-level SameSite=Lax choice; do not confuse this with dashboard authentication.' };
    return [
      { ...common, id: `${target.id}.configure`, command: `${target.command} configure`, path: target.path, params: target.params, method: 'POST', domainWrite: 'configure', body: { type: 'object', additionalProperties: false, required: ['cookie_domain', 'enabled'], properties }, response: 'Configuration read-back and separate domainVerified status. Does not write DNS records or silently add/widen allowed origins. Positive verification requires your DNS ownership; provisioning is not a delivery/login test.', summary: 'Configure an owned HTTP-only cookie domain; DNS setup remains explicit.', examples: [`privy ${target.command} configure ${target.params.length ? '<client-id> ' : ''}--cookie-domain example.com --enabled true --dry-run`] },
      { ...common, id: `${target.id}.verify`, command: `${target.command} verify`, path: target.path, params: target.params, method: 'PATCH', domainWrite: 'verify', response: 'One explicit verification refresh followed by fresh status; no polling loop or automatic retries. Unset domains report no action.', summary: 'Ask Privy to refresh DNS verification once; never fabricate ownership.', examples: [`privy ${target.command} verify ${target.params.length ? '<client-id> ' : ''}--yes`] },
      { ...common, id: `${target.id}.delete`, command: `${target.command} delete`, path: target.path, params: target.params, method: 'DELETE', domainWrite: 'delete', response: 'Unset state verified after deletion. Requires --confirm-domain and --allow-session-impact; app deletion of a domain also affects inheriting clients. External DNS records are not removed.', summary: 'Remove a cookie domain with explicit confirmation of session impact.', examples: [`privy ${target.command} delete ${target.params.length ? '<client-id> ' : ''}--confirm-domain example.com --allow-session-impact --yes`] },
    ];
  }),
  { ...common, id: 'domains.get', command: 'domains get', summary: 'Inspect app HTTP-only cookie domain and DNS status; this is not the allowed-origin list.', method: 'GET', path: '/api/v1/apps/{app_id}/domains', response: 'Domain status and DNS instructions. Reading pending status is not a successful verification claim.', examples: ['privy domains get'] },
  { ...common, id: 'clients.domains.get', command: 'clients domains get', summary: 'Inspect one client’s custom cookie-domain state; app inheritance is configured separately.', method: 'GET', path: '/api/v1/apps/{app_id}/app_client/{client_id}/domains', params: ['client_id'], clientPreflight: true, response: 'Custom domain status after exact same-app client lookup. Use domains get for the inherited app-level domain.', examples: ['privy clients domains get <client-id>'] },
];
