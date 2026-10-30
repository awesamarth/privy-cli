import { CliError } from './errors.ts';
import { guideRefs } from './docs.ts';
import { listOutputSchema } from './list-output.ts';
import { validateId } from './store.ts';
import { userOperations } from './user-operations.ts';
import { walletOperations } from './wallet-operations.ts';
import { quorumOperations, validateQuorumBody } from './quorum-operations.ts';
import { organizationOperations } from './organization-operations.ts';
import { approvalOperations } from './approval-operations.ts';
import { webhookOperations, watchlistValues } from './webhook-operations.ts';
import { credentialOperations } from './credential-operations.ts';
import { appClientOperations } from './app-client-operations.ts';
import { domainOperations, normalizeCookieDomain } from './domain-operations.ts';
import { ecosystemOperations, type ConnectionAction } from './ecosystem-operations.ts';
import { availabilityOperations } from './availability-operations.ts';
import { securityOperations, validateSecurity, type SecurityKind } from './security-settings.ts';
import { jwtOperations, validateJwt, type JwtAction } from './jwt-settings.ts';
import { advancedOperations, validateAdvanced } from './advanced-operations.ts';
import { integrationOperations, validateIntegration, type IntegrationKind } from './integration-operations.ts';
import { imageOperations, imageWorkflow } from './image-operations.ts';
import { analyticsOperations, validateAnalytics } from './analytics-operations.ts';
import { accountOperations } from './account-operations.ts';
import { userMetadataOperations, validateUserMetadata } from './user-metadata-operations.ts';
import { accessOperations, validateAccess } from './access-operations.ts';
import { providerOperations, telegramOperations, validateProviderBody, validateTelegramBody } from './provider-operations.ts';
import { appSettingOperations, validateAllowedIps } from './app-setting-operations.ts';

export const ORIGIN = 'https://dashboard.privy.io';
export const DASHBOARD_APP_ID = 'cla04x0d00002nyb6oofp5dqh';
export type JsonObject = Record<string, any>;
export interface Field {
  type: 'string' | 'boolean' | 'integer' | 'array' | 'object';
  nullable?: boolean;
  sensitive?: boolean;
  minItems?: number;
  description: string;
  minLength?: number;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
  pattern?: string;
  default?: string | number | boolean | unknown[];
  enum?: (string | number | boolean)[];
  maxItems?: number;
  items?: { type: 'string' | 'object'; maxLength?: number; pattern?: string; properties?: Record<string, Field>; required?: string[]; additionalProperties?: false };
  properties?: Record<string, Field>;
  required?: string[];
  additionalProperties?: false;
}
export interface BodySchema {
  type: 'object'; properties: Record<string, Field>; required?: string[];
  additionalProperties: false; minProperties?: number;
}
export interface Operation {
  id: string;
  command: string;
  aliases?: string[];
  summary: string;
  keywords: string[];
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  path: string;
  scope: 'app' | 'account' | 'user';
  body?: BodySchema;
  bodyArrayField?: string;
  bodyEnvelope?: string;
  securitySetting?: { kind: SecurityKind; action: 'read' | 'update' | 'rotate' };
  jwtAction?: JwtAction;
  availabilityAction?: 'read' | 'update';
  advancedAction?: 'inspect' | 'merging-read' | 'merging-update' | 'captcha-read' | 'captcha-update';
  ecosystemConnection?: { side: 'providers' | 'requesters'; action: ConnectionAction };
  integration?: { kind: IntegrationKind; action: 'read' | 'update' };
  imageAction?: 'get' | 'upload' | 'status' | 'finalize';
  telegram?: 'read' | 'update' | 'delete';
  providerRead?: 'one' | 'list';
  publicUserMetadata?: boolean;
  publicWallet?: 'get' | 'archive';
  publicOrganizationDelete?: boolean;
  accountBillingRead?: boolean;
  accountJwtFeature?: 'read' | 'update';
  accountView?: 'get' | 'members' | 'invitations';
  accountWrite?: 'role' | 'remove' | 'invite' | 'revoke';
  accessWrite?: { list: 'allowlist' | 'denylist'; action: 'add' | 'delete' | 'clear' };
  providerWrite?: 'update' | 'delete' | 'create-custom' | 'enable-custom' | 'delete-custom';
  download?: 'csv';
  approvalSummary?: boolean;
  appClientSummary?: boolean;
  clientPreflight?: boolean;
  browserHandoff?: boolean;
  confirmUrl?: boolean;
  secretSave?: { kind: string; idParam?: string; idField?: string; responseField: string };
  selectFromArray?: string;
  selectArrayId?: string;
  generatedBody?: 'app-deletion-confirmation' | 'policy-deletion-confirmation' | 'organization-wallet-assignment';
  params?: string[];
  queryFromParams?: Record<string, string>;
  bodyFromParams?: Record<string, string>;
  userWrite?: 'import' | 'bulk-import' | 'update' | 'delete' | 'freeze' | 'restore' | 'revoke' | 'unlink';
  walletWrite?: 'create' | 'update' | 'export';
  quorumWrite?: 'create';
  organizationWrite?: 'create' | 'update';
  credentialWrite?: 'create' | 'delete';
  appClientWrite?: 'create' | 'update' | 'delete';
  domainWrite?: 'configure' | 'verify' | 'delete';
  settingsWrite?: { read: string; unordered?: string[]; embeddedWallet?: boolean; externalIntegration?: boolean };
  selectFields?: string[];
  webhookWrite?: 'create' | 'delete' | 'enable' | 'test' | 'resend' | 'secret' | 'subscriptions' | 'watchlist';
  policyWrite?: 'create' | 'update' | 'delete' | 'create-rule' | 'update-rule' | 'delete-rule';
  query?: Record<string, Field>;
  pagination?: { cursor: 'cursor'; nextCursor: 'next_cursor' | 'cursor'; doneField?: 'done'; items: 'data' | 'transactions'; cursorMode?: 'last-item-id' };
  examples: string[];
  behavior?: 'accounts' | 'apps' | 'create-app' | 'update-app' | 'delete-app' | 'get-user' | 'get-wallet' | 'get-organization' | 'get-quorum' | 'webhook-subscriptions' | 'wallet-export-download' | 'credential-metadata';
  response: string;
  evidence: string;
}
const nameField: Field = { type: 'string', description: 'Application display name.', minLength: 1, maxLength: 100, pattern: '\\S' };
const appPatch: BodySchema = {
  type: 'object', additionalProperties: false, minProperties: 1,
  properties: {
    name: nameField,
    allowed_domains: { type: 'array', items: { type: 'string', maxLength: 2048 }, description: 'Allowed domains. Replaces the complete array; does not append.' },
    email_auth: { type: 'boolean', description: 'Enable email login.' },
    disable_plus_emails: { type: 'boolean', description: 'Reject plus-addressed app-user email identities; does not change dashboard email login.' },
    block_temporary_email_domains: { type: 'boolean', description: 'Block temporary/disposable email domains for app users.' },
    wallet_auth: { type: 'boolean', description: 'Enable external Ethereum-wallet login. Does not request or perform a signature.' },
    solana_wallet_auth: { type: 'boolean', description: 'Enable external Solana-wallet login. Does not request or perform a signature.' },
    external_wallets_for_signup_enabled: { type: 'boolean', description: 'Allow external-wallet signup rather than linking only; does not create users or wallets.' },
    max_linked_wallets_per_user: { type: 'integer', enum: [1, 20], description: 'Dashboard choices: restrict to one external wallet, or allow the default twenty.' },
    show_wallet_login_first: { type: 'boolean', description: 'Prioritize web3 wallet methods instead of email/SMS/social methods in the app login UI.' },
    passkeys_for_signup_enabled: { type: 'boolean', description: 'Allow passkey-only signup; requires passkey_auth. Losing all passkeys without another login method can lose account access.' },
    google_oauth: { type: 'boolean', description: 'Enable Google login; provider configuration may also be required.' },
    github_oauth: { type: 'boolean', description: 'Enable GitHub login; provider configuration may also be required.' },
    discord_oauth: { type: 'boolean', description: 'Enable Discord login; own credentials are optional.' },
    ...Object.fromEntries(['apple', 'twitter', 'linkedin', 'tiktok', 'line', 'twitch', 'spotify', 'instagram', 'telegram'].map(provider => [`${provider}_oauth`, { type: 'boolean' as const, description: `Enable ${provider} OAuth login. ${['spotify', 'instagram', 'telegram'].includes(provider) ? 'Requires own provider configuration.' : 'Own provider credentials are optional; migration rules remain server-enforced.'}` }])),
    telegram_auth: { type: 'boolean', description: 'Enable bot-based Telegram authentication; distinct from telegram_oauth. Requires app bot configuration.' },
    farcaster_auth: { type: 'boolean', description: 'Enable Sign in with Farcaster.' },
    farcaster_link_wallets_enabled: { type: 'boolean', description: 'Link Farcaster connected wallets; requires external Ethereum wallet login.' },
    passkey_auth: { type: 'boolean', description: 'Enable passkey login.' },
    accent_color: { type: 'string', pattern: '^#(?:[0-9a-fA-F]{3}){1,2}$', description: 'Brand color in #RGB or #RRGGBB format.' },
    logo_url: { type: 'string', nullable: true, maxLength: 2083, description: 'HTTP(S) JPEG/JPG/GIF/PNG logo URL, or null to clear. No embedded credentials or SVG. File upload is separate.' },
    terms_and_conditions_url: { type: 'string', nullable: true, maxLength: 2083, description: 'HTTPS terms link, or null to clear.' },
    privacy_policy_url: { type: 'string', nullable: true, maxLength: 2083, description: 'HTTPS privacy-policy link, or null to clear.' },
    require_users_accept_terms: { type: 'boolean', description: 'Require explicit app-user consent during login. Requires at least one configured legal link; does not change dashboard authentication.' },
  },
};

const pageQuery: Record<string, Field> = {
  limit: { type: 'integer', minimum: 1, maximum: 100, default: 20, description: 'Items per API page (1–100; default 20).' },
  cursor: { type: 'string', minLength: 1, maxLength: 4096, description: 'Opaque next_cursor from a previous response.' },
  query: { type: 'string', maxLength: 1024, description: 'Search term as supported by this dashboard resource.' },
};
const filter = (description: string): Field => ({ type: 'string', minLength: 1, maxLength: 1024, description });
const pagination = { cursor: 'cursor', nextCursor: 'next_cursor', items: 'data' } as const;
const policyPath = '/api/v1/apps/{app_id}/policies';
const policyName: Field = { ...nameField, maxLength: 50, description: 'Policy or rule display name (1–50 characters).' };
const ruleProperties: Record<string, Field> = {
  name: policyName,
  method: { type: 'string', minLength: 1, maxLength: 100, pattern: '^(\\*|[a-zA-Z0-9_]+)$', description: 'Policy method, e.g. eth_sendTransaction, or * for all methods. Privy validates compatibility with the policy chain.' },
  action: { type: 'string', enum: ['ALLOW', 'DENY'], description: 'Action when the conditions match: ALLOW or DENY.' },
  conditions: { type: 'array', items: { type: 'object' }, maxItems: 100, description: 'Complete condition array as JSON (replaces existing conditions). Uses the Privy policy language; nested condition semantics are validated by Privy, not fully modeled locally.' },
};

// Single source of truth for request paths, body validation, help, search and previews.
// Add endpoints only after observing their actual request/response contract.
export const operations: Operation[] = [
  ...userOperations,
  ...walletOperations,
  ...quorumOperations,
  ...organizationOperations,
  ...approvalOperations,
  ...webhookOperations,
  ...credentialOperations,
  ...appClientOperations,
  ...domainOperations,
  ...appSettingOperations,
  ...integrationOperations,
  ...availabilityOperations,
  ...advancedOperations,
  ...securityOperations,
  ...jwtOperations,
  ...ecosystemOperations,
  ...providerOperations,
  ...telegramOperations,
  ...accessOperations,
  ...userMetadataOperations,
  ...accountOperations,
  ...analyticsOperations,
  ...imageOperations,
  { id: 'accounts.list', command: 'accounts list', summary: 'List accessible dashboard accounts.', keywords: ['organization', 'team'], method: 'GET', path: '/api/v1/teams', scope: 'user', behavior: 'accounts', response: 'Array of account IDs and names; membership details are omitted.', evidence: 'live-read', examples: ['privy accounts list'] },
  { id: 'apps.list', command: 'apps list', summary: 'List applications across accessible accounts, excluding locally protected apps.', keywords: ['project', 'find', 'application'], method: 'GET', path: '/api/v1/teams', scope: 'user', behavior: 'apps', response: 'Array of app summaries with account context. No individual app requests.', evidence: 'live-read', examples: ['privy apps list'] },
  { id: 'apps.get', command: 'apps get', summary: 'Inspect an application configuration.', keywords: ['application', 'show', 'settings'], method: 'GET', path: '/api/dashboard/apps/{app_id}', scope: 'app', response: 'App configuration object; sensitive fields are redacted by the CLI.', evidence: 'live-read', examples: ['privy apps get --app <app-id>'] },
  { id: 'config.get', command: 'apps config get', aliases: ['config get'], summary: 'Read application configuration, optionally one field.', keywords: ['settings', 'domains', 'login', 'providers'], method: 'GET', path: '/api/dashboard/apps/{app_id}', scope: 'app', response: 'App configuration object; --field selects one top-level field.', evidence: 'live-read', examples: ['privy apps config get --field allowed_domains'] },
  { id: 'apps.create', command: 'apps create', summary: 'Create a new application in an account.', keywords: ['new', 'project', 'application'], method: 'POST', path: '/api/v1/teams/{account_id}/create_app', scope: 'account', body: { type: 'object', additionalProperties: false, required: ['name'], properties: { name: nameField } }, behavior: 'create-app', response: 'Read-back verified app ID, name and environment plus explicit app-secret storage results. Choose env, keychain, both or none before creation; raw values never printed.', evidence: 'observed-dashboard-write; CLI lifecycle validation', examples: ['privy apps create --account <account-id> --name demo --secret-store env --env-output .env.local --dry-run', 'privy apps create --account <account-id> --name demo --secret-store env --env-output .env.local --yes'] },
  { id: 'apps.delete', command: 'apps delete', summary: 'Permanently delete a development app and its users; requires explicit app ID and exact name confirmation.', keywords: ['remove', 'destroy', 'cleanup', 'application'], method: 'DELETE', path: '/api/v1/apps/{app_id}', scope: 'app', behavior: 'delete-app', generatedBody: 'app-deletion-confirmation', body: { type: 'object', additionalProperties: false, required: ['confirmation'], properties: { confirmation: { type: 'string', description: 'Generated from the explicit app ID using the exact dashboard deletion confirmation phrase.' } } }, response: 'Deleted app ID and verified absence. Production deletion is not supported. Local profile selection is cleared when it matches; project bindings are not rewritten.', evidence: 'observed-dashboard-confirmation-and-loaded-code; disposable development app deleted live', examples: ['privy --app <app-id> apps delete --dry-run', 'privy --app <app-id> apps delete --confirm-name disposable-app --yes'] },
  { id: 'config.update', command: 'apps config update', aliases: ['config update'], summary: 'Update application configuration and verify changed fields by reading them back.', keywords: ['change', 'edit', 'settings', 'domains', 'login', 'providers', 'google login', 'google auth', 'apple login', 'github login', 'discord login', 'enable google', 'rename', 'branding', 'logo', 'color', 'terms', 'privacy', 'consent', 'email', 'external wallets', 'signup', 'passkeys'], method: 'POST', path: '/api/v1/apps/{app_id}', scope: 'app', body: appPatch, behavior: 'update-app', response: 'App ID, verified flag and changed field values. No entire-object replacement.', evidence: 'dashboard settings/branding UI and loaded handlers; per-field live evidence recorded in management-map', examples: ['privy apps config update --name demo --dry-run', 'privy apps config update --file patch.json --diff', 'privy apps config update --body - --yes < patch.json'] },
  { id: 'users.count', command: 'users count', summary: 'Read application user counts and limits.', keywords: ['usage', 'number', 'users'], method: 'GET', path: '/api/v1/apps/{app_id}/users/count', scope: 'app', response: 'User count and user limit.', evidence: 'live-read', examples: ['privy users count'] },
  { id: 'users.list', command: 'users list', summary: 'List or search user summaries; --full retains complete user records. Cursor-paginated.', keywords: ['find', 'search', 'email', 'user'], method: 'GET', path: '/api/v1/apps/{app_id}/users', scope: 'app', query: { ...pageQuery, account_type: filter('Filter by linked account type supported by the dashboard.') }, pagination, response: 'Summary data by default; --full retains existing full user rows. Pagination is unchanged: next_cursor, has_more, pages_read and pagination diagnostics (requested_limit, page_counts, returned_page_counts, end_reason). has_more means continuation availability, not guaranteed extra rows. --all is bounded by --max-pages.', evidence: 'live-read:empty-page; filter contract observed in dashboard', examples: ['privy users list --limit 20', 'privy users list --query user@example.com', 'privy users list --all --max-pages 5', 'privy users list --all --full --max-pages 5'] },
  { id: 'wallets.list', command: 'wallets list', summary: 'List or search wallet summaries; --full or --include-balance true retains complete rows.', keywords: ['find', 'search', 'embedded', 'wallet', 'balance'], method: 'GET', path: '/api/v1/apps/{app_id}/wallets/search', scope: 'app', query: { ...pageQuery, chain_type: filter('Chain type, for example ethereum or solana.'), policy_id: filter('Filter by policy ID.'), key_quorum_id: filter('Filter by key quorum ID.'), tag: filter('Filter by wallet tag.'), include_balance: { type: 'boolean', description: 'Include wallet balances (true or false).' } }, pagination: { ...pagination, cursorMode: 'last-item-id' }, response: 'Summary data by default; --full or --include-balance true retains existing full wallet rows. next_cursor, has_more, pages_read and pagination diagnostics are unchanged. No signing or private-key export.', evidence: 'live-read:empty-page; filter contract observed in dashboard', examples: ['privy wallets list --limit 20', 'privy wallets list --chain-type ethereum --include-balance true'] },
  { id: 'policies.list', command: 'policies list', summary: 'List or search authorization policies.', keywords: ['policy', 'rules', 'spending', 'permissions'], method: 'GET', path: '/api/v1/apps/{app_id}/policies', scope: 'app', query: { ...pageQuery, chain_type: filter('Filter by chain type.'), owner_key_quorum_id: filter('Filter by owning key quorum ID.') }, pagination, response: 'data, next_cursor, has_more and pages_read.', evidence: 'live-read:nonempty; name/chain filtering, continuation and page cap verified on disposable app', examples: ['privy policies list', 'privy policies list --query spending --all'] },
  { id: 'policies.get', command: 'policies get', summary: 'Read one policy, including its rules and owner.', keywords: ['show', 'inspect', 'rules'], method: 'GET', path: `${policyPath}/{policy_id}`, params: ['policy_id'], scope: 'app', response: 'Policy object including ordered rules, version, chain type and owner_id.', evidence: 'dashboard UI and loaded hooks; live read', examples: ['privy policies get <policy-id>'] },
  { id: 'policies.create', command: 'policies create', summary: 'Create a policy with optional initial rules and owner; empty rules default to deny. Does not attach wallets.', keywords: ['new', 'authorization', 'rules', 'owner'], method: 'POST', path: policyPath, scope: 'app', policyWrite: 'create', body: { type: 'object', additionalProperties: false, required: ['name', 'chain_type'], properties: { name: policyName, chain_type: { type: 'string', enum: ['ethereum', 'solana', 'tron', 'sui', 'xrpl'], description: 'Policy chain type. ethereum also covers Tempo/EVM networks.' }, owner_id: { type: 'string', pattern: '^[a-zA-Z0-9_-]{1,128}$', description: 'Optional owning key quorum in this app; requires --confirm-owner. All subsequent changes require owner authorization.' }, version: { type: 'string', enum: ['1.0'], default: '1.0', description: 'Policy language version (default 1.0).' }, rules: { type: 'array', items: { type: 'object' }, maxItems: 100, default: [], description: 'Initial rules: each has name, method, action (ALLOW/DENY) and conditions. Same schema as policies rules create. Empty defaults to deny.' } } }, response: 'Created policy with verified owner and ordered rules. No signatures or wallet attachment.', evidence: 'actual dashboard owner selector and chain options, loaded create/rule editor hooks; manual evidence in management-map', examples: ['privy policies create --name payout-guard --chain-type ethereum --dry-run', 'privy policies create --file policy.json --confirm-owner <quorum-id> --yes'] },
  { id: 'policies.update', command: 'policies update', summary: 'Rename an unowned policy and verify the change.', keywords: ['rename', 'edit'], method: 'PATCH', path: `${policyPath}/{policy_id}`, params: ['policy_id'], scope: 'app', policyWrite: 'update', body: { type: 'object', additionalProperties: false, required: ['name'], properties: { name: policyName } }, response: 'Read-back verified policy. Owner-managed policies require a separate approval flow and are rejected.', evidence: 'dashboard details and loaded PATCH hook; CLI rename/read-back live-verified', examples: ['privy policies update <policy-id> --name payout-guard --diff', 'privy policies update <policy-id> --name payout-guard --yes'] },
  { id: 'policies.delete', command: 'policies delete', summary: 'Delete an unused, unowned policy; requires exact current name confirmation.', keywords: ['remove', 'cleanup'], method: 'DELETE', path: `${policyPath}/{policy_id}`, params: ['policy_id'], scope: 'app', policyWrite: 'delete', generatedBody: 'policy-deletion-confirmation', body: { type: 'object', additionalProperties: false, required: ['name'], properties: { name: policyName } }, response: 'Verified policy absence after checking owner, exact name and dashboard deletability.', evidence: 'dashboard exact-name dialog and loaded DELETE hook; CLI deletion/404 plus retained app access live-verified', examples: ['privy policies delete <policy-id> --confirm-name payout-guard --dry-run', 'privy policies delete <policy-id> --confirm-name payout-guard --yes'] },
  { id: 'policies.rules.get', command: 'policies rules get', summary: 'Inspect one rule within a policy.', keywords: ['show', 'condition'], method: 'GET', path: `${policyPath}/{policy_id}/rules/{rule_id}`, params: ['policy_id', 'rule_id'], scope: 'app', response: 'Rule name, method, conditions and action.', evidence: 'dashboard rule editor and loaded GET hook; CLI rule read live-verified', examples: ['privy policies rules get <policy-id> <rule-id>'] },
  { id: 'policies.rules.create', command: 'policies rules create', summary: 'Add a rule to an unowned policy and verify it by reading the policy.', keywords: ['allow', 'deny', 'condition'], method: 'POST', path: `${policyPath}/{policy_id}/rules`, params: ['policy_id'], scope: 'app', policyWrite: 'create-rule', body: { type: 'object', additionalProperties: false, required: ['name', 'method', 'action', 'conditions'], properties: ruleProperties }, response: 'Created rule and read-back verification. An attached policy can affect existing wallets; this command does not execute wallet actions.', evidence: 'dashboard rule editor and live conditional DENY-rule creation/read-back', examples: ['privy policies rules create <policy-id> --file rule.json --dry-run', 'privy policies rules create <policy-id> --file rule.json --yes'] },
  { id: 'policies.rules.update', command: 'policies rules update', summary: 'Replace a rule definition in an unowned policy; all four fields are required.', keywords: ['edit', 'allow', 'deny', 'condition'], method: 'PATCH', path: `${policyPath}/{policy_id}/rules/{rule_id}`, params: ['policy_id', 'rule_id'], scope: 'app', policyWrite: 'update-rule', body: { type: 'object', additionalProperties: false, required: ['name', 'method', 'action', 'conditions'], properties: ruleProperties }, response: 'Read-back verified rule. No owner signing or approval bypass.', evidence: 'dashboard rule editor and loaded PATCH hook; full-body CLI update/read-back live-verified, partial-body request rejected with 400', examples: ['privy policies rules update <policy-id> <rule-id> --file rule.json --diff', 'privy policies rules update <policy-id> <rule-id> --file rule.json --yes'] },
  { id: 'policies.rules.delete', command: 'policies rules delete', summary: 'Remove a rule from an unowned policy and verify its absence.', keywords: ['remove', 'condition'], method: 'DELETE', path: `${policyPath}/{policy_id}/rules/{rule_id}`, params: ['policy_id', 'rule_id'], scope: 'app', policyWrite: 'delete-rule', response: 'Rule absence verified in a fresh parent-policy read. This can change permissions on attached wallets.', evidence: 'dashboard rule deletion confirmation and loaded DELETE hook; CLI deletion/parent read-back live-verified', examples: ['privy policies rules delete <policy-id> <rule-id> --dry-run', 'privy policies rules delete <policy-id> <rule-id> --yes'] },
  { id: 'clients.list', command: 'clients list', summary: 'List application clients and their public SDK IDs.', appClientSummary: true, keywords: ['client', 'application'], method: 'GET', path: '/api/v1/apps/{app_id}/app_client', scope: 'app', response: 'App-client array; sensitive fields redacted.', evidence: 'live-read', examples: ['privy clients list'] },
  { id: 'key-quorums.list', command: 'key-quorums list', aliases: ['keys list'], summary: 'List authorization key quorums, not private keys.', keywords: ['keys', 'signers', 'authorization'], method: 'GET', path: '/api/v1/apps/{app_id}/key_quorums', scope: 'app', query: { ...pageQuery, member_id: filter('Dashboard member_id filter; nested quorum IDs did not match in the observed backend response.') }, pagination: { ...pagination, cursorMode: 'last-item-id' }, response: 'data, next_cursor, has_more and pages_read. No private-key export.', evidence: 'live-read:empty-page; filter contract observed in dashboard', examples: ['privy key-quorums list'] },
  { id: 'analytics.wallets', command: 'analytics wallets', summary: 'Read wallet-count and asset-balance summary for an app.', keywords: ['balance', 'assets', 'wallets', 'usage'], method: 'GET', path: '/api/v1/apps/{app_id}/analytics/wallet-summary', scope: 'app', response: 'Wallet summary metrics and freshness metadata.', evidence: 'live-read', examples: ['privy analytics wallets'] },
];

export function operation(idOrCommand: string): Operation {
  const found = operations.find(o => o.id === idOrCommand || o.command === idOrCommand || o.aliases?.includes(idOrCommand));
  if (!found) throw new CliError('UNKNOWN_OPERATION', 'Unknown operation. Use cli search to find a command.', 2);
  return found;
}
export function validateUserId(value: string): string {
  const id = value.startsWith('did:privy:') ? value.slice('did:privy:'.length) : value;
  return 'did:privy:' + validateId(id);
}
function validateValue(key: string, value: unknown, field: Field): void {
  if (value === null && field.nullable) return;
  let valid = field.type === 'object' ? value !== null && typeof value === 'object' && !Array.isArray(value)
    : field.type === 'array' ? Array.isArray(value) && value.length >= (field.minItems ?? 0) && value.length <= (field.maxItems ?? Infinity) && value.every(v => field.items?.type === 'object' ? v !== null && typeof v === 'object' && !Array.isArray(v) : typeof v === 'string' && v.length <= (field.items?.maxLength ?? Infinity) && (!field.items?.pattern || new RegExp(field.items.pattern).test(v)))
    : field.type === 'integer' ? Number.isInteger(value) && Number(value) >= (field.minimum ?? -Infinity) && Number(value) <= (field.maximum ?? Infinity)
    : field.type === 'boolean' ? typeof value === 'boolean'
    : typeof value === 'string' && value.length >= (field.minLength ?? 0) && value.length <= (field.maxLength ?? Infinity) && (!field.pattern || new RegExp(field.pattern).test(value));
  if (field.enum && !field.enum.includes(value as string)) valid = false;
  if (!valid) {
    const error = new CliError('INVALID_INPUT', `Invalid ${key}: expected ${field.type} satisfying the field constraints. Inspect the operation with schema.`, 2);
    error.details = { field: key, expected: field };
    throw error;
  }
}
export function validateBody(schema: BodySchema, input: unknown): JsonObject {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new CliError('INVALID_PATCH', 'Body must be a JSON object.', 2);
  const defaults = Object.fromEntries(Object.entries(schema.properties).filter(([, f]) => f.default !== undefined).map(([key, f]) => [key, f.default]));
  const body = { ...defaults, ...input as JsonObject };
  if (Object.keys(body).length < (schema.minProperties ?? 0)) throw new CliError('INVALID_PATCH', 'Body must not be empty.', 2);
  for (const key of schema.required ?? []) if (!Object.hasOwn(body, key)) throw new CliError('MISSING_FIELD', `Missing required field: ${key}.`, 2);
  for (const [key, value] of Object.entries(body)) {
    if (!Object.hasOwn(schema.properties, key)) throw new CliError('UNKNOWN_FIELD', 'Unsupported body field. Unrecognized names are omitted because they can contain credentials; inspect schema and compare the supplied keys.', 2);
    const field = schema.properties[key];
    validateValue(key, value, field);
    if (value !== null && field.type === 'object' && field.properties) body[key] = validateBody({ type: 'object', properties: field.properties, required: field.required, additionalProperties: false }, value);
    if (Array.isArray(value) && field.items?.type === 'object' && field.items.properties) body[key] = value.map(item => validateBody({ type: 'object', properties: field.items!.properties!, required: field.items!.required, additionalProperties: false }, item));
  }
  return body;
}
export function parsePatch(input: unknown): JsonObject { return validateBody(appPatch, input); }
export interface OperationInput { appId?: string; accountId?: string; params?: Record<string, string>; confirmName?: string; body?: unknown; query?: JsonObject; }
export interface RequestPlan {
  operationId: string; command: string; method: string; url: string; path: string;
  pathParams: Record<string, string>; query: JsonObject; body?: JsonObject;
  auth: 'dashboard-session' | 'app-credential+dashboard-preflight'; mutation: boolean;
  runtimePreserves?: string[];
}
export function planRequest(op: Operation, input: OperationInput): RequestPlan {
  const pathParams: Record<string, string> = {};
  if (op.scope === 'app') {
    if (input.appId === undefined) throw new CliError('APP_REQUIRED', 'Pass --app <id> or select an app with apps use.', 2);
    pathParams.app_id = validateId(input.appId);
  }
  if (op.scope === 'account') {
    if (input.accountId === undefined) throw new CliError('ACCOUNT_REQUIRED', 'Pass --account <id>. Find IDs with accounts list.', 2);
    pathParams.account_id = validateId(input.accountId);
  }
  for (const key of Object.keys(input.params ?? {})) if (!op.params?.includes(key)) throw new CliError('UNKNOWN_PARAMETER', 'Unsupported path parameter. Inspect the operation with schema; unrecognized names are omitted.', 2);
  for (const key of op.params ?? []) {
    if (!input.params?.[key]) throw new CliError('MISSING_PARAMETER', `Missing path parameter: ${key}.`, 2);
    pathParams[key] = key === 'user_id' ? validateUserId(input.params[key]) : key === 'provider' && /^custom:[a-z0-9]+(?:-[a-z0-9]+)*$/.test(input.params[key]) && input.params[key].length <= 128 ? input.params[key] : validateId(input.params[key]);
  }
  const defaults = Object.fromEntries(Object.entries(op.query ?? {}).filter(([, f]) => f.default !== undefined).map(([key, f]) => [key, f.default]));
  const query = { ...defaults, ...input.query };
  for (const [key, param] of Object.entries(op.queryFromParams ?? {})) {
    if (Object.hasOwn(input.query ?? {}, key)) throw new CliError('DUPLICATE_FIELD', `Query ${key} is generated from ${param}.`, 2);
    query[key] = pathParams[param];
  }
  for (const [key, value] of Object.entries(query)) {
    if (!op.query || !Object.hasOwn(op.query, key)) throw new CliError('UNKNOWN_QUERY', 'Unsupported query field. Inspect the operation with schema; unrecognized names are omitted.', 2);
    validateValue(key, value, op.query[key]);
  }
  validateAnalytics(op, query);
  if (op.id === 'webhooks.history.list' && query.endpointId !== undefined && query.msgId !== undefined) throw new CliError('CONFLICTING_FILTERS', 'Webhook history accepts endpointId or msgId, not both. Message history includes destination URLs for local inspection.', 2);
  if (op.generatedBody && input.body !== undefined) throw new CliError('UNEXPECTED_BODY', 'This request body is generated by the CLI and cannot be overridden.', 2);
  if (op.generatedBody === 'policy-deletion-confirmation' && !input.confirmName) throw new CliError('NAME_CONFIRMATION_REQUIRED', 'Policy deletion requires --confirm-name, including for an offline preview.', 2);
  let bodyInput = op.generatedBody === 'app-deletion-confirmation'
    ? { confirmation: `I am certain I want to delete this app ${pathParams.app_id} and all its users. I understand that this action is not reversible.` }
    : op.generatedBody === 'policy-deletion-confirmation' ? (input.confirmName === undefined ? {} : { name: input.confirmName })
    : op.generatedBody === 'organization-wallet-assignment' ? { entity: { type: 'organization', id: pathParams.organization_id } } : input.body;
  if (op.bodyFromParams) {
    if (bodyInput !== undefined && (!bodyInput || typeof bodyInput !== 'object' || Array.isArray(bodyInput))) throw new CliError('INVALID_PATCH', 'Body must be a JSON object.', 2);
    const generated = { ...(bodyInput as JsonObject ?? {}) };
    for (const [key, param] of Object.entries(op.bodyFromParams)) {
      if (Object.hasOwn(generated, key)) throw new CliError('DUPLICATE_FIELD', `Body ${key} is generated from the positional ID and cannot be overridden.`, 2);
      generated[key] = pathParams[param];
    }
    bodyInput = generated;
  }
  const body = op.body ? validateBody(op.body, bodyInput) : undefined;
  if (op.publicUserMetadata && body) validateUserMetadata(body.custom_metadata);
  if (body) validateAccess(op, body);
  if (op.integration?.action === 'update' && body) validateIntegration(op, body);
  if (body) { validateAdvanced(op, body); validateSecurity(op, body); validateJwt(op, body); }
  if (op.providerWrite && body) validateProviderBody(op, body);
  if (op.telegram && body) validateTelegramBody(op, body);
  if (op.userWrite === 'import' || op.userWrite === 'bulk-import') {
    for (const user of body!.users) if (!Array.isArray(user.linked_accounts) || !user.linked_accounts.length || !user.linked_accounts.every((a: unknown) => a && typeof a === 'object' && !Array.isArray(a))) throw new CliError('INVALID_INPUT', 'Each imported user needs a nonempty linked_accounts object array.', 2);
  }
  if (op.webhookWrite === 'create' && body) {
    let url: URL;
    try { url = new URL(body.url); } catch { throw new CliError('INVALID_WEBHOOK_URL', 'Expected an authorized HTTPS URL.', 2); }
    if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new CliError('INVALID_WEBHOOK_URL', 'Webhook URLs must use HTTPS without userinfo or fragments.', 2);
  }
  if (op.behavior === 'update-app' && body) {
    for (const field of ['logo_url', 'terms_and_conditions_url', 'privacy_policy_url']) {
      const value = body[field]; if (value === undefined || value === null) continue;
      let url: URL; try { url = new URL(value); } catch { throw new CliError('INVALID_CONFIG_URL', `Invalid URL for ${field}.`, 2); }
      if (url.username || url.password || (field === 'logo_url' ? !['http:', 'https:'].includes(url.protocol) || !/\.(jpeg|jpg|gif|png)$/.test(url.pathname) : url.protocol !== 'https:')) throw new CliError('INVALID_CONFIG_URL', `Unsupported URL for ${field}. Inspect schema; embedded credentials are forbidden.`, 2);
    }
  }
  if (op.settingsWrite?.embeddedWallet && body) {
    const config = body.embedded_wallet_config, mode = config.create_on_login;
    const chains = [config.ethereum.create_on_login, config.solana.create_on_login];
    if (chains.some(value => value !== 'off' && value !== mode) || mode !== 'off' && chains.every(value => value === 'off')) throw new CliError('INVALID_WALLET_AUTOCREATE', 'Enabled chains must use the selected global mode. Enable at least one chain when creation is on; use off for all three to disable.', 2);
  }
  if (op.id === 'config.ip-allowlist.update' && body) validateAllowedIps(body.allowed_ips);
  if (op.domainWrite === 'configure' && body) body.cookie_domain = normalizeCookieDomain(body.cookie_domain);
  if (op.appClientWrite === 'create' && body?.client_type === 'mobile' && body.use_app_cookie_domain_settings) throw new CliError('INVALID_CLIENT_COOKIES', 'Mobile clients cannot inherit a web cookie domain.', 2);
  if (op.webhookWrite === 'watchlist' && body) watchlistValues(body.assets);
  if (op.webhookWrite === 'subscriptions' && body && new Set(body.subscriptions).size !== body.subscriptions.length) throw new CliError('DUPLICATE_SUBSCRIPTION', 'Subscription names must be unique.', 2);
  if (op.policyWrite === 'create' && body) for (const rule of body.rules) validateBody({ type: 'object', additionalProperties: false, required: ['name', 'method', 'action', 'conditions'], properties: ruleProperties }, rule);
  if (op.organizationWrite && body) {
    for (const id of body.wallet_ids ?? []) validateId(id);
    if (new Set(body.wallet_ids ?? []).size !== (body.wallet_ids ?? []).length) throw new CliError('DUPLICATE_WALLET', 'Wallet IDs must be unique.', 2);
  }
  if (op.quorumWrite && body) validateQuorumBody(body);
  if (op.walletWrite && body) {
    for (const id of body.policy_ids ?? []) validateId(id);
    if (body.entity !== undefined) {
      if (body.entity.type !== 'organization' || Object.keys(body.entity).some(k => !['type', 'id'].includes(k))) throw new CliError('INVALID_INPUT', 'entity must be {type:"organization",id:"..."}.', 2);
      validateId(body.entity.id);
    }
    for (const signer of body.additional_signers ?? []) {
      if (Object.keys(signer).some(k => !['signer_id', 'override_policy_ids'].includes(k)) || !Array.isArray(signer.override_policy_ids) || signer.override_policy_ids.length > 1) throw new CliError('INVALID_INPUT', 'Each additional signer requires signer_id and override_policy_ids (zero or one policy).', 2);
      validateId(signer.signer_id); signer.override_policy_ids.forEach(validateId);
    }
  }
  if (!op.body && input.body !== undefined) throw new CliError('UNEXPECTED_BODY', 'This operation does not accept a request body.', 2);
  const pathname = op.path.replace(/\{([^}]+)\}/g, (_, key) => {
    if (!Object.hasOwn(pathParams, key)) throw new CliError('MISSING_PARAMETER', `Missing path parameter: ${key}.`, 2);
    return encodeURIComponent(pathParams[key]);
  });
  const search = new URLSearchParams(Object.entries(query).map(([k, v]) => [k, String(v)])).toString();
  const path = pathname + (search ? '?' + search : '');
  return { operationId: op.id, command: `privy ${op.command}`, method: op.method, url: (op.publicUserMetadata || op.publicWallet || op.publicOrganizationDelete ? 'https://api.privy.io' : ORIGIN) + path, path, pathParams, query, ...(body ? { body: op.bodyEnvelope ? { [op.bodyEnvelope]: body } : op.bodyArrayField ? body[op.bodyArrayField] : body } : {}), auth: op.publicUserMetadata || op.publicWallet || op.publicOrganizationDelete ? 'app-credential+dashboard-preflight' : 'dashboard-session', mutation: op.method !== 'GET', ...(op.settingsWrite?.embeddedWallet ? { runtimePreserves: ['embedded_wallet_config.user_owned_recovery_options', 'embedded_wallet_config.require_user_owned_recovery_on_create'] } : op.telegram === 'update' ? { runtimePreserves: ['bot_name', 'seamless_auth_enabled'] } : {}) };
}
export function operationSchema(op: Operation) {
  return {
    operationId: op.id, command: `privy ${op.command}`, summary: op.summary,
    httpMethod: op.method, origin: op.publicUserMetadata || op.publicWallet || op.publicOrganizationDelete ? 'https://api.privy.io' : ORIGIN, path: op.path, scope: op.scope,
    auth: op.publicUserMetadata || op.publicWallet || op.publicOrganizationDelete ? 'app-credential+dashboard-preflight' : 'dashboard-session', mutation: op.method !== 'GET',
    pathParams: [...op.path.matchAll(/\{([^}]+)\}/g)].map(m => ({ name: m[1], type: 'string', required: true })),
    queryParams: op.query ?? {}, requestBody: op.bodyEnvelope ? { type: 'object', additionalProperties: false, required: [op.bodyEnvelope], properties: { [op.bodyEnvelope]: op.body } } : op.bodyArrayField ? op.body!.properties[op.bodyArrayField] : op.body ?? null, ...(op.bodyEnvelope ? { cliBody: op.body, bodyEnvelope: op.bodyEnvelope } : {}), ...(op.bodyArrayField ? { cliBody: op.body, bodyArrayField: op.bodyArrayField } : {}), generatedBody: op.generatedBody,
    arguments: [...(op.params ?? []), ...(op.imageAction === 'upload' ? ['image_file'] : [])], queryFromParams: op.queryFromParams, bodyFromParams: op.bodyFromParams,
    pagination: op.pagination ? { ...op.pagination, defaultMaxPages: 10, maxPageCap: 100, allIsExplicit: true, pageSize: 'The current command uses its explicit limit or schema default; --all never inherits another invocation’s limit.', resultMetadata: { requested_limit: 'Page size requested by this invocation', page_counts: 'Rows retained from each fetched page', returned_page_counts: 'Rows returned by the API before any endpoint-specific lookahead slicing', end_reason: ['single_page', 'max_pages_reached', 'cursor_exhausted'], has_more: 'Backward-compatible continuation availability, not a guarantee of another nonempty page' }, termination: 'Follow documented continuation semantics; do not infer completion from a short page. Repeated cursors are refused.' } : undefined,
    response: op.response, evidence: op.evidence, examples: op.examples, guides: guideRefs(op.command),
    ...(listOutputSchema(op.id) ? { output: listOutputSchema(op.id) } : {}),
    ...(op.browserHandoff ? { browserHandoff: 'Normal browser review; --no-open prints the URL. No signing or automatic approval.' } : {}),
    ...(op.behavior === 'create-app' || op.credentialWrite === 'create' ? {
      sensitiveResponse: 'App API secret saved only to explicitly chosen destinations, or deliberately discarded with none; never printed.',
      localStorage: { requiredChoice: '--secret-store', choices: ['env', 'keychain', 'both', 'none'], interactive: 'Prompt before creation only in an interactive terminal with --yes; no default destination. Non-interactive execution and dry-run require the flag.', envOptions: { file: '--env-output', variable: '--env-key (default PRIVY_APP_SECRET)', overwrite: '--overwrite-env' }, preflight: 'Execution checks owned regular files, no symlinks/hardlinks, bounded dotenv syntax and untracked/ignored status inside Git. Existing variable replacement needs explicit consent.', filePermissions: '0600; preserve unrelated assignments; cooperative destination lock and atomic installation', partialFailure: 'Inspect returned resource/reference and per-destination status; no automatic retry or rollback. both saves Keychain first.', cleanup: 'Remote deletion never rewrites env files; remove obsolete values deliberately. CLI authentication remains in OS storage.' },
    } : op.secretSave ? { sensitiveResponse: 'Stored directly in the OS credential store; never returned as a raw API response.' } : {}),
    workflow: op.jwtAction ? { input: 'configure requires complete verifier JSON through stdin; secret-bearing URLs and claim values omitted from output', confirmation: '--confirm-name --allow-access-change --yes; --allow-production on production; requireJwtClaims:false also needs --allow-unrestricted-jwt', initialSetup: 'When app auth is disabled, configure requires --enable-auth and conditionally POSTs custom_jwt_auth:true before POSTing the verifier. Non-atomic; a partial failure can leave authentication enabled without a verifier. Inspect before retry; no automatic rollback.', cache: 'Changes require server-reported eligibility; revoked keys can remain valid until cache expiry. Flush is acknowledgement-only.', safety: 'No account-wide feature activation, billing or JWT signing; actual external authentication unverified' }
      : op.securitySetting ? { confirmation: '--confirm-name --allow-access-change --yes; production also --allow-production; rotation additionally --allow-session-impact', safety: 'Account/mode gates, selected-app preflight and fresh read-back. No key export, signing or owner-authorized execution.', rotation: 'Single rotation only; direct verification-key consumers must update. A subsequent rotation can invalidate previous sessions; no automatic retry.' }
      : op.availabilityAction ? { preflight: 'Owning-account approval and selected-app environment; verified enabled cookies, or custom experience for development. No implicit feature request or billing changes.', confirmation: '--yes --allow-access-change --confirm-name; production also --allow-production', verification: 'Fresh availability and unchanged known controls. Pending review is not published; no automatic retries.' }
      : op.advancedAction ? { scope: 'Customer-app identity settings, not dashboard account membership', confirmation: 'Merging/CAPTCHA writes require --yes --allow-access-change --confirm-name; production also --allow-production', warning: 'Merging affects future identity linking, not undo of existing links. hCaptcha requires compatible frontend SDKs (React react-auth@3.9.0+); incompatible SDKs can stop login.', inspection: 'Wallet export/recovery and custom JWT capability metadata only; no keys or owner authorization' }
      : op.ecosystemConnection ? { ...op.ecosystemConnection, confirmation: 'Writes require --yes and --allow-access-change; production also requires --allow-production. Approval may have irreversible effects after consumer enablement.', safety: 'Protect both app IDs before credentials/network; exact counterpart from complete selected-app list; current eligibility and fresh state preflight', output: 'Protected counterparts omitted; first20 rows, --all up to1000; no invented server pagination', verification: 'Fresh connection status, not external SDK use; no automatic write retries' }
      : op.integration ? { kind: op.integration.kind, action: op.integration.action, credentialInput: 'Sensitive fields/endpoint arrays use piped JSON only; full provider URLs and IIBAN are redacted', verification: 'Allowlisted read-back; masked credentials are not exact-value proof; no external integration verification', limits: 'No onboarding, funding, signing, transactions or paid provisioning. Scanning respects dashboard cookie-domain/ecosystem eligibility.', retries: 'No automatic write retries' }
      : op.imageAction ? imageWorkflow(op.imageAction)
      : op.accountJwtFeature ? { scope: 'Entire selected workspace; separate from per-app authentication', confirmation: '--confirm-account exact name --allow-access-change --yes', eligibility: 'Free tier and all apps development; protected accounts refused. No production override, billing or approval request.', preflight: 'At most100 apps; disable refuses any active app JWT authentication. Recheck account membership, app auth, capabilities and billing before writing.', verification: 'Account flag read-back, unchanged app authentication/other known feature flags and billing tier; no automatic retry or rollback' }
      : op.accountWrite ? { scope: 'Entire selected account, not the selected app', preflight: 'Fresh account state; refuse if any protected app; last admin/self-impact/dependency checks', confirmation: '--confirm-account exact name and --yes', production: 'Accounts containing production apps require --allow-production', verification: 'Fresh account membership/invitation read-back', retries: 'none' }
      : op.publicUserMetadata ? { preflight: 'Dashboard app environment and exact same-app user; merged metadata size', credentialSource: 'Explicit --credential ID in the app/profile OS vault; never argv secret', verification: 'Fresh dashboard user metadata comparison', production: '--allow-production and --yes', retries: 'none' }
      : op.accessWrite ? { preflight: 'Selected app environment, full bounded current list, same-app IDs/duplicate checks', production: '--allow-production and --yes', verification: 'Fresh entries or absence; login enforcement is separate', retries: 'none' }
      : op.publicOrganizationDelete ? { preflight: 'Same-app organization, environment, exact --confirm-name, zero active or archived wallet bindings', credentialSource: 'Explicit --credential ID from app/profile OS vault', verification: 'Public exact-ID absence and retained public collection access', retries: 'none' }
      : op.publicWallet ? { credentialSource: 'Explicit --credential ID from selected app/profile OS vault', preflight: 'Same-app read; archive additionally requires unowned server wallet, environment and exact --confirm-wallet ID', verification: 'Fresh public GET with include_archived=true and archived_at timestamp', warning: 'Archive is not deletion; prevents writes/signing. No CLI restoration.', retries: 'none' }
      : op.providerWrite || op.telegram && op.telegram !== 'read' ? { credentialInput: 'Credential fields require stdin JSON; no secret flags or body files', preflight: 'Selected app/environment and current configuration; editability/feature/provider-specific guards', production: 'requires --allow-production and --yes', verification: 'Fresh public configuration; masked or omitted secret values and real external login are not verified', retries: 'none' }
      : op.settingsWrite ? { preflight: op.settingsWrite.embeddedWallet ? 'Read app environment and full embedded-wallet config; inject existing recovery options/requirement into the POST without changing them. Offline body shows requested creation fields only; --diff resolves the full request.' : 'Check selected app environment and current settings.', production: 'requires --allow-production and --yes', verification: 'Fresh read-back of each changed field; set comparison where declared', retries: 'none' }
      : op.domainWrite ? { preflight: 'Check environment, current domain and optional same-app web client. No implicit domain replacement or allowed-origin expansion.', production: 'requires --allow-production and --yes', confirmation: 'Disabling/deleting requires --allow-session-impact; deletion also requires exact --confirm-domain.', verification: 'Fresh configuration/status read-back. DNS verification is reported separately; an owned DNS domain is required.', retries: 'none', limitation: 'Live empty-state reads verified; positive DNS provisioning/verification awaits an explicitly authorized owned test domain.' }
      : op.appClientWrite ? { preflight: 'Check app environment and same-app client; cookie inheritance requires a configured app domain.', production: 'requires --allow-production and --yes', verification: 'Fresh exact-ID list comparison', retries: 'none' }
      : op.credentialWrite ? { preflight: 'Check environment and current same-app key metadata; explicit access mode for creation.', production: 'requires --allow-production and --yes', verification: 'One-time secret handled according to the explicit storage choice before fresh metadata comparison; deletion verified by absence', retries: 'none', warning: 'Deletion breaks consumers. Creation never automatically deletes old keys. Store failures after creation require inspecting the reported reference, not recreating blindly.' }
      : op.webhookWrite ? { preflight: 'Check app environment and endpoint state. Delete/test/resend/enable require exact --confirm-url. Subscriptions affect all app endpoints.', production: 'requires --allow-production and --yes', verification: 'List/status read-back for configuration; notification submissions are acknowledgements, not successful delivery', retries: 'none', warning: 'Callbacks can disclose user data or repeat receiver business actions. Only use authorized destinations.' }
      : op.organizationWrite ? { preflight: 'Check app environment, existing organization/quorum and optional unbound wallets.', production: 'requires --allow-production and --yes', verification: 'Exact-ID organization and supplied wallet entity read-back', retries: 'none', warning: 'Wallet organization bindings are one-way. App organizations are not developer accounts or teams.' }
      : op.quorumWrite ? { preflight: 'Check app environment and nested quorum existence/depth.', production: 'requires --allow-production and --yes', verification: 'Exact-ID lookup and public member/threshold comparison', retries: 'none', warning: 'Public registration only. Retain your private keys securely; this operation does not generate or store them.' }
      : op.walletWrite ? { preflight: 'Read app environment, wallet and referenced resources. Control changes on owned wallets require approval. New owner assignment requires --confirm-owner.', production: 'requires --allow-production and --yes', verification: 'Fresh exact-ID wallet lookup and comparison; exports are job submissions', retries: 'none', warning: 'Changing owners/policies/signers changes control of funds, but does not execute a transaction.' }
      : op.userWrite ? { preflight: 'Read app environment; existing users are looked up by exact ID before mutations.', production: 'requires --allow-production and --yes', verification: 'Read-back where observable; bulk jobs are submissions, not completed imports. Revocation reports observed state without claiming an end-user session exercise.', retries: 'none' }
      : op.policyWrite ? { preflight: 'Read app environment; existing policies must have owner_id: null. Policy deletion also requires exact name and deletable: true.', production: 'requires --allow-production in addition to --yes', verification: 'Fresh policy read and field comparison; deletion requires verified absence', retries: 'none', limitations: 'Owner may be set at creation with explicit confirmation; subsequent owner-managed changes require approval. No signatures or automatic wallet attachment. Nested condition semantics validated by Privy.' }
      : op.behavior === 'update-app' ? { preflight: 'GET app configuration', production: 'requires --allow-production in addition to --yes', verification: 'GET app configuration and compare changed fields' }
      : op.behavior === 'delete-app' ? { preflight: 'Require explicit --app, --yes and --confirm-name matching a fresh configuration read; identify its account', production: 'not supported; only dev apps can be deleted', verification: 'App must be absent from a fresh listing of the same still-visible account', retries: 'none' } : undefined,
  };
}
