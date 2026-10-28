import { isDeepStrictEqual } from 'node:util';
import { CliError } from './errors.ts';
import { integrationMetadata, cookieDomainEnabled } from './integration-operations.ts';
import type { Operation, JsonObject, RequestPlan } from './operations.ts';

const common = { scope: 'app' as const, path: '/api/v1/apps/{app_id}/cross-app/configuration', keywords: ['global-wallet', 'publish', 'unpublish', 'availability', 'eligibility', 'readiness'], evidence: 'Loaded ecosystem availability toggle/callback and confirmation; account approval plus environment-specific cookie/custom-experience prerequisites.' };
export const availabilityOperations: Operation[] = [
  { ...common, id: 'global-wallet.availability.get', command: 'global-wallet availability get', method: 'GET', availabilityAction: 'read', summary: 'Inspect cross-app wallet availability and publishing blockers; no activation or approval request.', response: 'Structured eligibility reasons and safe prerequisites. Readiness is not backend approval, permission proof, frontend validation or external integration verification.', examples: ['privy global-wallet availability get'] },
  { ...common, id: 'global-wallet.availability.update', command: 'global-wallet availability update', method: 'POST', availabilityAction: 'update', body: { type: 'object', additionalProperties: false, required: ['availability'], properties: { availability: { type: 'string', enum: ['private', 'public'], description: 'public makes this app a cross-app wallet provider; private pauses other apps’ access. Does not publish the CLI to npm. invite_only/pending are readable server states, not writable inputs.' } } }, summary: 'Make this app available/unavailable as a cross-app wallet provider, after explicit eligibility and access-impact checks.', response: 'Requires --confirm-name, --allow-access-change and --yes; production requires --allow-production. Preserves known other cross-app controls. Pending review is not reported as published. No billing, account approval request or automatic retry.', examples: ['privy global-wallet availability update --availability public --diff', 'privy global-wallet availability update --availability private --confirm-name <app-name> --allow-access-change --yes'] },
];
type Request = (path: string, method?: string, body?: JsonObject, acknowledgementOnly?: boolean) => Promise<any>;
export interface AvailabilityContext { app: JsonObject; teams: JsonObject[] }
export async function availabilityState(context: AvailabilityContext, request: Request): Promise<JsonObject> {
  const { app, teams } = context;
  const owners = teams.filter(team => Array.isArray(team.apps) && team.apps.some((row: JsonObject) => row.id === app.id));
  if (owners.length !== 1) throw new CliError('ACCOUNT_SCOPE_UNVERIFIED', 'Cannot establish the selected app’s unique owning account. No write was sent.');
  const account = owners[0], flag = account.globalWalletConnectEnabledAt;
  const approved = flag === null || flag === false ? false : typeof flag === 'string' && Number.isFinite(Date.parse(flag)) ? true : null;
  const config = integrationMetadata('ecosystem', await request(`/api/v1/apps/${app.id}/cross-app/configuration`)).config;
  const cookies = await cookieDomainEnabled(app.id, request);
  const customExperienceConfigured = ['custom_connect_url', 'custom_transact_url', 'custom_auth_authorize_url', 'custom_auth_transact_url'].some(key => Boolean(config[key]));
  const commonReasons: string[] = [];
  if (!['dev', 'prod'].includes(app.env)) commonReasons.push('UNKNOWN_APP_ENVIRONMENT');
  if (approved !== true) commonReasons.push(approved === false ? 'ACCOUNT_APPROVAL_REQUIRED' : 'ACCOUNT_APPROVAL_UNVERIFIED');
  const publishReasons = [...commonReasons];
  if (app.env === 'prod' && !cookies) publishReasons.push('VERIFIED_COOKIE_DOMAIN_REQUIRED');
  if (app.env === 'dev' && !cookies && !customExperienceConfigured) publishReasons.push('COOKIE_DOMAIN_OR_CUSTOM_EXPERIENCE_REQUIRED');
  return { appId: app.id, appName: app.name, accountId: account.id, env: app.env, config, prerequisites: { accountApproved: approved, enabledVerifiedCookies: cookies, customExperienceConfigured, customExperienceVerified: false }, publish: { eligible: publishReasons.length === 0, alreadyApplied: config.availability === 'public', reasons: publishReasons }, unpublish: { eligible: commonReasons.length === 0, alreadyApplied: config.availability === 'private', reasons: commonReasons }, writesPerformed: false, externalIntegrationVerified: false, note: 'Eligibility follows observed dashboard gates; the backend still enforces authorization/review. No account approval, billing or production conversion is performed.' };
}
export async function writeAvailability(plan: RequestPlan, context: () => Promise<AvailabilityContext>, request: Request, confirmName?: string): Promise<JsonObject> {
  const before = await availabilityState(await context(), request), desired = plan.body!.availability;
  if (typeof before.appName !== 'string' || confirmName !== before.appName) throw new CliError('APP_NAME_MISMATCH', 'Use --confirm-name with the exact selected app name. No write was sent.', 2);
  if (before.config.availability === desired) return { ...before, verified: true, alreadyApplied: true };
  if (desired === 'public' && before.config.availability === 'public_pending_approval') return { ...before, verified: false, pendingReview: true, alreadyRequested: true };
  if (desired === 'public' && before.config.availability !== 'private') throw new CliError('AVAILABILITY_TRANSITION_UNSUPPORTED', 'The dashboard does not expose converting invite-only access to public in place. No write was sent.', 2);
  const gate = desired === 'public' ? before.publish : before.unpublish;
  if (!gate.eligible) { const error = new CliError('AVAILABILITY_NOT_ELIGIBLE', 'Cross-app availability prerequisites are not met. Inspect global-wallet availability get; no approval request or write was sent.', 2); error.details = { reasons: gate.reasons }; throw error; }
  const latest = await availabilityState(await context(), request);
  if (!isDeepStrictEqual(latest, before)) throw new CliError('AVAILABILITY_STATE_CHANGED', 'App/account eligibility or cross-app controls changed during preflight. No write was sent.', 2);
  await request(plan.path, 'POST', plan.body, true);
  try {
    const after = integrationMetadata('ecosystem', await request(plan.path)).config;
    const pendingReview = desired === 'public' && after.availability === 'public_pending_approval';
    if (!isDeepStrictEqual(after, { ...before.config, availability: pendingReview ? 'public_pending_approval' : desired })) throw new Error();
    return { appId: before.appId, acknowledged: true, writesPerformed: true, verified: !pendingReview, metadataVerified: true, pendingReview, state: after, externalIntegrationVerified: false };
  } catch { throw new CliError('AVAILABILITY_VERIFY_FAILED', 'Availability write acknowledged but fresh state could not be verified. Inspect availability get; no write was repeated.'); }
}
