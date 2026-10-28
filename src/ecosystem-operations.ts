import { isDeepStrictEqual } from 'node:util';
import { CliError } from './errors.ts';
import { validateId } from './store.ts';
import type { Operation, JsonObject, RequestPlan } from './operations.ts';

export type ConnectionAction = 'list' | 'enable' | 'disable' | 'request' | 'accept' | 'reject';
const root = '/api/v1/apps/{app_id}/cross-app';
const common = { scope: 'app' as const, keywords: ['global-wallet', 'ecosystem', 'cross-app', 'connections', 'integrations'], evidence: 'loaded ecosystem provider/requester cards, confirmation copy and GET/POST hooks; see management-map' };
export const ecosystemOperations: Operation[] = (['providers', 'requesters'] as const).flatMap(side => {
  const actions: ConnectionAction[] = side === 'providers' ? ['list', 'enable', 'disable', 'request'] : ['list', 'accept', 'reject'];
  const param = side === 'providers' ? 'provider_app_id' : 'requester_app_id';
  return actions.map((action): Operation => ({ ...common, id: `global-wallet.${side}.${action}`, command: `global-wallet ${side} ${action}`, method: action === 'list' ? 'GET' : 'POST', path: `${root}/${side}`, ecosystemConnection: { side, action },
    ...(action === 'list' ? {} : { params: [param], bodyFromParams: { [param]: param }, body: { type: 'object' as const, additionalProperties: false as const, required: [param], properties: { [param]: { type: 'string' as const, description: 'Exact counterpart app ID; local protection applies to both apps.' }, ...(side === 'providers' ? { enable_connection: { type: 'boolean' as const, enum: [action !== 'disable'], default: action !== 'disable', description: 'Fixed by command. Request explicitly asks the provider for access; enable does not silently send an access request.' } } : { connection_action: { type: 'string' as const, enum: [action], default: action, description: 'Accept is provider-side approval; reject rejects pending requests or blocks accepted/enabled connections.' } }) } } }),
    summary: action === 'list' ? `List safe ${side} metadata from the selected app; protected counterparts omitted, first 20 by default.` : `${action} a ${side === 'providers' ? 'wallet-provider connection' : 'requesting app connection'}. Requires --allow-access-change; may grant/revoke cross-app access.`,
    response: action === 'list' ? 'Single dashboard collection read, no invented server pagination. --all exposes up to 1000 rows. Explicit truncation; never queries counterpart app endpoints.' : 'Exact listed counterpart, fresh state/eligibility checks, one POST and status read-back. Provider acceptance can have irreversible effects once enabled; no signing, publishing or account-feature approval. No automatic retries.', examples: [`privy global-wallet ${side} ${action}${action === 'list' ? ' --all' : ' <counterpart-app-id> --dry-run'}`] }));
});
export function connectionRows(raw: any, side: 'providers' | 'requesters'): JsonObject[] {
  const rows = raw?.[side];
  if (!Array.isArray(rows) || rows.length > 1000) throw new CliError('INVALID_CONNECTION_LIST', 'Expected a complete connection array within the CLI 1000-row bound. No truncated match is used for writes.');
  const ids = new Set<string>();
  return rows.map((row: any) => {
    if (!row || typeof row !== 'object' || typeof row.name !== 'string') throw new CliError('INVALID_CONNECTION_LIST', 'Incomplete connection identity metadata.');
    const id = validateId(row.app_id);
    if (ids.has(id) || row.status != null && !['pending', 'accepted', 'enabled', 'disabled', 'rejected', 'blocked'].includes(row.status)) throw new CliError('INVALID_CONNECTION_LIST', 'Duplicate counterpart or unknown connection status.');
    ids.add(id);
    if (side === 'providers' && (!['private', 'public', 'public_pending_approval', 'invite_only'].includes(row.availability) || !['read_only', 'read_write'].includes(row.allowed_permissions))) throw new CliError('INVALID_CONNECTION_LIST', 'Cannot establish provider availability/permissions.');
    return { app_id: id, name: row.name, status: row.status ?? null, ...(side === 'providers' ? { availability: row.availability, allowed_permissions: row.allowed_permissions } : {}), ...(typeof row.icon_url === 'string' ? { icon_url: row.icon_url } : {}), ...(typeof row.created_at === 'string' ? { created_at: row.created_at } : {}) };
  });
}
export function connectionList(raw: any, side: 'providers' | 'requesters', blocked: string[], all = false): JsonObject {
  const original = connectionRows(raw, side), rows = original.filter(row => !blocked.includes(row.app_id)), limit = all ? 1000 : 20;
  return { data: rows.slice(0, limit), totalAvailable: rows.length, truncated: rows.length > limit, protectedAppsOmitted: original.length !== rows.length, collectionRequests: 1, externalIntegrationVerified: false };
}
type Request = (path: string, method?: string, body?: JsonObject, acknowledgementOnly?: boolean) => Promise<any>;
export async function writeConnection(op: Operation, plan: RequestPlan, request: Request, allowAccessChange?: boolean): Promise<JsonObject> {
  if (!allowAccessChange) throw new CliError('ACCESS_CHANGE_CONFIRMATION_REQUIRED', 'Add --allow-access-change to acknowledge cross-app access grants/revocations or an external provider access request. Approval can have irreversible effects after enablement. No write was sent.', 2);
  const { side, action } = op.ecosystemConnection!, appId = plan.pathParams.app_id, otherId = plan.body![side === 'providers' ? 'provider_app_id' : 'requester_app_id'];
  const find = async () => connectionRows(await request(plan.path), side).find(row => row.app_id === otherId);
  const before = await find();
  if (!before) throw new CliError('CONNECTION_NOT_LISTED', 'Counterpart is not in this selected app’s complete connection list. No write was sent.', 2);
  const success = (row: JsonObject | undefined): boolean => Boolean(row && (action === 'enable' ? row.status === 'enabled' : action === 'disable' ? row.status === null || row.status === 'disabled' : action === 'request' ? row.status === 'pending' : action === 'accept' ? ['accepted', 'enabled'].includes(row.status) : ['rejected', 'blocked'].includes(row.status)));
  if (success(before)) return { appId, counterpartAppId: otherId, verified: true, writesPerformed: false, state: before, externalIntegrationVerified: false };
  let providerAvailability: string | undefined;
  if (side === 'providers') {
    const allowed = action === 'enable' ? before.availability === 'public' && before.status === null || ['disabled', 'accepted'].includes(before.status) : action === 'disable' ? before.status === 'enabled' : before.availability === 'invite_only' && before.status === null;
    if (!allowed) throw new CliError('CONNECTION_ACTION_UNAVAILABLE', 'This action is unavailable for the current provider status/availability. Invite-only access requests require the separate request command. No write was sent.', 2);
  } else {
    const config = await request(`/api/v1/apps/${appId}/cross-app/configuration`);
    providerAvailability = config?.availability;
    if (!['private', 'public', 'public_pending_approval', 'invite_only'].includes(providerAvailability!)) throw new CliError('INVALID_ECOSYSTEM_STATE', 'Cannot establish provider availability. No write was sent.');
    if (action === 'accept' ? providerAvailability !== 'invite_only' || !['pending', 'rejected'].includes(before.status) : !['pending', 'accepted', 'enabled'].includes(before.status)) throw new CliError('CONNECTION_ACTION_UNAVAILABLE', 'This requester action is unavailable in the dashboard for the current state. No write was sent.', 2);
  }
  if (!isDeepStrictEqual(await find(), before)) throw new CliError('CONNECTION_CHANGED', 'Connection changed during preflight. No write was sent.', 2);
  if (providerAvailability !== undefined && (await request(`/api/v1/apps/${appId}/cross-app/configuration`)).availability !== providerAvailability) throw new CliError('CONNECTION_CHANGED', 'Provider availability changed during preflight. No write was sent.', 2);
  await request(plan.path, 'POST', plan.body, true);
  try {
    const after = await find();
    const expected = action === 'reject' ? before.status === 'pending' ? 'rejected' : 'blocked' : null;
    if (!success(after) || expected && after!.status !== expected) throw new Error();
    return { appId, counterpartAppId: otherId, verified: true, state: after, externalIntegrationVerified: false };
  } catch { throw new CliError('CONNECTION_VERIFY_FAILED', 'Connection write acknowledged but status read-back failed. Inspect the connection list; no write was repeated.'); }
}
