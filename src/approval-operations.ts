import { CliError } from './errors.ts';
import { validateId } from './store.ts';
import type { Field, JsonObject, Operation } from './operations.ts';
const root = '/api/v1/apps/{app_id}';
const text = (description: string): Field => ({ type: 'string', minLength: 1, maxLength: 256, description });
const common = { scope: 'app' as const, keywords: ['approval', 'intent', 'proposal', 'owner', 'review'], approvalSummary: true, evidence: 'actual Approvals UI (MFA prerequisite), loaded 53476 list hook and 3311 intent/detail/handoff code' };
export const approvalOperations: Operation[] = [
  { ...common, id: 'approvals.list', command: 'approvals list', summary: 'List approval metadata and dashboard review links; never signs or executes proposals.', method: 'GET', path: `${root}/approvals`, query: {
    limit: { type: 'integer', minimum: 1, maximum: 100, default: 20, description: 'Page size.' }, cursor: text('Continuation cursor.'),
    status: text('Dashboard status filter, e.g. pending.'), pending_member_id: text('Pending member ID.'), resource_id: text('Resource ID.'), created_by_id: text('Creator ID.'),
    intent_type: text('Proposal type, e.g. POLICY, RULE, WALLET or KEY_QUORUM.'), current_user_has_signed: { type: 'boolean', description: 'Filter by current developer signature state.' }, sort_by: text('Dashboard sort order.'),
  }, pagination: { cursor: 'cursor', nextCursor: 'next_cursor', items: 'data' }, response: 'Safe metadata and review links, not authorization signatures or raw request headers/bodies. Empty-list evidence only in the current account.', examples: ['privy approvals list --status pending', 'privy approvals list --resource-id <resource-id> --all'] },
  ...(['get', 'open'] as const).map(verb => ({ ...common, id: `approvals.${verb}`, command: `approvals ${verb}`, summary: verb === 'get' ? 'Inspect remote intent status and obtain a human-review link.' : 'Open a proposal in the normal browser for human review; no automatic approval.', method: 'GET' as const, path: `${root}/intents/{intent_id}`, params: ['intent_id'], browserHandoff: verb === 'open', response: 'Remote status is not independent verification of the requested resource change. Full review/authorization stays in the dashboard and may require MFA.' + (verb === 'open' ? ' --no-open prints the handoff only.' : ''), examples: [`privy approvals ${verb} <intent-id>${verb === 'open' ? ' --no-open' : ''}`] })),
];

export function summarizeApproval(value: JsonObject, appId: string, requestedId?: string): JsonObject {
  const record = value?.item_type ? value.data : value;
  let id: string;
  try { id = validateId(value?.id ?? record?.id); }
  catch { throw new CliError('INVALID_APPROVAL', 'Approval response did not contain a valid ID.'); }
  if (!record || typeof record !== 'object' || Array.isArray(record) || requestedId && id !== requestedId) throw new CliError('INVALID_APPROVAL', 'Approval response did not match the requested resource.');
  const fields = ['intent_type', 'status', 'resource_id', 'created_at', 'updated_at', 'expires_at', 'created_by_id', 'authorization_threshold'];
  const summary = Object.fromEntries(fields.filter(k => typeof record[k] === 'string' || typeof record[k] === 'number').map(k => [k, record[k]]));
  const query = new URLSearchParams(value.item_type === 'mfa_reset' ? { mfa_reset_request: id } : { intent: id, ...(typeof record.intent_type === 'string' ? { intent_type: record.intent_type } : {}) });
  const method = record.request_details?.method;
  return { id, ...(value.item_type ? { item_type: value.item_type } : {}), ...summary,
    ...(['GET', 'POST', 'PATCH', 'DELETE'].includes(method) ? { request_method: method } : {}),
    review_url: `https://dashboard.privy.io/apps/${appId}/approvals?${query}`,
    authorizationPerformed: false, details: 'Review full requested changes in the dashboard; authorization may require MFA. CLI does not sign or execute this proposal.' };
}
