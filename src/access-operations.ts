import { CliError } from './errors.ts';
import type { Field, JsonObject, Operation, RequestPlan } from './operations.ts';
import type { ProviderRequest } from './provider-operations.ts';
const common = { scope: 'app' as const, keywords: ['access', 'allowlist', 'denylist', 'signup', 'email', 'domain', 'phone', 'wallet'], evidence: 'actual Access control page and loaded list/add/delete/clear handlers; see management-map' };
const flags: Record<string, Field> = { allowlist_enabled: { type: 'boolean', description: 'Only listed identities can access the app when true.' }, denylist_enabled: { type: 'boolean', description: 'Block listed identities when true. Cannot be enabled with allowlist.' } };
export const accessOperations: Operation[] = [
  { ...common, id: 'access.get', command: 'access get', method: 'GET', path: '/api/dashboard/apps/{app_id}', selectFields: Object.keys(flags), summary: 'Read app-user access-control mode, separate from server IP restrictions.', response: 'Allowlist/denylist enabled flags.', examples: ['privy access get'] },
  { ...common, id: 'access.update', command: 'access update', method: 'POST', path: '/api/v1/apps/{app_id}', settingsWrite: { read: 'access.get' }, body: { type: 'object', additionalProperties: false, required: Object.keys(flags), properties: flags }, summary: 'Select allowlist, denylist, or unrestricted app-user access; may block existing users.', response: 'Fresh flag read-back; no auth messages or identity deletion requested.', examples: ['privy access update --allowlist-enabled true --denylist-enabled false --diff'] },
  ...(['allowlist', 'denylist'] as const).flatMap((list): Operation[] => {
    const path = `/api/v1/apps/{app_id}/${list}`, stem = `access.${list}`;
    return [
      { ...common, id: `${stem}.list`, command: `access ${list} list`, method: 'GET' as const, path, query: { query: { type: 'string' as const, maxLength: 256, description: 'Dashboard identity search filter.' }, ...(list === 'denylist' ? { limit: { type: 'integer' as const, minimum: 1, maximum: 100, default: 20, description: 'Requested page size, at most 100.' }, cursor: { type: 'string' as const, description: 'Continuation cursor.' } } : {}) }, ...(list === 'denylist' ? { pagination: { cursor: 'cursor' as const, nextCursor: 'next_cursor' as const, items: 'data' as const } } : {}), summary: `Read ${list} entries using the observed non-cursor list API.`, response: 'Allowlist array or denylist data envelope; identities may be sensitive.', examples: [`privy access ${list} list`] },
      { ...common, id: `${stem}.add`, command: `access ${list} add`, method: 'POST' as const, path: path + (list === 'denylist' ? '/batch' : ''), bodyArrayField: 'entries', body: { type: 'object' as const, additionalProperties: false as const, required: ['entries'], properties: { entries: { type: 'array' as const, minItems: 1, maxItems: 100, items: { type: 'object' as const }, description: `Entries {type,value}. Types: email, emailDomain, phone, ${list === 'allowlist' ? 'wallet' : 'ethereumAddress, solanaAddress'}. Does not switch access mode.` } } }, accessWrite: { list, action: 'add' as const }, summary: `Add explicit identities to the ${list}; verify all entries.`, response: 'Fresh matching entries, not proof of actual login enforcement.', examples: [`privy access ${list} add --entries '[{"type":"email","value":"demo@example.invalid"}]' --dry-run`] },
      { ...common, id: `${stem}.remove`, command: `access ${list} remove`, method: 'DELETE' as const, path, ...(list === 'denylist' ? { params: ['entry_id'], bodyFromParams: { id: 'entry_id' } } : {}), body: { type: 'object' as const, additionalProperties: false as const, required: list === 'allowlist' ? ['ids'] : ['id'], properties: list === 'allowlist' ? { type: { type: 'string' as const, enum: ['ids'], default: 'ids', description: 'Remove specific IDs only.' }, ids: { type: 'array' as const, minItems: 1, maxItems: 100, items: { type: 'string' as const, maxLength: 128 }, description: 'IDs from this app’s allowlist.' } } : { id: { type: 'string' as const, description: 'Same-app denylist ID.' } } }, accessWrite: { list, action: 'delete' as const }, summary: `Remove selected ${list} entries and verify absence.`, response: 'Fresh absence; removing denylist entries can allow access.', examples: [list === 'allowlist' ? 'privy access allowlist remove --ids \'["entry-id"]\' --dry-run' : 'privy access denylist remove <entry-id> --dry-run'] },
      { ...common, id: `${stem}.clear`, command: `access ${list} clear`, method: 'DELETE' as const, path: path + (list === 'denylist' ? '/batch' : ''), body: { type: 'object' as const, additionalProperties: false as const, required: ['type'], properties: { type: { type: 'string' as const, enum: list === 'allowlist' ? ['accepted', 'all'] : ['all'], description: 'Explicit scope: all entries, or accepted allowlist invitations only. Irreversible.' } } }, accessWrite: { list, action: 'clear' as const }, summary: `Clear ${list} entries in an explicit scope; can change app access.`, response: 'Fresh verification of requested clear scope.', examples: [`privy access ${list} clear --type all --dry-run`] },
    ];
  }),
];
export function validateAccess(op: Operation, body: JsonObject): void {
  if (op.id === 'access.update' && body.allowlist_enabled && body.denylist_enabled) throw new CliError('CONFLICTING_ACCESS_MODES', 'Allowlist and denylist cannot both be enabled.', 2);
  if (op.accessWrite?.action !== 'add') return;
  const seen = new Set<string>();
  for (const row of body.entries) {
    const types = ['email', 'emailDomain', 'phone', ...(op.accessWrite.list === 'allowlist' ? ['wallet'] : ['ethereumAddress', 'solanaAddress'])];
    if (Object.keys(row).some(k => !['type', 'value'].includes(k)) || !types.includes(row.type) || typeof row.value !== 'string' || !row.value.length || row.value.length > 320 || row.value !== row.value.trim()) throw new CliError('INVALID_ACCESS_ENTRY', 'Expected a supported {type,value} identity without whitespace or extra fields.', 2);
    const v = row.value;
    const eth = /^0x[0-9a-fA-F]{40}$/.test(v), sol = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(v);
    if (row.type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) || row.type === 'emailDomain' && !/^@?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$/.test(v) || row.type === 'phone' && !/^\+[1-9][0-9]{7,14}$/.test(v) || row.type === 'wallet' && !eth && !sol || row.type === 'ethereumAddress' && !eth || row.type === 'solanaAddress' && !sol) throw new CliError('INVALID_ACCESS_ENTRY', 'Invalid email/domain/E.164 phone/wallet identity.', 2);
    if (row.type === 'email' || row.type === 'emailDomain') row.value = v.toLowerCase();
    const key = `${row.type}:${row.value}`;
    if (seen.has(key)) throw new CliError('DUPLICATE_ACCESS_ENTRY', 'Duplicate identity in request.', 2);
    seen.add(key);
  }
}
function rows(value: any, list: string): JsonObject[] {
  const data = list === 'allowlist' ? value : value?.data;
  if (!Array.isArray(data) || data.length > 10000 || data.some(r => !r || typeof r.id !== 'string' || typeof r.value !== 'string')) throw new CliError('INVALID_ACCESS_LIST', 'Unexpected or oversized access list. No complete result inferred.');
  if (new Set(data.map(r => r.id)).size !== data.length) throw new CliError('INVALID_ACCESS_LIST', 'Duplicate access-list IDs.');
  return data;
}
export async function writeAccess(op: Operation, plan: RequestPlan, request: ProviderRequest): Promise<JsonObject> {
  const spec = op.accessWrite!, appId = plan.pathParams.app_id, root = `/api/v1/apps/${appId}/${spec.list}`;
  const read = async (): Promise<JsonObject[]> => {
    if (spec.list === 'allowlist') return rows(await request(root), spec.list);
    const result: JsonObject[] = [], cursors = new Set<string>();
    let cursor: string | null = null;
    for (let page = 0; page < 10; page++) {
      const response = await request(root + '?limit=100' + (cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''));
      result.push(...rows(response, spec.list));
      if (response.next_cursor === null) {
        if (new Set(result.map(r => r.id)).size !== result.length) throw new CliError('INVALID_ACCESS_LIST', 'Duplicate IDs across denylist pages.');
        return result;
      }
      if (typeof response.next_cursor !== 'string' || !response.next_cursor || cursors.has(response.next_cursor)) throw new CliError('INVALID_ACCESS_LIST', 'Invalid or repeated denylist cursor.');
      cursor = response.next_cursor; cursors.add(cursor!);
    }
    throw new CliError('LOOKUP_INCOMPLETE', 'Denylist exceeded ten pages; no incomplete list treated as complete.');
  };
  const before = await read(), body = plan.body!;
  const match = (row: JsonObject, entry: JsonObject) => (row.type ?? row.rule_type) === entry.type && row.value === entry.value;
  if (spec.action === 'add' && body.some((entry: JsonObject) => before.some(row => match(row, entry)))) throw new CliError('ACCESS_ENTRY_EXISTS', 'An identity already exists. Inspect list; do not repeat the batch.', 2);
  const ids: string[] = spec.action === 'delete' ? body.ids ?? [body.id] : [];
  if (ids.some(id => !before.some(row => row.id === id)) || new Set(ids).size !== ids.length) throw new CliError('ACCESS_ENTRY_NOT_FOUND', 'Each distinct deletion ID must exist in this app.', 2);
  await request(plan.path, plan.method, body, true);
  try {
    const after = await read();
    if (spec.action === 'add') {
      const created = body.map((entry: JsonObject) => after.filter(row => match(row, entry)));
      if (created.some((matches: JsonObject[]) => matches.length !== 1) || before.some(row => !after.some(r => r.id === row.id))) throw new Error();
      return { appId, verified: true, entries: created.flat() };
    }
    if (spec.action === 'delete' && (after.some(row => ids.includes(row.id)) || before.filter(row => !ids.includes(row.id)).some(row => !after.some(r => r.id === row.id))) || spec.action === 'clear' && (body.type === 'all' ? after.length > 0 : after.some(row => Boolean(row.acceptedAt)) || before.filter(row => !row.acceptedAt).some(row => !after.some(r => r.id === row.id)))) throw new Error();
    return { appId, verified: true, remaining: after.length };
  } catch { throw new CliError('ACCESS_VERIFY_FAILED', 'Write acknowledged but access-list verification failed. Read current state; no retry occurred.'); }
}
