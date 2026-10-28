import { createPublicKey } from 'node:crypto';
import { CliError } from './errors.ts';
import { validateId } from './store.ts';
import type { Field, JsonObject, Operation } from './operations.ts';
const root = '/api/v1/apps/{app_id}/key_quorums';
const list = (description: string): Field => ({ type: 'array', maxItems: 100, items: { type: 'string', maxLength: 4096 }, description });
const common = { scope: 'app' as const, keywords: ['authorization', 'keys', 'quorum', 'members'], evidence: 'authorized key-quorum registration UI and loaded creation/list hooks; manual results in management-map' };
export const quorumOperations: Operation[] = [
  { ...common, id: 'key-quorums.get', command: 'key-quorums get', aliases: ['keys get'], summary: 'Inspect a key quorum by exact ID, including public members and threshold.', method: 'GET', path: root, params: ['key_quorum_id'], behavior: 'get-quorum', queryFromParams: { query: 'key_quorum_id' }, query: { query: { type: 'string', maxLength: 128, description: 'Generated exact-ID search.' }, limit: { type: 'integer', minimum: 100, maximum: 100, default: 100, description: 'Bounded exact-ID search page size.' } }, response: 'Exact quorum from bounded search. No private keys.', examples: ['privy key-quorums get <quorum-id>'] },
  { ...common, id: 'key-quorums.create', command: 'key-quorums create', aliases: ['keys register'], summary: 'Register public authorization keys or existing quorums with an explicit threshold.', method: 'POST', path: root, quorumWrite: 'create', body: { type: 'object', additionalProperties: false, required: ['display_name', 'authorization_threshold'], properties: {
    display_name: { type: 'string', minLength: 1, maxLength: 50, pattern: '\\S', description: 'Quorum name.' },
    authorization_threshold: { type: 'integer', minimum: 1, maximum: 100, description: 'Required approvals; cannot exceed the number of distinct supplied members.' },
    public_keys: list('Public P-256 authorization keys, base64-encoded SPKI DER. Never supply private keys.'),
    key_quorum_ids: { ...list('Existing leaf key-quorum IDs in this app; at most five, nested one level deep.'), maxItems: 5 },
  } }, response: 'Created quorum and read-back verification. Registers public material only; does not generate/export private keys or attach ownership to any resource.', examples: ['privy key-quorums create --file quorum.json --dry-run', 'privy key-quorums create --file quorum.json --yes'] },
];

export function validateQuorumBody(body: JsonObject): void {
  const keys: string[] = body.public_keys ?? [], ids: string[] = body.key_quorum_ids ?? [];
  if (!keys.length && !ids.length || body.authorization_threshold > keys.length + ids.length) throw new CliError('INVALID_THRESHOLD', 'Supply at least one member and a threshold no greater than the member count.', 2);
  if (new Set(keys).size !== keys.length || new Set(ids).size !== ids.length) throw new CliError('DUPLICATE_MEMBER', 'Quorum members must be unique.', 2);
  ids.forEach(validateId);
  for (const key of keys) {
    try {
      const bytes = Buffer.from(key, 'base64');
      if (bytes.toString('base64') !== key) throw new Error();
      const parsed = createPublicKey({ key: bytes, format: 'der', type: 'spki' });
      if (parsed.asymmetricKeyType !== 'ec' || parsed.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw new Error();
    } catch { throw new CliError('INVALID_PUBLIC_KEY', 'Expected a base64-encoded P-256 SPKI public key. Private keys, PEM and other curves are not accepted.', 2); }
  }
}
