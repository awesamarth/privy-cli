import { CliError } from './errors.ts';
import type { JsonObject, Operation } from './operations.ts';
export const userMetadataOperations: Operation[] = (['set', 'update'] as const).map(action => ({
  id: `users.metadata.${action}`, command: `users metadata ${action}`, summary: action === 'set' ? 'Replace a user’s entire custom metadata using a stored app API credential.' : 'Shallow-merge user custom metadata using a stored app API credential.', keywords: ['user', 'custom', 'metadata', 'merge', 'replace'], method: action === 'set' ? 'POST' : 'PATCH', path: '/v1/users/{user_id}/custom_metadata', scope: 'app', params: ['user_id'], publicUserMetadata: true,
  body: { type: 'object', additionalProperties: false, required: ['custom_metadata'], properties: { custom_metadata: { type: 'object', description: 'At most 1 KiB UTF-8 JSON; string keys and string/integer/boolean values. Set replaces; update shallow-merges.' } } },
  response: 'Fresh dashboard read-back of exact same-app user metadata. Uses fixed api.privy.io Basic app authentication for the write, never dashboard bearer credentials on that host.', evidence: 'official REST documentation https://docs.privy.io/user-management/users/custom-metadata.md; manual evidence in management-map', examples: [`privy users metadata ${action} <user-id> --custom-metadata '{"purpose":"example"}' --diff`, `privy users metadata ${action} <user-id> --custom-metadata '{"purpose":"example"}' --credential <stored-full-credential-id> --yes`],
}));
export function validateUserMetadata(value: unknown): asserts value is JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.values(value).some(v => typeof v !== 'string' && typeof v !== 'boolean' && !(typeof v === 'number' && Number.isSafeInteger(v))) || Buffer.byteLength(JSON.stringify(value)) > 1024) throw new CliError('INVALID_CUSTOM_METADATA', 'Custom metadata must be a JSON object up to 1 KiB with string, safe-integer or boolean values.', 2);
}
