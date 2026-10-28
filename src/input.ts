import { open, stat } from 'node:fs/promises';
import { constants } from 'node:fs';
import { CliError } from './errors.ts';
import type { Field, JsonObject, Operation } from './operations.ts';

const MAX_BODY_BYTES = 1024 * 1024;
export const optionKey = (name: string) => name.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
export const optionFlag = (name: string) => name.replace(/([a-z0-9])([A-Z])/g, '$1-$2').replaceAll('_', '-').toLowerCase();
async function stdin(signal?: AbortSignal): Promise<string> {
  if (process.stdin.isTTY) throw new CliError('STDIN_REQUIRED', 'Pipe JSON into stdin when using --body - or --file -.', 2);
  signal?.throwIfAborted();
  let size = 0;
  const chunks: Buffer[] = [];
  const cancel = () => process.stdin.destroy(new CliError('CANCELLED', 'Input cancelled before a request was sent.', 130));
  signal?.addEventListener('abort', cancel, { once: true });
  try {
    for await (const chunk of process.stdin) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += bytes.length;
      if (size > MAX_BODY_BYTES) throw new CliError('BODY_TOO_LARGE', 'Request bodies are limited to 1 MiB.', 2);
      chunks.push(bytes);
    }
    signal?.throwIfAborted();
    return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
  } finally { signal?.removeEventListener('abort', cancel); }
}
export function readQuery(op: Operation, options: JsonObject): JsonObject {
  const query: JsonObject = {};
  for (const [key, field] of Object.entries(op.query ?? {})) {
    const value = options[optionKey(key)];
    if (value === undefined) continue;
    if (field.type === 'string') query[key] = value;
    else {
      try { query[key] = JSON.parse(value); }
      catch { throw new CliError('INVALID_INPUT', `--${optionFlag(key)} expects a JSON ${field.type}.`, 2); }
    }
  }
  return query;
}
function hasSensitiveInput(body: JsonObject, fields: Record<string, Field>): boolean {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return false;
  return Object.entries(fields).some(([key, field]) => Object.hasOwn(body, key) && (field.sensitive
    || field.properties && hasSensitiveInput(body[key], field.properties)
    || field.items?.properties && Array.isArray(body[key]) && body[key].some((item: JsonObject) => hasSensitiveInput(item, field.items!.properties!))));
}
export async function readBody(op: Operation, options: JsonObject, signal?: AbortSignal): Promise<JsonObject | undefined> {
  signal?.throwIfAborted();
  if (!op.body) return undefined;
  const sources = [options.body, options.file, options.patch].filter(v => v !== undefined);
  if (sources.length > 1) throw new CliError('CONFLICTING_INPUT', 'Choose only one of --body, --file or --patch.', 2);
  let body: JsonObject = {};
  if (sources.length) {
    let text: string;
    try {
      if (sources[0] === '-') text = await stdin(signal);
      else if (options.file !== undefined) {
        const info = await stat(options.file);
        if (!info.isFile() || info.size > MAX_BODY_BYTES) throw new CliError('INVALID_BODY_FILE', 'Body file must be a regular file no larger than 1 MiB.', 2);
        const file = await open(options.file, constants.O_RDONLY | constants.O_NONBLOCK);
        try {
          const before = await file.stat();
          if (!before.isFile() || before.dev !== info.dev || before.ino !== info.ino || before.size > MAX_BODY_BYTES) throw new CliError('INVALID_BODY_FILE', 'Body file changed or is not a bounded regular file.', 2);
          const buffer = Buffer.alloc(MAX_BODY_BYTES + 1);
          let used = 0;
          while (used < buffer.length) { signal?.throwIfAborted(); const { bytesRead } = await file.read(buffer, used, buffer.length - used, used); if (!bytesRead) break; used += bytesRead; }
          if (used > MAX_BODY_BYTES) throw new CliError('BODY_TOO_LARGE', 'Request bodies are limited to 1 MiB.', 2);
          const after = await file.stat();
          if (before.size !== used || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw new CliError('BODY_FILE_CHANGED', 'Body file changed while being read; no request was sent.', 2);
          text = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, used));
        } finally { await file.close(); }
      } else text = sources[0];
      if (Buffer.byteLength(text) > MAX_BODY_BYTES) throw new CliError('BODY_TOO_LARGE', 'Request bodies are limited to 1 MiB.', 2);
      body = JSON.parse(text);
      if (Array.isArray(body) && op.bodyArrayField) body = { [op.bodyArrayField]: body };
      if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error();
    } catch (error) {
      if (error instanceof CliError) throw error;
      throw new CliError('INVALID_BODY', 'Could not read a JSON object. Use --body, --file, or pipe JSON with --body -.', 2);
    }
  }
  for (const [key, field] of Object.entries(op.body.properties)) {
    const value = options[optionKey(key)];
    if (value === undefined) continue;
    if (Object.hasOwn(body, key)) throw new CliError('DUPLICATE_FIELD', `Field ${key} was supplied in both the body and a flag. Choose one.`, 2);
    if (field.type === 'string') body[key] = value;
    else {
      try { body[key] = JSON.parse(value); }
      catch { throw new CliError('INVALID_INPUT', `--${optionFlag(key)} expects a JSON ${field.type}.`, 2); }
    }
  }
  if (Buffer.byteLength(JSON.stringify(body)) > MAX_BODY_BYTES) throw new CliError('BODY_TOO_LARGE', 'Request bodies are limited to 1 MiB, including typed flags.', 2);
  if (hasSensitiveInput(body, op.body.properties) && (sources[0] !== '-' || Object.entries(op.body.properties).some(([key, field]) => options[optionKey(key)] !== undefined && hasSensitiveInput({ [key]: body[key] }, { [key]: field })))) throw new CliError('SECRET_STDIN_REQUIRED', 'Sensitive fields require piped JSON with --body - or --file -. Do not pass credentials through argv or plaintext body files.', 2);
  signal?.throwIfAborted();
  return body;
}
