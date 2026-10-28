import { open, unlink } from 'node:fs/promises';
import { resolve } from 'node:path';
import { CliError } from './errors.ts';

// Measured wallet exports use Google Cloud Storage signed URLs. Approve its HTTPS
// storage namespace, not arbitrary API-supplied hosts or user-configurable destinations.
const EXPORT_HOSTS = new Set(['storage.googleapis.com']);
export async function readSignedExport(value: unknown, expectedBytes: number, fetcher: (url: string, init: RequestInit) => Promise<Response>, signal?: AbortSignal): Promise<string> {
  let url: URL;
  try { if (typeof value !== 'string') throw new Error(); url = new URL(value); }
  catch { throw new CliError('INVALID_EXPORT_URL', 'Export service did not return a valid signed URL. No URL was printed.'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.port && url.port !== '443') throw new CliError('INVALID_EXPORT_URL', 'Export storage URL failed security checks. No external request was sent.');
  if (!EXPORT_HOSTS.has(url.hostname) && !url.hostname.endsWith('.storage.googleapis.com')) throw new CliError('UNVERIFIED_EXPORT_HOST', `Export storage host has not been verified: ${url.hostname}. No external request was sent; the signed URL was not printed.`);
  try {
    const response = await fetcher(url.href, { method: 'GET', headers: { accept: 'text/csv, application/octet-stream' }, credentials: 'omit', redirect: 'error', signal: AbortSignal.any([AbortSignal.timeout(20_000), ...(signal ? [signal] : [])]) });
    if (!response.ok || response.headers.get('content-type')?.includes('application/json')) { await response.body?.cancel(); throw new Error(); }
    const reader = response.body?.getReader(); if (!reader) throw new Error();
    const chunks: Uint8Array[] = []; let bytes = 0;
    try {
      while (true) {
        const part = await reader.read(); if (part.done) break;
        bytes += part.value.byteLength;
        if (bytes > 64 * 1024 * 1024 || bytes > expectedBytes) { await reader.cancel(); throw new Error(); }
        chunks.push(part.value);
      }
    } finally { reader.releaseLock(); }
    if (bytes !== expectedBytes) throw new Error();
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(Buffer.concat(chunks));
    if (!text || /^\s*</.test(text) || Buffer.byteLength(text) !== bytes) throw new Error();
    return text;
  } catch { throw new CliError('EXPORT_DOWNLOAD_FAILED', 'Could not download and verify the CSV. The signed URL was not printed; dashboard credentials were not sent to storage. No partial file was retained.'); }
}

// Reserve before contacting Privy; never overwrite a file or follow an existing symlink.
export async function downloadToFile(path: string, fetchText: () => Promise<string>): Promise<{ file: string; bytes: number }> {
  const file = resolve(path);
  let handle;
  try { handle = await open(file, 'wx', 0o600); }
  catch { throw new CliError('OUTPUT_UNAVAILABLE', 'Cannot create output file. Choose a new path in an existing directory; files are never overwritten.', 2); }
  let complete = false;
  try {
    const text = await fetchText();
    if (typeof text !== 'string') throw new CliError('INVALID_RESPONSE', 'Export did not return text. No data was saved.');
    await handle.writeFile(text, 'utf8'); await handle.sync();
    complete = true;
    return { file, bytes: Buffer.byteLength(text) };
  } finally {
    await handle.close();
    if (!complete) await unlink(file).catch(() => {});
  }
}
