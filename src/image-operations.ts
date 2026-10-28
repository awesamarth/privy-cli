import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { extname } from 'node:path';
import { createHash } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { isDeepStrictEqual } from 'node:util';
import { CliError } from './errors.ts';
import { validateId, type SecretRef } from './store.ts';
import type { JsonObject, Operation } from './operations.ts';

const MAX_IMAGE = 8 * 1024 * 1024;
export interface PreparedImage { data: Uint8Array; mediaType: string; bytes: number; sha256: string; }
export interface ImageReceipt { version: 1; appId: string; id: string; mediaType: string; bytes: number; sha256: string; previousIconHash: string; }
export function imageWorkflow(action: NonNullable<Operation['imageAction']>): JsonObject {
  const base = { action, publishing: 'No publishing, availability/permissions/signup, billing or login-branding changes', retries: 'No automatic write retries' };
  if (action === 'get') return { ...base, stages: ['Confirm app access', 'Read projected current icon URL and availability'], writesPerformed: false };
  if (action === 'status') return { ...base, stages: ['Load same app/profile OS-vault checkpoint', 'Confirm app access', 'Read upload readiness'], writesPerformed: false };
  const recovery = 'Pending status/finalize requires the same app/profile OS-vault checkpoint; refuse observed intervening logo changes; clear checkpoint after verified attachment';
  if (action === 'finalize') return { ...base, recovery, stages: ['Load checkpoint; check app environment', 'Recognize already-attached image without another write', 'Check current icon, readiness and unchanged controls', 'Recheck environment; PATCH images/upload once', 'Fresh icon/control read-back'], confirmation: '--yes; production also requires --allow-production' };
  return { ...base, recovery, file: { argument: 'image_file', formats: ['PNG', 'JPEG', 'WebP'], maxBytes: MAX_IMAGE, validation: 'Extension/signature, regular non-symlink file and stable bounded read; not full decoding', disclosure: 'Original bytes/metadata are sent to public image hosting' }, stages: ['Read current icon and controls', 'POST images/upload with JSON {}', 'Store app-bound OS-vault checkpoint without signed URL/file bytes', 'Credential-free multipart upload to approved HTTPS storage host; no redirects', 'At most five readiness polls', 'Unless --stage-only: fresh readiness/control/environment checks, PATCH once, fresh icon/control read-back'], optionalFlags: ['--stage-only'], confirmation: '--yes; production also requires --allow-production' };
}
const common = { scope: 'app' as const, keywords: ['image', 'logo', 'upload', 'ecosystem', 'cross-app', 'global-wallet'], evidence: 'actual Global wallet -> My app upload control and ecosystem images/upload handler; see management-map' };
const root = '/api/v1/apps/{app_id}';
export const imageOperations: Operation[] = [
  { ...common, id: 'global-wallet.logo.get', command: 'global-wallet logo get', method: 'GET', path: root + '/cross-app/configuration', imageAction: 'get', summary: 'Read the Global wallet connection logo; distinct from login branding logo_url.', response: 'Public icon URL and availability only. Does not publish the app or change permissions.', examples: ['privy global-wallet logo get'] },
  { ...common, id: 'global-wallet.logo.upload', command: 'global-wallet logo upload', method: 'POST', path: root + '/images/upload', imageAction: 'upload', body: { type: 'object', additionalProperties: false, properties: {} }, summary: 'Upload a local PNG/JPEG/WebP as the Global wallet logo (max 8 MiB; original bytes/metadata are sent to public image hosting).', response: 'Validate local file, allocate upload, OS-vault recovery checkpoint, credential-free multipart upload, at most five readiness polls plus fresh attach preflight, then attach and fresh read-back. Signed URL never printed/stored; no write retries. Does not publish the app.', examples: ['privy global-wallet logo upload ./logo.png --dry-run', 'privy global-wallet logo upload ./logo.png --yes'] },
  { ...common, id: 'global-wallet.logo.status', command: 'global-wallet logo status', method: 'GET', path: root + '/images/upload', params: ['upload_id'], queryFromParams: { uploadId: 'upload_id' }, query: { uploadId: { type: 'string', description: 'CLI-created upload ID, bound to the selected app by its OS-vault checkpoint.' } }, imageAction: 'status', summary: 'Check a pending CLI upload without exposing its signed URL or re-uploading bytes.', response: 'Readiness and safe file metadata; requires the same app/profile checkpoint.', examples: ['privy global-wallet logo status <upload-id>'] },
  { ...common, id: 'global-wallet.logo.finalize', command: 'global-wallet logo finalize', method: 'PATCH', path: root + '/images/upload', params: ['upload_id'], bodyFromParams: { upload_id: 'upload_id' }, body: { type: 'object', additionalProperties: false, required: ['upload_id'], properties: { upload_id: { type: 'string', description: 'Pending CLI upload ID from the OS-vault checkpoint.' } } }, imageAction: 'finalize', summary: 'Attach an already-complete pending upload; never repeat the file transfer; refuse observed intervening logo changes.', response: 'Same-app checkpoint/readiness and current-logo checks, one attach request, fresh icon and unchanged cross-app controls verification. Already-attached uploads are not attached again.', examples: ['privy global-wallet logo finalize <upload-id> --yes'] },
];
export function imageInfo(image: PreparedImage | ImageReceipt): JsonObject { return { bytes: image.bytes, mediaType: image.mediaType, sha256: image.sha256 }; }
const digest = (value: string | Uint8Array): string => createHash('sha256').update(value).digest('hex');
export async function readImage(path: string): Promise<PreparedImage> {
  let file;
  try {
    const before = await lstat(path);
    if (!before.isFile() || before.isSymbolicLink() || before.size < 12 || before.size > MAX_IMAGE) throw new CliError('INVALID_IMAGE_FILE', 'Use a non-symlink regular PNG/JPEG/WebP file, at most 8 MiB.', 2);
    file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    const start = await file.stat();
    if (!start.isFile() || start.ino !== before.ino || start.dev !== before.dev || start.size !== before.size) throw new CliError('IMAGE_FILE_CHANGED', 'Image changed during opening. No upload was attempted.', 2);
    const buffer = Buffer.alloc(start.size + 1); let used = 0;
    while (used < buffer.length) { const { bytesRead } = await file.read(buffer, used, buffer.length - used, used); if (!bytesRead) break; used += bytesRead; }
    const end = await file.stat();
    if (used !== start.size || end.size !== start.size || end.mtimeMs !== start.mtimeMs || end.ctimeMs !== start.ctimeMs) throw new CliError('IMAGE_FILE_CHANGED', 'Image changed while reading. No upload was attempted.', 2);
    const data = buffer.subarray(0, used), extension = extname(path).toLowerCase();
    const png = data.length >= 33 && data.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) && data.toString('ascii', 12, 16) === 'IHDR';
    const jpeg = data[0] === 255 && data[1] === 216 && data[2] === 255;
    const webp = data.toString('ascii', 0, 4) === 'RIFF' && data.toString('ascii', 8, 12) === 'WEBP' && data.readUInt32LE(4) + 8 === data.length;
    const mediaType = png && extension === '.png' ? 'image/png' : jpeg && ['.jpg', '.jpeg'].includes(extension) ? 'image/jpeg' : webp && extension === '.webp' ? 'image/webp' : null;
    if (!mediaType) throw new CliError('INVALID_IMAGE_FORMAT', 'Image extension and file signature must match PNG/JPEG/WebP. SVG and arbitrary files are refused.', 2);
    return { data, bytes: data.length, mediaType, sha256: digest(data) };
  } catch (error) { if (error instanceof CliError) throw error; throw new CliError('INVALID_IMAGE_FILE', 'Could not safely read the image file. No upload was attempted.', 2); }
  finally { await file?.close().catch(() => {}); }
}
export function imageState(value: any): JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !(value.icon_url === null || typeof value.icon_url === 'string') || typeof value.availability !== 'string' || typeof value.allowed_permissions !== 'string' || typeof value.signups_allowed !== 'boolean') throw new CliError('INVALID_IMAGE_STATE', 'Cannot establish current logo and cross-app controls. No default state was invented.');
  return value;
}
export function parseImageReceipt(raw: string | null, appId: string, id: string): ImageReceipt {
  try {
    if (!raw) throw new Error();
    const r = JSON.parse(raw);
    if (r.version !== 1 || r.appId !== appId || r.id !== id || !Number.isInteger(r.bytes) || r.bytes < 12 || r.bytes > MAX_IMAGE || !['image/png', 'image/jpeg', 'image/webp'].includes(r.mediaType) || !/^[a-f0-9]{64}$/.test(r.sha256) || !/^[a-f0-9]{64}$/.test(r.previousIconHash)) throw new Error();
    return { version: 1, appId, id: validateId(id), bytes: r.bytes, mediaType: r.mediaType, sha256: r.sha256, previousIconHash: r.previousIconHash };
  } catch { throw new CliError('UPLOAD_CHECKPOINT_REQUIRED', 'A matching CLI upload checkpoint is required in this app/profile OS vault. No arbitrary image ID will be attached.', 2); }
}
export function uploadComplete(value: any): boolean {
  if (!value || typeof value.complete !== 'boolean') throw new CliError('INVALID_UPLOAD_STATUS', 'Unexpected image upload status; completion was not assumed.');
  return value.complete;
}
function deliveryUrl(value: unknown, id: string): string {
  try {
    if (typeof value !== 'string') throw new Error();
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.hostname !== 'imagedelivery.net' || url.port || url.username || url.password || url.search || url.hash || !url.pathname.split('/').includes(id)) throw new Error();
    return value;
  } catch { throw new CliError('INVALID_IMAGE_DELIVERY', 'Expected an unsigned public image-delivery URL matching this upload ID.'); }
}
type Request = (path: string, method?: string, body?: JsonObject) => Promise<any>;
type Store = (ref: SecretRef, value: string) => Promise<JsonObject>;
export async function finalizeImage(appId: string, receipt: ImageReceipt, request: Request): Promise<JsonObject> {
  const root = `/api/v1/apps/${appId}`, before = imageState(await request(root + '/cross-app/configuration'));
  let attached = false;
  try { deliveryUrl(before.icon_url, receipt.id); attached = true; } catch {}
  if (attached) return { appId, uploadId: receipt.id, verified: true, alreadyAttached: true, writesPerformed: false, iconUrl: before.icon_url, file: imageInfo(receipt) };
  if (digest(before.icon_url ?? '') !== receipt.previousIconHash) throw new CliError('LOGO_CHANGED', 'Current logo changed since upload allocation. No overwrite was sent. Inspect the current logo before starting another upload.', 2);
  if (!uploadComplete(await request(root + '/images/upload?uploadId=' + receipt.id))) throw new CliError('UPLOAD_NOT_READY', 'Upload is not complete. Check status later; do not repeat the file transfer automatically.', 2);
  const latest = imageState(await request(root + '/cross-app/configuration'));
  if (['icon_url', 'availability', 'allowed_permissions', 'signups_allowed', 'custom_connect_url'].some(key => !isDeepStrictEqual(before[key], latest[key]))) throw new CliError('LOGO_CHANGED', 'Logo or cross-app controls changed during preflight. No attach request was sent.', 2);
  const result = await request(root + '/images/upload', 'PATCH', { upload_id: receipt.id });
  try {
    const expected = deliveryUrl(result?.delivery_url, receipt.id), after = imageState(await request(root + '/cross-app/configuration'));
    if (after.icon_url !== expected || ['availability', 'allowed_permissions', 'signups_allowed', 'custom_connect_url'].some(key => !isDeepStrictEqual(before[key], after[key]))) throw new Error();
    return { appId, uploadId: receipt.id, verified: true, iconUrl: after.icon_url, crossAppControlsUnchanged: true, publishedByThisCommand: false, file: imageInfo(receipt) };
  } catch { throw new CliError('IMAGE_VERIFY_FAILED', 'Attach was acknowledged but image/control read-back could not be verified. Inspect logo get/status; no write was repeated.'); }
}
export async function uploadImage(appId: string, image: PreparedImage, request: Request, fetcher: (url: string, init: RequestInit) => Promise<Response>, store: Store, signal?: AbortSignal, stageOnly = false): Promise<JsonObject> {
  const root = `/api/v1/apps/${appId}`;
  const before = imageState(await request(root + '/cross-app/configuration'));
  let id: string | undefined, checkpointStored = false, stage = 'allocate';
  try {
    const allocation = await request(root + '/images/upload', 'POST', {});
    id = validateId(allocation?.upload_id);
    const receipt: ImageReceipt = { version: 1, appId, id, bytes: image.bytes, mediaType: image.mediaType, sha256: image.sha256, previousIconHash: digest(before.icon_url ?? '') };
    stage = 'checkpoint';
    await store({ appId, kind: 'image-upload', id }, JSON.stringify(receipt)); checkpointStored = true;
    stage = 'transfer';
    let url: URL;
    try { url = new URL(allocation.upload_url); } catch { throw new CliError('INVALID_UPLOAD_DESTINATION', 'Privy returned an unusable upload destination. No file transfer was sent.'); }
    if (url.protocol !== 'https:' || url.hostname !== 'upload.imagedelivery.net' || url.port || url.username || url.password || url.hash) {
      throw new CliError('INVALID_UPLOAD_DESTINATION', 'Upload destination is outside the approved HTTPS image-upload host. No file transfer was sent.');
    }
    const form = new FormData();
    form.append('file', new Blob([new Uint8Array(image.data)], { type: image.mediaType }), 'logo.' + ({ 'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp' }[image.mediaType]));
    let response: Response;
    try { response = await fetcher(url.href, { method: 'POST', body: form, credentials: 'omit', redirect: 'error', signal: AbortSignal.any([AbortSignal.timeout(30000), ...(signal ? [signal] : [])]) }); }
    catch { throw new CliError('IMAGE_TRANSFER_UNCERTAIN', 'File transfer failed or timed out and may have reached storage. Inspect upload status; signed URL/body omitted and no retry occurred.'); }
    await response.body?.cancel().catch(() => {});
    if (!response.ok) throw new CliError('IMAGE_TRANSFER_FAILED', `Image storage returned HTTP ${response.status}. Inspect upload status; no response body or signed URL is exposed.`, 1, response.status);
    stage = 'readiness'; let ready = false;
    for (let attempt = 0; attempt < 5; attempt++) {
      if (uploadComplete(await request(root + '/images/upload?uploadId=' + id))) { ready = true; break; }
      if (attempt < 4) await sleep(1000, undefined, { signal });
    }
    if (!ready) throw new CliError('UPLOAD_NOT_READY', 'Image is not ready after five checks. Use logo status, then logo finalize when ready; no file transfer will be repeated.');
    if (stageOnly) return { appId, uploadId: id, storageReady: true, attached: false, verified: false, checkpointRetained: true, file: imageInfo(image), nextStep: 'Use logo status/finalize with this upload ID in the same app/profile. No file transfer needs repeating.' };
    stage = 'attach'; return await finalizeImage(appId, receipt, request);
  } catch (cause) {
    const error = cause instanceof CliError ? cause : new CliError('IMAGE_UPLOAD_INTERRUPTED', 'Image workflow stopped. Inspect remote state before a deliberate retry.');
    error.details = { ...error.details, appId, ...(id ? { uploadId: id } : {}), stage, checkpointConfirmed: checkpointStored, requestMayHaveMutated: true };
    throw error;
  }
}
