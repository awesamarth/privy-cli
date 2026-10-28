import { chmod, lstat, mkdir, open, readFile, rename, rm, unlink } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import type { AsyncEntry } from '@napi-rs/keyring';
import { CliError } from './errors.ts';

export interface Credentials { accessToken: string; refreshToken: string; }
export interface SecretRef { appId: string; kind: string; id: string; }
export interface ProfileConfig { appId?: string; blockedAppIds: string[]; secretRefs?: SecretRef[]; }
export interface CredentialStore {
  load(): Promise<Credentials | null>;
  save(value: Credentials): Promise<void>;
  clear(): Promise<void>;
}

export function validateProfile(value: string): string {
  if (typeof value !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(value)) {
    throw new CliError('INVALID_PROFILE', 'Profile names must use 1–64 letters, numbers, underscores or hyphens.', 2);
  }
  return value;
}
export function validateId(value: string): string {
  if (typeof value !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(value)) throw new CliError('INVALID_ID', 'Invalid resource ID.', 2);
  return value;
}

export function validateSecretRef(value: unknown): SecretRef {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new CliError('INVALID_SECRET_REFERENCE', 'Expected an app-scoped secret reference.', 2);
  const ref = value as SecretRef;
  if (Object.keys(ref).some(k => !['appId', 'kind', 'id'].includes(k)) || typeof ref.kind !== 'string' || !/^[a-z][a-z0-9-]{0,31}$/.test(ref.kind)) throw new CliError('INVALID_SECRET_REFERENCE', 'Invalid secret kind or reference fields.', 2);
  return { appId: validateId(ref.appId), kind: ref.kind, id: validateId(ref.id) };
}

export class KeychainStore implements CredentialStore {
  private key: { service: string; name: string };
  constructor(profile: string) {
    this.key = { service: 'io.github.awesamarth.privy-cli', name: validateProfile(profile) };
  }
  // Lazy loading keeps help, schemas and offline previews usable without a keyring daemon.
  private async entry(): Promise<AsyncEntry> {
    const { AsyncEntry } = await import('@napi-rs/keyring');
    return new AsyncEntry(this.key.service, this.key.name, { linux: { store: 'secret-service' } });
  }
  async load(): Promise<Credentials | null> {
    let raw: string | null;
    try { raw = await (await this.entry()).getPassword(); }
    catch { throw new CliError('KEYCHAIN_UNAVAILABLE', 'Cannot read the OS credential store. Unlock your keychain/keyring and retry.'); }
    if (!raw) return null;
    try {
      const value = JSON.parse(raw);
      if (typeof value.accessToken !== 'string' || !value.accessToken || typeof value.refreshToken !== 'string' || !value.refreshToken) throw new Error();
      return { accessToken: value.accessToken, refreshToken: value.refreshToken };
    } catch { throw new CliError('INVALID_CREDENTIALS', 'Stored credentials are malformed. Run auth logout --local, then auth login.'); }
  }
  async save(value: Credentials): Promise<void> {
    try { await (await this.entry()).setPassword(JSON.stringify(value)); }
    catch { throw new CliError('KEYCHAIN_WRITE_FAILED', 'Cannot save credentials in the OS credential store. No plaintext fallback was written.'); }
  }
  async clear(): Promise<void> {
    try { await (await this.entry()).deleteCredential(); }
    catch { throw new CliError('KEYCHAIN_DELETE_FAILED', 'Cannot remove credentials from the OS credential store.'); }
  }
}

export class ProfileStore {
  readonly root: string;
  readonly profile: string;
  constructor(profile: string, root = join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'privy-cli')) {
    this.profile = validateProfile(profile);
    this.root = root;
  }
  private get file(): string { return join(this.root, `${this.profile}.json`); }
  async prepare(): Promise<void> {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    const stat = await lstat(this.root);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (process.getuid && stat.uid !== process.getuid())) {
      throw new CliError('UNSAFE_CONFIG_DIRECTORY', 'Config directory must be a real directory owned by the current user.');
    }
    await chmod(this.root, 0o700);
  }
  async load(): Promise<ProfileConfig> {
    try {
      const stat = await lstat(this.file);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new CliError('UNSAFE_CONFIG_FILE', 'Profile config must be a regular file, not a symlink.');
      const raw = JSON.parse(await readFile(this.file, 'utf8'));
      if (!Array.isArray(raw.blockedAppIds) || !raw.blockedAppIds.every((x: unknown) => typeof x === 'string')) throw new Error();
      raw.blockedAppIds.forEach(validateId);
      if (raw.appId !== undefined) validateId(raw.appId);
      if (raw.secretRefs !== undefined && (!Array.isArray(raw.secretRefs) || raw.secretRefs.length > 10000)) throw new Error();
      const secretRefs = raw.secretRefs?.map(validateSecretRef);
      return { appId: raw.appId, blockedAppIds: raw.blockedAppIds, ...(secretRefs?.length ? { secretRefs } : {}) };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { blockedAppIds: [] };
      if (error instanceof CliError) throw error;
      throw new CliError('INVALID_CONFIG', 'Profile config is invalid. Repair it before continuing; safety rules will not be ignored.');
    }
  }
  async save(value: ProfileConfig): Promise<void> {
    await this.prepare();
    const temp = `${this.file}.${randomUUID()}.tmp`;
    try {
      const file = await open(temp, 'wx', 0o600);
      try { await file.writeFile(JSON.stringify(value, null, 2) + '\n'); await file.sync(); } finally { await file.close(); }
      await rename(temp, this.file);
    } finally { await rm(temp, { force: true }); }
  }
  async locked<T>(fn: () => Promise<T>): Promise<T> {
    await this.prepare();
    const path = join(this.root, `${this.profile}.lock`);
    const deadline = Date.now() + 10_000;
    while (true) {
      try {
        const file = await open(path, 'wx', 0o600);
        try { await file.writeFile(JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() })); } finally { await file.close(); }
        break;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
        if (Date.now() >= deadline) throw new CliError('PROFILE_LOCKED', `Another command holds ${path}. If it crashed, verify the PID in that file is no longer running before removing the lock.`);
        await sleep(100);
      }
    }
    try { return await fn(); } finally { await unlink(path); }
  }
}
