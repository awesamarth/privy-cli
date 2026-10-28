import { constants } from 'node:fs';
import { lstat, open, realpath, rename, link, unlink, mkdir, rm } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createInterface } from 'node:readline';
import { CliError } from './errors.ts';
import { validateSecretCommand } from './secrets.ts';
import type { SecretRef } from './store.ts';
import type { JsonObject } from './operations.ts';

const exec = promisify(execFile);
export type AppSecretMode = 'env' | 'keychain' | 'both' | 'none';
export interface AppSecretChoice { mode: AppSecretMode; file?: string; variable?: string; overwrite: boolean; }
export interface AppSecretSink { mode: AppSecretMode; save(ref: SecretRef, value: string): Promise<JsonObject>; }
const modes = ['env', 'keychain', 'both', 'none'];

async function ask(label: string, signal: AbortSignal): Promise<string> {
  signal.throwIfAborted();
  return new Promise((accept, reject) => {
    const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true, historySize: 0 });
    let done = false;
    const finish = (value?: string) => {
      if (done) return; done = true; signal.removeEventListener('abort', cancel); rl.close();
      if (value === undefined) reject(new CliError('CANCELLED', 'Storage selection cancelled. No remote write was sent.', 130));
      else accept(value.trim());
    };
    const cancel = () => finish();
    signal.addEventListener('abort', cancel, { once: true });
    rl.once('line', value => finish(value)); rl.once('close', cancel); rl.once('SIGINT', cancel);
    process.stderr.write(label); if (signal.aborted) cancel();
  });
}
export async function chooseAppSecretStorage(options: JsonObject, signal: AbortSignal): Promise<AppSecretChoice> {
  const interactive = !options.dryRun && options.yes && process.stdin.isTTY && process.stderr.isTTY;
  let mode = options.secretStore;
  if (mode === undefined && interactive) mode = await ask('App API secret storage (env / keychain / both / none): ', signal);
  if (!modes.includes(mode)) throw new CliError('APP_SECRET_STORAGE_REQUIRED', 'Choose --secret-store env|keychain|both|none before creation. Env/both also require --env-output. Nothing was created.', 2);
  const env = mode === 'env' || mode === 'both';
  if (!env && (options.envOutput !== undefined || options.envKey !== undefined || options.overwriteEnv)) throw new CliError('CONFLICTING_OPTIONS', 'Env options require --secret-store env or both.', 2);
  let file = options.envOutput;
  if (env && file === undefined && interactive) file = (await ask('Server env file (default .env.local): ', signal)) || '.env.local';
  if (env && (typeof file !== 'string' || !file || /[\x00-\x1f\x7f]/.test(file) || !/^\.?env(?:\.[A-Za-z0-9_-]+)*$/.test(basename(file)))) throw new CliError('ENV_FILE_REQUIRED', 'Pass --env-output pointing to .env, .env.local or another env file. Its parent directory must already exist.', 2);
  const variable = env ? options.envKey ?? 'PRIVY_APP_SECRET' : undefined;
  if (env) {
    validateSecretCommand(variable, ['server']);
    if (/^(NEXT_PUBLIC_|VITE_|PUBLIC_|NUXT_PUBLIC_|REACT_APP_|GATSBY_|EXPO_PUBLIC_)/i.test(variable)) throw new CliError('PUBLIC_SECRET_VARIABLE_REFUSED', 'App secrets require a server-only variable, never a frontend-public prefix.', 2);
  }
  return { mode, ...(env ? { file: resolve(file), variable } : {}), overwrite: Boolean(options.overwriteEnv) };
}
export function storagePreview(choice: AppSecretChoice): JsonObject {
  return { mode: choice.mode, ...(choice.file ? { file: choice.file, variable: choice.variable, overwriteExistingVariable: choice.overwrite, checks: 'Execution checks ownership, symlinks, Git tracking/ignore status and existing assignments before the remote write.' } : {}), valuePrinted: false, loginStorageUnchanged: true };
}

async function checkParents(file: string): Promise<void> {
  let path = dirname(file);
  for (;;) {
    const stat = await lstat(path);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new CliError('UNSAFE_ENV_PATH', 'Env file parents must be real directories, not symlinks.', 2);
    if ((stat.mode & 0o022) !== 0 && (stat.mode & 0o1000) === 0) throw new CliError('UNSAFE_ENV_PATH', 'Env file ancestors must not be writable by other users.', 2);
    if (path === dirname(file) && process.getuid && stat.uid !== process.getuid()) throw new CliError('UNSAFE_ENV_PATH', 'The env file parent must belong to the current user.', 2);
    const parent = dirname(path); if (parent === path) break; path = parent;
  }
  if (await realpath(dirname(file)) !== dirname(file)) throw new CliError('UNSAFE_ENV_PATH', 'Use the canonical env file directory, without symlink components.', 2);
}
async function gitProtection(file: string): Promise<string> {
  const opts = { cwd: dirname(file), timeout: 5000, maxBuffer: 65536, env: Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_'))) };
  try { await exec('git', ['rev-parse', '--show-toplevel'], opts); }
  catch (error) {
    // Outside a worktree is allowed, but does not claim future Git protection.
    const stderr = (error as { stderr?: string }).stderr ?? '';
    if ((error as { code?: unknown }).code === 128 && stderr.includes('not a git repository')) return 'not-a-git-worktree; ignore this file before initializing Git';
    throw new CliError('ENV_GIT_CHECK_FAILED', 'Could not establish Git protection. Install/fix git before saving an app secret to a file.', 2);
  }
  try {
    const tracked = await exec('git', ['ls-files', '-z', '--', basename(file)], opts);
    if (tracked.stdout.length) throw new CliError('ENV_FILE_TRACKED', 'The env file is tracked by Git. Choose a different untracked, ignored file.', 2);
    await exec('git', ['check-ignore', '--quiet', '--', basename(file)], opts);
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError('ENV_FILE_NOT_IGNORED', 'Add this env file to .gitignore before creating the app/credential. No remote write was sent during preflight.', 2);
  }
  return 'untracked-and-ignored';
}
type Snapshot = { bytes: Buffer; dev: number; ino: number; mode: number; mtime: number } | null;
async function snapshot(file: string): Promise<Snapshot> {
  let handle;
  try {
    const entry = await lstat(file);
    if (entry.isSymbolicLink() || !entry.isFile()) throw new Error('unsafe entry');
    handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const opened = await handle.stat();
    if (opened.dev !== entry.dev || opened.ino !== entry.ino) { await handle.close(); throw new Error('changed entry'); }
  }
  catch (error) { await handle?.close().catch(() => {}); if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null; throw new CliError('UNSAFE_ENV_FILE', 'Cannot safely open the env file. Symlinks are refused.', 2); }
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > 1024 * 1024 || process.getuid && stat.uid !== process.getuid()) throw new CliError('UNSAFE_ENV_FILE', 'Env file must be an owned regular file, not hard-linked, and at most 1 MiB.', 2);
    const bytes = await handle.readFile();
    if (bytes.length > 1024 * 1024) throw new CliError('UNSAFE_ENV_FILE', 'Env file exceeds the 1 MiB limit.', 2);
    return { bytes, dev: stat.dev, ino: stat.ino, mode: stat.mode, mtime: stat.mtimeMs };
  } finally { await handle.close(); }
}
function same(a: Snapshot, b: Snapshot): boolean { return a === null || b === null ? a === b : a.dev === b.dev && a.ino === b.ino && a.mode === b.mode && a.mtime === b.mtime && a.bytes.equals(b.bytes); }
function envContents(bytes: Buffer, variable: string, overwrite: boolean, value: string): string {
  const text = bytes.toString('utf8');
  if (!Buffer.from(text).equals(bytes) || text.includes('\0')) throw new CliError('ENV_FORMAT_UNSUPPORTED', 'Env file must be UTF-8 text without NUL bytes.', 2);
  const lines = text.match(/[^\r\n]*(?:\r\n|\n|\r|$)/g)!.filter(Boolean);
  let found = false;
  const output = lines.map(line => {
    const ending = line.match(/(?:\r\n|\n|\r)$/)?.[0] ?? '', content = line.slice(0, line.length - ending.length);
    if (/^\s*(?:#.*)?$/.test(content)) return line;
    const match = content.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!match) throw new CliError('ENV_FORMAT_UNSUPPORTED', 'Env file contains unsupported syntax. Multiline values and shell commands are refused; use a dedicated env file.', 2);
    const rhs = match[2];
    if (/^["'`]/.test(rhs) && !/^(?:"(?:[^"\\]|\\.)*"|'[^']*'|`[^`]*`)\s*(?:#.*)?$/.test(rhs)) throw new CliError('ENV_FORMAT_UNSUPPORTED', 'Multiline/ambiguous env values are refused. Use a dedicated env file.', 2);
    if (match[1] !== variable) return line;
    if (found) throw new CliError('ENV_DUPLICATE_VARIABLE', 'The target variable appears more than once. Resolve it before creation.', 2);
    found = true;
    if (!overwrite) throw new CliError('ENV_VARIABLE_EXISTS', 'The target variable already exists. Inspect it privately, then explicitly use --overwrite-env or choose another file/key.', 2);
    return `${variable}='${value}'${ending}`;
  }).join('');
  if (found) return output;
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  return output + (output && !/[\r\n]$/.test(output) ? eol : '') + `${variable}='${value}'${eol}`;
}

/** Reserve and inspect local destinations before any remote creation. No raw values escape this sink. */
export async function prepareAppSecretStorage(choice: AppSecretChoice, vault: (ref: SecretRef, value: string) => Promise<JsonObject>): Promise<{ sink: AppSecretSink; close(): Promise<void> }> {
  let original: Snapshot = null, lock: Awaited<ReturnType<typeof open>> | undefined, protection: string | undefined;
  const file = choice.file;
  const lockPath = file ? file + '.privy-lock' : undefined;
  try {
    if (file) {
      await checkParents(file);
      lock = await open(lockPath!, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
      protection = await gitProtection(file); original = await snapshot(file);
      envContents(original?.bytes ?? Buffer.alloc(0), choice.variable!, choice.overwrite, 'PREFLIGHT');
    }
  } catch (error) {
    if (lock) { await lock.close(); await unlink(lockPath!).catch(() => {}); }
    if (error instanceof CliError) throw error;
    throw new CliError('APP_SECRET_PREFLIGHT_FAILED', 'Could not prepare the destination. Check directory permissions or an existing .privy-lock; do not remove an active writer lock. No remote write was sent.', 2);
  }
  return {
    close: async () => { if (lock) { await lock.close(); await unlink(lockPath!).catch(() => {}); lock = undefined; } },
    sink: { mode: choice.mode, save: async (ref, value) => {
      const destinations: JsonObject[] = [];
      if (choice.mode === 'none') return { mode: 'none', stored: false, deliberatelyDiscarded: true, valuePrinted: false };
      try {
        if (typeof value !== 'string' || !value || value.includes('\0') || Buffer.byteLength(value) > 65536) throw new CliError('INVALID_APP_SECRET', 'Creation did not return a supported nonempty app secret.');
        if (choice.mode === 'keychain' || choice.mode === 'both') {
          const state: JsonObject = { destination: 'keychain', status: 'attempted', reference: ref }; destinations.push(state);
          await vault(ref, value); state.status = 'saved-and-verified';
        }
        if (file) {
          const state: JsonObject = { destination: 'env', status: 'attempted', file, variable: choice.variable }; destinations.push(state);
          if (!/^[A-Za-z0-9_+./:=~\-]+$/.test(value)) throw new CliError('ENV_SECRET_FORMAT_UNSUPPORTED', 'The generated value is not safe for literal dotenv storage. No value was printed.');
          await checkParents(file); protection = await gitProtection(file);
          if (!same(original, await snapshot(file))) throw new CliError('ENV_FILE_CHANGED', 'Env file changed after preflight; it was not overwritten.');
          const contents = envContents(original?.bytes ?? Buffer.alloc(0), choice.variable!, choice.overwrite, value);
          // Same-filesystem atomic installation. Private staging is ignored even if the process crashes.
          const staging = join(dirname(file), `.privy-secret-${randomUUID()}`);
          await mkdir(staging, { mode: 0o700 });
          try {
            const ignore = await open(join(staging, '.gitignore'), 'wx', 0o600); try { await ignore.writeFile('*\n'); } finally { await ignore.close(); }
            const temp = join(staging, 'value'); const handle = await open(temp, 'wx', 0o600);
            try { await handle.writeFile(contents); await handle.sync(); } finally { await handle.close(); }
            await checkParents(file); await gitProtection(file);
            if (!same(original, await snapshot(file))) throw new CliError('ENV_FILE_CHANGED', 'Env file changed during storage; it was not overwritten.');
            if (original) await rename(temp, file); else { await link(temp, file); await unlink(temp); }
            state.status = 'written';
            const after = await snapshot(file);
            if (!after || !after.bytes.equals(Buffer.from(contents)) || (after.mode & 0o777) !== 0o600) throw new CliError('ENV_VERIFY_FAILED', 'Env file read-back or permissions differed. Inspect privately; no retry was attempted.');
            state.status = 'saved-and-verified'; state.gitProtection = protection;
          } finally { await rm(staging, { recursive: true, force: true }); }
        }
        return { mode: choice.mode, stored: true, destinations, valuePrinted: false };
      } catch (cause) {
        const error = new CliError('APP_SECRET_CAPTURE_FAILED', 'Remote creation succeeded, but local storage did not complete. Inspect the reported destinations and remote resource before any retry. No rollback or automatic recreation occurred.');
        error.details = { reference: ref, remoteCreated: true, destinations, reason: cause instanceof CliError ? cause.code : 'LOCAL_STORAGE_FAILED', valuePrinted: false };
        throw error;
      }
    } },
  };
}
