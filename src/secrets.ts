import { spawn } from 'node:child_process';
import type { AsyncEntry } from '@napi-rs/keyring';
import { CliError } from './errors.ts';
import { validateProfile, validateSecretRef, type SecretRef } from './store.ts';

/** Values live only in OS credential storage; profile JSON indexes nonsecret references. */
export class ResourceSecretStore {
  private profile: string;
  constructor(profile: string) { this.profile = validateProfile(profile); }
  private async entry(value: SecretRef): Promise<AsyncEntry> {
    const ref = validateSecretRef(value);
    const { AsyncEntry } = await import('@napi-rs/keyring');
    return new AsyncEntry('io.github.awesamarth.privy-cli.resources', `${this.profile}:${ref.appId}:${ref.kind}:${ref.id}`, { linux: { store: 'secret-service' } });
  }
  async load(ref: SecretRef): Promise<string | null> {
    try { return await (await this.entry(ref)).getPassword(); }
    catch { throw new CliError('KEYCHAIN_UNAVAILABLE', 'Cannot read the resource secret from OS credential storage. No plaintext fallback is used.'); }
  }
  async save(ref: SecretRef, value: string): Promise<void> {
    if (typeof value !== 'string' || !value.length || value.includes('\0') || Buffer.byteLength(value) > 65536) throw new CliError('INVALID_SECRET', 'Secret is empty, malformed or exceeds the storage bound. No value was printed.');
    try { await (await this.entry(ref)).setPassword(value); }
    catch { throw new CliError('KEYCHAIN_WRITE_FAILED', 'Cannot save the resource secret in OS credential storage. No plaintext fallback was written.'); }
    if (await this.load(ref) !== value) throw new CliError('SECRET_VERIFY_FAILED', 'OS credential-store read-back did not match. Inspect the secret reference; no value was printed.');
  }
  async clear(ref: SecretRef): Promise<void> {
    try { await (await this.entry(ref)).deleteCredential(); }
    catch { throw new CliError('KEYCHAIN_DELETE_FAILED', 'Cannot remove the resource secret from OS credential storage.'); }
  }
}
export function sameSecretRef(a: SecretRef, b: SecretRef): boolean { return a.appId === b.appId && a.kind === b.kind && a.id === b.id; }

export function validateSecretCommand(variable: string, args: string[]): void {
  if (typeof variable !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(variable) || /^(PATH|HOME|SHELL|NODE_OPTIONS|NODE_PATH|LD_.*|DYLD_.*)$/i.test(variable)) throw new CliError('INVALID_ENVIRONMENT_VARIABLE', 'Choose a normal application secret variable, not a process/loader configuration variable.', 2);
  if (!args.length || !args[0] || args.some(a => a.includes('\0'))) throw new CliError('COMMAND_REQUIRED', 'Pass a trusted program and arguments after --.', 2);
}
/** Explicit secret handoff: no shell and no injected value in argv. The trusted child owns its I/O. */
export async function runWithSecret(value: string, variable: string, args: string[], signal: AbortSignal): Promise<number> {
  validateSecretCommand(variable, args);
  return new Promise((resolve, reject) => {
    const child = spawn(args[0], args.slice(1), { env: { ...process.env, [variable]: value }, stdio: 'inherit', signal });
    child.once('error', () => reject(new CliError('SECRET_COMMAND_FAILED', 'Could not start the requested program. No secret value was printed by the CLI.')));
    child.once('close', (code, killedBy) => resolve(code ?? (killedBy === 'SIGINT' ? 130 : 1)));
  });
}
