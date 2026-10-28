import { lstat, readFile, open, link, rename, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { CliError } from './errors.ts';
import { validateId, validateProfile } from './store.ts';

export const PROJECT_FILE = 'privy.json';
export interface ProjectConfig { version: 1; profile: string; appId: string; }
export interface ProjectContext { file: string; config: ProjectConfig; }

export function validateProject(value: unknown): ProjectConfig {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new CliError('INVALID_PROJECT', 'Expected a versioned Privy project object.', 2);
  const raw = value as Record<string, unknown>;
  if (Object.keys(raw).some(key => !['version', 'profile', 'appId'].includes(key)) || raw.version !== 1 ||
      typeof raw.profile !== 'string' || typeof raw.appId !== 'string') {
    throw new CliError('INVALID_PROJECT', 'privy.json must contain only version: 1, profile and appId. It cannot contain credentials or protection overrides.', 2);
  }
  return { version: 1, profile: validateProfile(raw.profile), appId: validateId(raw.appId) };
}

export async function findProject(start = process.cwd()): Promise<ProjectContext | undefined> {
  let directory = resolve(start);
  while (true) {
    const file = join(directory, PROJECT_FILE);
    try {
      const stat = await lstat(file);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 16 * 1024) throw new Error();
      const config = validateProject(JSON.parse(await readFile(file, 'utf8')));
      return { file, config };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw new CliError('INVALID_PROJECT', 'Cannot safely read privy.json. Repair it or pass --no-project to ignore directory context. Profile protection is never overridden.', 2);
      }
    }
    const parent = dirname(directory);
    if (parent === directory) return undefined;
    directory = parent;
  }
}

export function resolveProjectContext(options: {
  explicitProfile?: string; environmentProfile?: string; explicitApp?: string;
  project?: ProjectContext;
}) {
  const { project } = options;
  const profile = validateProfile(options.explicitProfile ?? options.environmentProfile ?? project?.config.profile ?? 'default');
  // A directory binding must not silently cross into a different credential profile.
  const applies = Boolean(project && project.config.profile === profile);
  return {
    profile,
    profileSource: options.explicitProfile !== undefined ? 'flag' : options.environmentProfile !== undefined ? 'environment' : project ? 'project' : 'default',
    appId: options.explicitApp ?? (applies ? project!.config.appId : undefined),
    appSource: options.explicitApp !== undefined ? 'flag' : applies ? 'project' : undefined,
    projectApplied: applies,
  };
}

export async function writeProject(config: ProjectConfig, directory = process.cwd(), overwrite = false): Promise<string> {
  const value = validateProject(config);
  const file = join(resolve(directory), PROJECT_FILE);
  try {
    const stat = await lstat(file);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new CliError('UNSAFE_PROJECT_FILE', 'Refusing to replace a non-regular privy.json file.', 2);
    if (!overwrite) throw new CliError('PROJECT_EXISTS', 'privy.json already exists. Inspect project show first; use --force with --yes to replace it.', 2);
  } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  const temp = `${file}.${randomUUID()}.tmp`;
  try {
    const handle = await open(temp, 'wx', 0o600);
    try { await handle.writeFile(JSON.stringify(value, null, 2) + '\n'); await handle.sync(); }
    finally { await handle.close(); }
    if (overwrite) await rename(temp, file);
    else {
      try { await link(temp, file); } // Exclusive creation, including against concurrent writers.
      catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new CliError('PROJECT_EXISTS', 'Another privy.json already exists; it was not replaced.', 2);
        throw error;
      }
    }
    return file;
  } finally { await rm(temp, { force: true }); }
}
