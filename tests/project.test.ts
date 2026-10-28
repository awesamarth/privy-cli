import { expect, test } from 'bun:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { resolveProjectContext, writeProject } from '../src/project.ts';
import { ProfileStore } from '../src/store.ts';

const binding = { version: 1 as const, profile: 'work', appId: 'sandbox-app' };
async function fixture(fn: (directory: string) => Promise<void>) {
  const directory = await mkdtemp(join(tmpdir(), 'privy-project-'));
  try { await fn(directory); } finally { await rm(directory, { recursive: true, force: true }); }
}
async function cli(directory: string, args: string[]) {
  const child = Bun.spawn([process.execPath, new URL('../src/cli.ts', import.meta.url).pathname, ...args], {
    cwd: directory, env: { ...process.env, PRIVY_PROFILE: '', XDG_CONFIG_HOME: join(directory, 'config') }, stdout: 'pipe', stderr: 'pipe',
  });
  const [stdout, stderr, exitCode] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
  return { stdout, stderr, exitCode };
}

test('explicit context wins and a project app cannot leak into a different profile', () => {
  const project = { file: '/repo/privy.json', config: binding };
  expect(resolveProjectContext({ project })).toMatchObject({ profile: 'work', appId: 'sandbox-app' });
  expect(resolveProjectContext({ project, explicitApp: 'override' }).appId).toBe('override');
  expect(resolveProjectContext({ project, environmentProfile: 'other' })).toMatchObject({ profile: 'other', appId: undefined });
  expect(resolveProjectContext({ project, environmentProfile: 'other', explicitProfile: 'work' }).profile).toBe('work');
});

test('project init requires confirmation and binds subsequent offline previews', () => fixture(async directory => {
  const args = ['--profile', 'work', '--app', 'sandbox-app', 'project', 'init'];
  expect(JSON.parse((await cli(directory, args)).stderr).error.code).toBe('CONFIRMATION_REQUIRED');
  expect((await cli(directory, [...args, '--yes'])).exitCode).toBe(0);
  const plan = await cli(directory, ['apps', 'get', '--dry-run']);
  expect(JSON.parse(plan.stdout).path).toBe('/api/dashboard/apps/sandbox-app');
  await expect(writeProject(binding, directory)).rejects.toMatchObject({ code: 'PROJECT_EXISTS' });
}));

test('directory context fails closed and cannot override profile protection', () => fixture(async directory => {
  await new ProfileStore('work', join(directory, 'config', 'privy-cli')).save({ blockedAppIds: ['sandbox-app'] });
  await writeProject(binding, directory);
  expect(JSON.parse((await cli(directory, ['apps', 'get', '--dry-run'])).stderr).error.code).toBe('APP_PROTECTED');
  await writeFile(join(directory, 'privy.json'), '{broken');
  expect(JSON.parse((await cli(directory, ['apps', 'get', '--dry-run'])).stderr).error.code).toBe('INVALID_PROJECT');
  const bypass = await cli(directory, ['--no-project', '--profile', 'work', '--app', 'sandbox-app', 'apps', 'get', '--dry-run']);
  expect(JSON.parse(bypass.stderr).error.code).toBe('APP_PROTECTED');
}));
