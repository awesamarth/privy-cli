import { expect, test } from 'bun:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

async function fixture(fn: (run: (args: string[]) => Promise<{ stdout: string; stderr: string; exitCode: number }>) => Promise<void>) {
  const root = await mkdtemp(join(tmpdir(), 'privy-cli-test-'));
  try {
    await fn(async args => {
      const child = Bun.spawn([process.execPath, new URL('../src/cli.ts', import.meta.url).pathname, '--no-project', '--profile', 'test', ...args], {
        cwd: root, env: { ...process.env, XDG_CONFIG_HOME: root }, stdout: 'pipe', stderr: 'pipe',
      });
      const [stdout, stderr, exitCode] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
      return { stdout, stderr, exitCode };
    });
  } finally { await rm(root, { recursive: true, force: true }); }
}

test('login describes code entry clearly and refuses noninteractive prompting', () => fixture(async run => {
  const help = await run(['auth', 'login', '--help']);
  expect(help.stdout).toContain('login code');
  expect(help.stdout).toContain('--no-open');
  const login = await run(['auth', 'login']);
  expect(login.exitCode).toBe(2);
  expect(JSON.parse(login.stderr).error.code).toBe('INTERACTIVE_REQUIRED');
}));

test('deletion previews offline but requires explicit target and confirmations to execute', () => fixture(async run => {
  const missing = await run(['apps', 'delete', '--dry-run']);
  expect(JSON.parse(missing.stderr).error.code).toBe('EXPLICIT_APP_REQUIRED');
  const preview = await run(['--app', 'safe', 'apps', 'delete', '--dry-run']);
  expect(preview.exitCode).toBe(0);
  expect(JSON.parse(preview.stdout)).toMatchObject({ method: 'DELETE', mutation: true });
  const noYes = await run(['--app', 'safe', 'apps', 'delete', '--confirm-name', 'Disposable']);
  expect(JSON.parse(noYes.stderr).error.code).toBe('CONFIRMATION_REQUIRED');
  const noName = await run(['--app', 'safe', 'apps', 'delete', '--yes']);
  expect(JSON.parse(noName.stderr).error.code).toBe('NAME_CONFIRMATION_REQUIRED');
  const policy = await run(['--app', 'safe', 'policies', 'delete', 'policy-id', '--confirm-name', 'Guard', '--dry-run']);
  expect(policy.exitCode).toBe(0);
  expect(JSON.parse(policy.stdout)).toMatchObject({ path: '/api/v1/apps/safe/policies/policy-id', body: { name: 'Guard' } });
}));
