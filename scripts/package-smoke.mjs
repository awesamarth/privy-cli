// Build and install the real tarball without Bun on PATH. Never calls Privy or reads real credentials.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

if (process.platform === 'win32') throw new Error('This isolated-PATH smoke runner currently supports macOS/Linux only. Windows packaging needs a separate live pass.');
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const work = mkdtempSync(join(tmpdir(), 'privy-cli-package-'));
const npmCli = join(dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js');
const execute = (exe, args, options = {}) => {
  const result = spawnSync(exe, args, { cwd: root, encoding: 'utf8', timeout: 120_000, ...options });
  if (result.status !== 0) throw new Error(`Command failed: ${exe} ${args.join(' ')}\n${result.error?.message || ''}\n${result.stderr || ''}`);
  return result.stdout;
};
try {
  execute(process.execPath, ['scripts/build.mjs']);
  const packed = JSON.parse(execute(process.execPath, [npmCli, 'pack', '--json', '--ignore-scripts', '--pack-destination', work]))[0];
  for (const entry of packed.files) {
    assert(entry.path === 'package.json' || entry.path === 'README.md' || entry.path.startsWith('dist/'), `Unwanted packaged file: ${entry.path}`);
    if (entry.path.endsWith('.js')) assert(!/\bBun\./.test(readFileSync(join(root, entry.path), 'utf8')), `Bun runtime reference in ${entry.path}`);
  }
  const archive = join(work, packed.filename);
  const bin = join(work, 'bin'); mkdirSync(bin);
  symlinkSync(process.execPath, join(bin, 'node'));
  const home = join(work, 'home'); mkdirSync(home);
  const env = { ...process.env, PATH: `${bin}:/usr/bin:/bin`, HOME: home, XDG_CONFIG_HOME: join(home, '.config'), PRIVY_PROFILE: `smoke-${Date.now()}`, NODE_OPTIONS: '' };
  assert.equal(spawnSync('bun', ['--version'], { env, encoding: 'utf8' }).error?.code, 'ENOENT');
  const tools = join(work, 'tools'); mkdirSync(tools);
  execute(process.execPath, [npmCli, 'install', '--prefix', tools, '--ignore-scripts', '--no-audit', '--no-fund', 'pnpm@10'], { env });
  const managers = [
    ['npm', [npmCli, 'install', '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund', archive]],
    ['pnpm', [join(tools, 'node_modules/pnpm/bin/pnpm.cjs'), 'add', '--prod', '--ignore-scripts', '--store-dir', join(work, 'pnpm-store'), archive]],
  ];
  for (const [name, args] of managers) {
    const cwd = join(work, name); mkdirSync(cwd);
    writeFileSync(join(cwd, 'package.json'), JSON.stringify({ name: 'package-smoke', private: true }));
    execute(process.execPath, args, { cwd, env });
    const command = join(cwd, 'node_modules/.bin/privy');
    const run = (args, input) => execute(command, args, { cwd, env, input });
    assert.match(run(['--help']), /Unofficial/);
    assert.match(run(['auth', 'login', '--help']), /--no-open/);
    const noninteractive = spawnSync(command, ['auth', 'login'], { cwd, env, encoding: 'utf8' });
    assert.equal(noninteractive.status, 2);
    assert.equal(JSON.parse(noninteractive.stderr).error.code, 'INTERACTIVE_REQUIRED');
    const schema = JSON.parse(run(['schema', 'apps', 'config', 'update']));
    assert.equal(schema.httpMethod, 'POST');
    assert.equal(schema.requestBody.properties.email_auth.type, 'boolean');
    const preview = JSON.parse(run(['--app', 'safe-app', 'apps', 'config', 'update', '--body', '-', '--dry-run'], '{"name":"Smoke"}'));
    assert.equal(preview.method, 'POST'); assert.equal(preview.body.name, 'Smoke');
    assert.equal(preview.url, 'https://dashboard.privy.io/api/v1/apps/safe-app');
    const search = JSON.parse(run(['cli', 'search', 'update app configuration']));
    assert.equal(search[0].command, 'privy apps config update');
    const deletion = JSON.parse(run(['--app', 'disposable-app', 'apps', 'delete', '--dry-run']));
    assert.equal(deletion.method, 'DELETE');
    assert.match(deletion.body.confirmation, /this app disposable-app and all its users/);
    const rule = JSON.parse(run(['--app', 'safe-app', 'policies', 'rules', 'update', 'policy-one', 'rule-one', '--body', '-', '--dry-run'], JSON.stringify({ name: 'Smoke rule', method: 'eth_sendTransaction', action: 'DENY', conditions: [] })));
    assert.equal(rule.method, 'PATCH');
    assert.equal(rule.path, '/api/v1/apps/safe-app/policies/policy-one/rules/rule-one');
    run(['--app', 'safe-app', 'project', 'init', '--yes']);
    const context = JSON.parse(run(['project', 'show']));
    assert.equal(context.appId, 'safe-app'); assert.equal(context.appSource, 'project');
    const bound = JSON.parse(run(['apps', 'get', '--dry-run']));
    assert.equal(bound.path, '/api/dashboard/apps/safe-app');
    run(['apps', 'protect', 'protected-app']);
    const blocked = spawnSync(command, ['--app', 'protected-app', 'apps', 'get', '--dry-run'], { cwd, env, encoding: 'utf8' });
    assert.equal(blocked.status, 2); assert.equal(JSON.parse(blocked.stderr).error.code, 'APP_PROTECTED');
    // Optional native dependency must be installed, even with install scripts disabled.
    execute(process.execPath, ['--input-type=module', '-e', 'const m=await import("@napi-rs/keyring"); if(typeof m.AsyncEntry!=="function")process.exit(1)'], { cwd: join(cwd, 'node_modules/@awesamarth/privy-cli'), env });
    console.log(`${name}: packed CLI works under ${process.version}, no Bun, install scripts disabled, native binding loads.`);
  }
  console.log(`Tarball: ${packed.files.length} files, ${packed.size} bytes compressed, ${packed.unpackedSize} bytes unpacked. No tests/research/browser/runtime bundled.`);
} finally { rmSync(work, { recursive: true, force: true }); }
