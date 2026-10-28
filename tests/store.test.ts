import { expect, test } from 'bun:test';
import { lstat, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ProfileStore } from '../src/store.ts';
import { redact } from '../src/errors.ts';

async function fixture(fn: (store: ProfileStore) => Promise<void>) {
  const root = await mkdtemp(join(tmpdir(), 'privy-store-'));
  try { await fn(new ProfileStore('test', root)); }
  finally { await rm(root, { recursive: true, force: true }); }
}

test('profile safety config round-trips privately and fails closed if corrupted', () => fixture(async store => {
  await store.save({ appId: 'safe', blockedAppIds: ['protected'] });
  expect(await store.load()).toEqual({ appId: 'safe', blockedAppIds: ['protected'] });
  if (process.platform !== 'win32') expect((await lstat(join(store.root, 'test.json'))).mode & 0o777).toBe(0o600);
  await writeFile(join(store.root, 'test.json'), '{invalid');
  await expect(store.load()).rejects.toMatchObject({ code: 'INVALID_CONFIG' });
}));

test('profile lock prevents concurrent credential rotation and releases after failure', () => fixture(async store => {
  let entered!: () => void;
  const started = new Promise<void>(resolve => { entered = resolve; });
  const order: string[] = [];
  const first = store.locked(async () => { entered(); await Bun.sleep(50); order.push('first'); throw new Error('failed'); });
  const failure = expect(first).rejects.toThrow('failed');
  await started;
  const second = store.locked(async () => { order.push('second'); });
  await Promise.all([failure, second]);
  expect(order).toEqual(['first', 'second']);
}));

test('output redacts nested secrets without hiding public metadata', () => {
  expect(redact({ app_secret: 'a', nested: { refreshToken: 'b', verification_key: 'public' }, secretOmitted: true }))
    .toEqual({ app_secret: '[REDACTED]', nested: { refreshToken: '[REDACTED]', verification_key: 'public' }, secretOmitted: true });
});
