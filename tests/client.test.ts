import { expect, test } from 'bun:test';
import { DashboardClient, DASHBOARD_APP_ID, type Fetcher } from '../src/client.ts';
import type { CredentialStore, Credentials } from '../src/store.ts';

function token(exp = Date.now() / 1000 + 3600) {
  return `test.${Buffer.from(JSON.stringify({ iss: 'privy.io', aud: DASHBOARD_APP_ID, sub: 'test-user', exp })).toString('base64url')}.test`;
}
class MemoryStore implements CredentialStore {
  value: Credentials | null = { accessToken: token(), refreshToken: 'old-refresh' };
  async load() { return this.value; }
  async save(value: Credentials) { this.value = value; }
  async clear() { this.value = null; }
}
function setup(handler: Fetcher, store = new MemoryStore()) {
  const methods: string[] = [];
  const client = new DashboardClient(store, { blockedAppIds: ['protected'] }, async (url, init) => {
    methods.push(init.method!); return handler(url, init);
  });
  return { client, store, methods };
}

test('offline previews and protected targets never access credentials or network', async () => {
  const fail = async (): Promise<never> => { throw new Error('Must stay offline'); };
  const client = new DashboardClient({ load: fail, save: fail, clear: fail }, { blockedAppIds: ['protected'] }, fail);
  expect(client.preview('config.update', { appId: 'safe', body: { name: 'Demo' } }).body).toEqual({ name: 'Demo' });
  expect(() => client.preview('apps.delete', { appId: 'protected' })).toThrow('protected');
  expect(() => client.preview('policies.get', { appId: 'safe', params: { policy_id: '../other' } })).toThrow('Invalid resource ID');
  expect(() => client.preview('policies.create', { appId: 'protected', body: { name: 'Policy', chain_type: 'ethereum' } })).toThrow('protected');
  await expect(client.app('protected')).rejects.toMatchObject({ code: 'APP_PROTECTED' });
});

test('refresh persists rotated credentials before the following request', async () => {
  const store = new MemoryStore();
  store.value!.accessToken = token(1);
  const fresh = { accessToken: token(), refreshToken: 'rotated' };
  const { client, methods } = setup(async (url, init) => {
    if (url.endsWith('/sessions')) return Response.json({ session_update_action: 'set', token: fresh.accessToken, refresh_token: fresh.refreshToken });
    expect(store.value).toEqual(fresh);
    expect(new Headers(init.headers).get('authorization')).toBe(`Bearer ${fresh.accessToken}`);
    return Response.json({ data: [] });
  }, store);
  await client.teams();
  expect(methods).toEqual(['POST', 'GET']);
});

test('failed remote logout preserves credentials instead of claiming revocation', async () => {
  const { client, store } = setup(async () => Response.json({}, { status: 500 }));
  await expect(client.logout()).rejects.toMatchObject({ status: 500 });
  expect(store.value?.refreshToken).toBe('old-refresh');
});

test('production updates require opt-in, send only the patch, and verify read-back', async () => {
  const { client, methods } = setup(async (_url, init) => {
    if (init.method === 'POST') expect(JSON.parse(String(init.body))).toEqual({ name: 'New' });
    return Response.json({ env: 'prod', name: 'New' });
  });
  const input = { appId: 'safe', body: { name: 'New' } };
  await expect(client.execute('config.update', input)).rejects.toMatchObject({ code: 'PRODUCTION_CONFIRMATION_REQUIRED' });
  expect(methods).toEqual(['GET']);
  methods.length = 0;
  expect(await client.execute('config.update', input, { allowProduction: true })).toMatchObject({ verified: true });
  expect(methods).toEqual(['GET', 'POST', 'GET']);
});

test('deletion refuses a wrong name or non-development environment before writing', async () => {
  let env = 'dev';
  const { client, methods } = setup(async () => Response.json({ env, name: 'Disposable' }));
  await expect(client.execute('apps.delete', { appId: 'safe' }, { confirmName: 'Wrong' })).rejects.toMatchObject({ code: 'APP_NAME_MISMATCH' });
  env = 'prod';
  await expect(client.execute('apps.delete', { appId: 'safe' }, { confirmName: 'Disposable' })).rejects.toMatchObject({ code: 'APP_DELETE_DEV_ONLY' });
  expect(methods).toEqual(['GET', 'GET']);
});

test('deletion verifies absence in the same account and never retries a failed verification', async () => {
  let deleted = false, accountVisible = true;
  const { client, methods } = setup(async (url, init) => {
    if (init.method === 'DELETE') {
      expect(JSON.parse(String(init.body)).confirmation).toContain('this app safe and all its users');
      deleted = true; return new Response(null, { status: 204 });
    }
    if (url.endsWith('/teams')) return Response.json({ data: deleted && !accountVisible ? [] : [{ id: 'account', apps: deleted ? [] : [{ id: 'safe' }] }] });
    return Response.json({ env: 'dev', name: 'Disposable' });
  });
  expect(await client.execute('apps.delete', { appId: 'safe' }, { confirmName: 'Disposable' })).toMatchObject({ deleted: true, verified: true });
  deleted = false; accountVisible = false; methods.length = 0;
  await expect(client.execute('apps.delete', { appId: 'safe' }, { confirmName: 'Disposable' })).rejects.toMatchObject({ code: 'DELETE_VERIFY_FAILED' });
  expect(methods.filter(m => m === 'DELETE')).toHaveLength(1);
});

test('creation reads back the new app with explicit no-storage consent', async () => {
  const { client, methods } = setup(async (_url, init) => Response.json(init.method === 'POST'
    ? { app: { id: 'new-app' }, secret: 'do-not-print' } : { id: 'new-app', name: 'New', env: 'dev' }));
  const storage = { mode: 'none', stored: false, deliberatelyDiscarded: true, valuePrinted: false };
  expect(await client.createApp('account', 'New', { appSecretStorage: { mode: 'none', save: async () => storage } })).toEqual({ id: 'new-app', name: 'New', env: 'dev', verified: true, storage, valuePrinted: false });
  expect(methods).toEqual(['POST', 'GET']);
});

test('policy deletion checks ownership and name, sends the dashboard body, and cannot verify lost access', async () => {
  let owner: string | null = 'owner', deleted = false;
  const { client, methods } = setup(async (url, init) => {
    if (init.method === 'DELETE') {
      expect(JSON.parse(String(init.body))).toEqual({ name: 'Guard' });
      deleted = true; return Response.json({ success: true });
    }
    if (url.includes('/api/dashboard/')) return deleted ? Response.json({}, { status: 403 }) : Response.json({ id: 'safe', env: 'dev' });
    if (url.endsWith('/deletable')) return Response.json({ deletable: true });
    return deleted ? Response.json({}, { status: 404 }) : Response.json({ id: 'policy', name: 'Guard', rules: [], owner_id: owner });
  });
  const input = { appId: 'safe', params: { policy_id: 'policy' }, confirmName: 'Guard' };
  await expect(client.execute('policies.delete', input)).rejects.toMatchObject({ code: 'POLICY_OWNER_APPROVAL_REQUIRED' });
  owner = null;
  await expect(client.execute('policies.delete', { ...input, confirmName: 'Wrong' })).rejects.toMatchObject({ code: 'POLICY_NAME_MISMATCH' });
  expect(methods.every(m => m === 'GET')).toBe(true);
  await expect(client.execute('policies.delete', input)).rejects.toMatchObject({ code: 'POLICY_VERIFY_FAILED' });
  expect(methods.filter(m => m === 'DELETE')).toHaveLength(1);
});

test('pagination reports its cap and stops repeated cursors', async () => {
  const { client, methods } = setup(async () => Response.json({ data: [], next_cursor: 'next' }));
  expect(await client.execute('users.list', { appId: 'safe' }, { all: true, maxPages: 1 })).toMatchObject({ truncated: true, next_cursor: 'next', pages_read: 1 });
  methods.length = 0;
  await expect(client.execute('users.list', { appId: 'safe' }, { all: true })).rejects.toMatchObject({ code: 'PAGINATION_LOOP' });
  expect(methods).toHaveLength(2);
});
