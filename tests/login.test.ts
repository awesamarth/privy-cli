import { expect, test } from 'bun:test';
import { emailLogin, type EmailLoginOptions } from '../src/login.ts';
import { DashboardClient, DASHBOARD_APP_ID, ORIGIN, type Fetcher } from '../src/client.ts';
import { CliError } from '../src/errors.ts';
import type { Credentials } from '../src/store.ts';

function setup(failAt?: 'email' | 'save') {
  const paths: string[] = [], logs: string[] = [], prompts: string[] = [];
  let stored: Credentials | null = null;
  const store = {
    load: async () => stored,
    save: async (value: Credentials) => {
      if (failAt === 'save') throw new CliError('KEYCHAIN_WRITE_FAILED', 'Cannot save credentials.');
      stored = value;
    },
    clear: async () => { stored = null; },
  };
  const token = `test.${Buffer.from(JSON.stringify({ iss: 'privy.io', aud: DASHBOARD_APP_ID, sub: 'synthetic-user', exp: Date.now() / 1000 + 3600 })).toString('base64url')}.test`;
  const fetcher: Fetcher = async (url, init) => {
    expect(new URL(url).origin).toBe(ORIGIN);
    expect(init.redirect).toBe('error');
    const path = new URL(url).pathname; paths.push(path);
    if (path.endsWith(DASHBOARD_APP_ID)) return Response.json({ data_classification: 'public', enabled_captcha_provider: 'hcaptcha', captcha_site_key: 'synthetic-key' });
    if (path.endsWith('/init')) return failAt === 'email'
      ? Response.json({ error: 'private response' }, { status: 429, headers: { 'retry-after': '45' } }) : Response.json({ success: true });
    if (path.endsWith('/authenticate')) {
      expect(JSON.parse(String(init.body))).toEqual({ email: 'dev@example.com', code: '123456', mode: 'no-signup' });
      return Response.json({ token, refresh_token: 'synthetic-refresh', session_update_action: 'set', is_new_user: false });
    }
    if (path === '/api/v1/teams') return Response.json({ data: [] });
    if (path.endsWith('/logout')) return Response.json({ success: true });
    throw new Error('Unexpected mocked request');
  };
  const options: EmailLoginOptions = {
    timeoutSeconds: 5, fetcher, log: message => logs.push(message),
    prompt: async field => { prompts.push(field); return field === 'email' ? 'dev@example.com' : '123456'; },
    openBrowser: async url => {
      const target = new URL(url);
      expect(await (await fetch(url)).text()).toContain('enter that code only in your terminal');
      await fetch(`${target.origin}/complete`, { method: 'POST',
        headers: { origin: target.origin, 'content-type': 'application/json' },
        body: JSON.stringify({ state: target.pathname.slice(1), token: 'synthetic-challenge' }),
      });
    },
    validate: (value, signal) => new DashboardClient(store, { blockedAppIds: [] }, fetcher, signal).validateLogin(value),
    save: store.save,
  };
  return { options, paths, logs, prompts, stored: () => stored };
}

test('login composes browser verification, code exchange, remote validation and secure persistence', async () => {
  const run = setup();
  await emailLogin(run.options);
  expect(run.paths).toEqual([`/api/v1/apps/${DASHBOARD_APP_ID}`, '/api/v1/passwordless/init', '/api/v1/passwordless/authenticate', '/api/v1/teams']);
  expect(run.prompts).toEqual(['email', 'code']);
  expect(run.stored()?.refreshToken).toBe('synthetic-refresh');
  expect(run.logs.join('\n')).not.toMatch(/123456|synthetic-refresh|synthetic-challenge/);
});

test('email rejection exposes safe retry guidance without retrying or prompting for a code', async () => {
  const run = setup('email');
  await expect(emailLogin(run.options)).rejects.toMatchObject({ code: 'AUTH_REJECTED', status: 429, retryAfterSeconds: 45 });
  expect(run.paths.filter(path => path.endsWith('/init'))).toHaveLength(1);
  expect(run.prompts).toEqual(['email']);
  expect(run.stored()).toBeNull();
  expect(run.logs.join('\n')).not.toContain('private response');
});

test('credential-store failure revokes only the new unsaved session', async () => {
  const run = setup('save');
  await expect(emailLogin(run.options)).rejects.toMatchObject({ code: 'KEYCHAIN_WRITE_FAILED' });
  expect(run.stored()).toBeNull();
  expect(run.paths.at(-1)).toBe('/api/v1/sessions/logout');
});

test('cancelling browser verification closes the listener without requesting an email', async () => {
  const run = setup(), controller = new AbortController();
  let url = '';
  await expect(emailLogin({ ...run.options, signal: controller.signal,
    openBrowser: async value => { url = value; controller.abort(); },
  })).rejects.toMatchObject({ code: 'CANCELLED' });
  await expect(fetch(url)).rejects.toThrow();
  expect(run.paths).toHaveLength(1);
  expect(run.stored()).toBeNull();
});
