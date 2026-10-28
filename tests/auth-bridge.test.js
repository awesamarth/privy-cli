import { expect, test } from 'bun:test';
import { startVerificationBridge } from '../research/browser-verification.mjs';

// Synthetic callback values only. These tests never load hCaptcha or call Privy.
function request(bridge, body, overrides = {}) {
  const url = new URL(bridge.url);
  return fetch(`${url.origin}/complete`, { method: 'POST',
    headers: { origin: url.origin, 'content-type': 'application/json', ...overrides },
    body: JSON.stringify({ state: url.pathname.slice(1), token: 'synthetic-test-value', ...body }),
  });
}

test('verification callback rejects foreign origins, hosts, states, oversized bodies and non-JSON', async () => {
  let calls = 0;
  const bridge = await startVerificationBridge({ siteKey: 'synthetic-public-key', onToken: async () => { calls++; } });
  try {
    expect(new URL(bridge.url).hostname).toBe('127.0.0.1');
    const page = await fetch(bridge.url);
    expect(page.headers.get('referrer-policy')).toBe('no-referrer');
    expect(page.headers.get('cache-control')).toBe('no-store');
    expect(page.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    expect((await request(bridge, {}, { origin: 'https://other.example' })).status).toBe(403);
    expect((await request(bridge, {}, { host: 'other.example' })).status).toBe(403);
    expect((await request(bridge, { state: 'wrong' })).status).toBe(403);
    expect((await request(bridge, {}, { 'content-type': 'text/plain' })).status).toBe(415);
    expect((await request(bridge, { token: 'x'.repeat(70_000) })).status).toBe(413);
    expect(calls).toBe(0);
  } finally { await bridge.close(); }
});

test('verification callback is single-use and never returns the challenge token', async () => {
  let calls = 0;
  const bridge = await startVerificationBridge({ siteKey: 'synthetic-public-key', onToken: async token => {
    calls++; expect(token).toBe('synthetic-test-value'); return { emailSent: true };
  } });
  try {
    const response = await request(bridge);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true, emailSent: true });
    expect(await bridge.done).toEqual({ ok: true, emailSent: true });
    expect((await request(bridge)).status).toBe(409);
    expect((await fetch(bridge.url)).status).toBe(410);
    expect(calls).toBe(1);
  } finally { await bridge.close(); }
});
