import { expect, test } from 'bun:test';
import { readBrowserCredentials } from '../src/browser.ts';

// Legacy CDP is opt-in. Retain its destination boundary, not an entire fake browser stack.
test('legacy session import rejects remote or credential-bearing debugging URLs', async () => {
  await expect(readBrowserCredentials('https://example.com')).rejects.toMatchObject({ code: 'INVALID_CDP_URL' });
  await expect(readBrowserCredentials('http://user:password@localhost')).rejects.toMatchObject({ code: 'INVALID_CDP_URL' });
});
