// After a deploy, tell IndexNow search engines (Bing, Yandex, Seznam, Naver...) which URLs exist.
// The key is public by design: it's served at /091b9f3e776a1d421815789cd0b7d44b.txt so engines can verify site ownership.
import { readFile } from 'node:fs/promises';

const host = 'privy-cli.awesamarth.dev';
const key = '091b9f3e776a1d421815789cd0b7d44b';
const sitemap = await readFile(new URL('../dist/sitemap-0.xml', import.meta.url), 'utf8');
const urlList = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map(m => m[1]);

const res = await fetch('https://api.indexnow.org/indexnow', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json; charset=utf-8' },
  body: JSON.stringify({ host, key, keyLocation: `https://${host}/${key}.txt`, urlList }),
});
console.log(`IndexNow: submitted ${urlList.length} URLs, HTTP ${res.status}`);
if (res.status >= 400) process.exitCode = 1;
