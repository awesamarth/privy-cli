// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { readFileSync } from 'node:fs';

const site = 'https://privy-cli.awesamarth.dev';
const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const structuredData = {
  '@context': 'https://schema.org',
  '@type': 'SoftwareApplication',
  name: 'Privy CLI',
  alternateName: ['@awesamarth/privy-cli', 'privy-cli'],
  description: "Manage your Privy account and apps from your agent or terminal. Inspired by Cloudflare's cf CLI. Unofficial; not affiliated with or endorsed by Privy.",
  applicationCategory: 'DeveloperApplication',
  applicationSubCategory: 'Command-line tool',
  operatingSystem: 'Node.js 22.18 or later',
  softwareVersion: version,
  license: 'https://opensource.org/licenses/MIT',
  url: site,
  downloadUrl: 'https://www.npmjs.com/package/@awesamarth/privy-cli',
  installUrl: `${site}/install/`,
  codeRepository: 'https://github.com/awesamarth/privy-cli',
  isAccessibleForFree: true,
  offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
  author: { '@type': 'Person', name: 'Samarth Saxena', url: 'https://github.com/awesamarth' },
};

export default defineConfig({
  site,
  devToolbar: { enabled: false },
  integrations: [
    starlight({
      title: 'Privy CLI (Unofficial)',
      description: "Manage your Privy account and apps from your agent or terminal. Inspired by Cloudflare's cf CLI (Unofficial)",
      favicon: '/favicon.svg',
      head: [
        { tag: 'meta', attrs: { property: 'og:image', content: `${site}/og.png` } },
        { tag: 'meta', attrs: { property: 'og:image:width', content: '1200' } },
        { tag: 'meta', attrs: { property: 'og:image:height', content: '630' } },
        { tag: 'meta', attrs: { property: 'og:image:alt', content: 'Privy CLI (Unofficial): manage Privy from your agent or terminal' } },
        { tag: 'meta', attrs: { name: 'twitter:card', content: 'summary_large_image' } },
        { tag: 'meta', attrs: { name: 'twitter:image', content: `${site}/og.png` } },
        { tag: 'meta', attrs: { name: 'twitter:creator', content: '@awesamarth_' } },
        { tag: 'meta', attrs: { name: 'author', content: 'Samarth Saxena' } },
        { tag: 'link', attrs: { rel: 'alternate', type: 'text/plain', title: 'llms.txt', href: `${site}/llms.txt` } },
        { tag: 'script', attrs: { type: 'application/ld+json' }, content: JSON.stringify(structuredData) },
      ],
      customCss: ['@fontsource-variable/geist', '@fontsource/fragment-mono', './src/styles/theme.css'],
      components: {
        SiteTitle: './src/components/SiteTitle.astro',
        Hero: './src/components/Hero.astro',
        ThemeProvider: './src/components/ThemeProvider.astro',
        ThemeSelect: './src/components/ThemeSelect.astro',
        Footer: './src/components/Footer.astro',
      },
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/awesamarth/privy-cli' }],
      sidebar: [
        {
          label: 'Start here',
          items: [
            { label: 'Overview', link: '/' },
            { slug: 'install' },
            { slug: 'agents' },
          ],
        },
        { label: 'How to', items: [{ autogenerate: { directory: 'tasks' } }] },
        { label: 'Guides', items: [{ autogenerate: { directory: 'guides' } }] },
        { label: 'Command reference', collapsed: true, items: [{ autogenerate: { directory: 'reference', collapsed: true } }] },
      ],
      expressiveCode: {
        themes: ['github-dark-default', 'github-light-default'],
        styleOverrides: {
          borderRadius: '0.75rem',
          codeFontFamily: 'var(--sl-font-mono)',
          uiFontFamily: 'var(--sl-font)',
          frames: { frameBoxShadowCssValue: 'none' },
        },
      },
      lastUpdated: false,
      pagination: true,
    }),
  ],
});
