// llms.txt index (https://llmstxt.org): what this site is, plus links to a plain-Markdown copy of every page.
import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';

const site = 'https://privy-cli.awesamarth.dev';

export const GET: APIRoute = async () => {
  const docs = await getCollection('docs');
  const section = (prefix: string) =>
    docs
      .filter(d => (prefix ? d.id.startsWith(prefix) : !d.id.includes('/')) && d.id !== 'index')
      .sort((a, b) => (a.data.sidebar.order ?? 99) - (b.data.sidebar.order ?? 99) || a.id.localeCompare(b.id))
      .map(d => `- [${d.data.title}](${site}/${d.id}.md): ${d.data.description ?? ''}`)
      .join('\n');

  const body = `# Privy CLI

> Manage your Privy account and apps from your agent or terminal. Inspired by Cloudflare's cf CLI (Unofficial). The \`privy\` command (npm: @awesamarth/privy-cli) creates and configures Privy apps, toggles login methods, and manages users, wallets, policies, webhooks, API credentials, integrations, dashboard members and analytics. JSON output, explicit mutations, offline docs and schemas.

Not affiliated with Privy. It is different from Privy's official \`@privy-io/agent-wallet-cli\`, which gives agents wallets for funding and transactions; this CLI manages the developer dashboard and never signs transactions.

Install with \`npm install -g @awesamarth/privy-cli\` (Node.js 22.18+). Agents can install the skill with \`npx skills add awesamarth/privy-cli\`. Workflow: \`privy cli search "task"\` → \`privy schema <command>\` → \`--dry-run\` / \`--diff\` → \`--yes\` → verify. First-time login (\`privy auth login\`) needs a human for a browser CAPTCHA and an email code.

Every page is also available as Markdown by adding \`.md\` to its URL. The full text of the guides and how-to pages is at ${site}/llms-full.txt.

## Start here

- [Overview](${site}/index.md): what the CLI covers and how it works
${['install', 'agents'].map(id => docs.find(d => d.id === id)).filter(Boolean).map(d => `- [${d!.data.title}](${site}/${d!.id}.md): ${d!.data.description ?? ''}`).join('\n')}

## How to

${section('tasks/')}

## Guides

${section('guides/')}

## Optional

- [Command reference](${site}/reference.md): every command, generated from the CLI
- [npm package](https://www.npmjs.com/package/@awesamarth/privy-cli)
- [Source code](https://github.com/awesamarth/privy-cli)
`;
  return new Response(body, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
};
