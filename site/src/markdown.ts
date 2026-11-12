import type { CollectionEntry } from 'astro:content';

const site = 'https://privy-cli.awesamarth.dev';

// Plain Markdown version of a page: MDX imports and component tags are removed, content is kept.
export function toMarkdown(entry: CollectionEntry<'docs'>): string {
  const body = (entry.body ?? '')
    .replace(/^import .*$/gm, '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/^\s*<TabItem label="([^"]+)">\s*$/gm, '$1:')
    .replace(/^\s*<\/?(Tabs|TabItem|CardGrid|Steps|Features)\b[^>]*>\s*$/gm, '')
    .replace(/<LinkCard title="([^"]+)" href="([^"]+)" description="([^"]+)" \/>/g, '- [$1]($2): $3')
    .replace(/\]\(\//g, `](${site}/`)
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  const url = `${site}/${entry.id === 'index' ? '' : `${entry.id}/`}`;
  return `# ${entry.data.title}\n\nSource: ${url}\n\n${entry.data.description ? `> ${entry.data.description}\n\n` : ''}${body}\n`;
}
