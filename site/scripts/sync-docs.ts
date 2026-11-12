// Copies the CLI's bundled guides (docs/user/*.md) into the site's content folder.
// docs/user stays the single source of truth for both `privy docs` and the website.
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { guides } from '../../src/docs.ts';
import { labels } from './guide-labels.ts';


const outDir = new URL('../src/content/docs/guides/', import.meta.url);
await rm(outDir, { recursive: true, force: true });
await mkdir(outDir, { recursive: true });

for (const [order, guide] of guides.entries()) {
  const source = await readFile(new URL(`../../docs/user/${guide.topic}.md`, import.meta.url), 'utf8');
  const heading = source.match(/^# (.+)\r?\n/);
  const title = heading?.[1].trim() ?? guide.title;
  const body = heading ? source.slice(heading[0].length).trimStart() : source;
  const frontmatter = [
    '---',
    `title: ${JSON.stringify(title)}`,
    `description: ${JSON.stringify(guide.summary)}`,
    'sidebar:',
    `  order: ${order}`,
    `  label: ${JSON.stringify(labels[guide.topic] ?? guide.title)}`,
    `editUrl: ${JSON.stringify(`https://github.com/awesamarth/privy-cli/edit/main/docs/user/${guide.topic}.md`)}`,
    '---',
    '',
    `<!-- Generated from docs/user/${guide.topic}.md. Edit that file, not this one. -->`,
  ].join('\n');
  await writeFile(new URL(`${guide.topic}.md`, outDir), `${frontmatter}\n\n${body}`);
}
console.log(`Synced ${guides.length} guides from docs/user.`);
