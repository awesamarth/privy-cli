// Full text of the overview, how-to pages and guides in one file for AI tools.
import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';
import { toMarkdown } from '../markdown';

export const GET: APIRoute = async () => {
  const docs = await getCollection('docs');
  const order = (id: string) => (id === 'index' ? 0 : id === 'reference' ? 9 : id === 'install' ? 1 : id === 'agents' ? 1.5 : !id.includes('/') ? 1 : id.startsWith('tasks/') ? 2 : id.startsWith('guides/') ? 3 : 9);
  const pages = docs
    .filter(d => order(d.id) < 9)
    .sort((a, b) => order(a.id) - order(b.id) || (a.data.sidebar.order ?? 99) - (b.data.sidebar.order ?? 99) || a.id.localeCompare(b.id));
  const body = pages.map(d => toMarkdown(d)).join('\n\n---\n\n');
  return new Response(body, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
};
