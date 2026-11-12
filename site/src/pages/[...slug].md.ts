// Markdown copy of every page at <page>.md, e.g. /tasks/webhooks.md, for AI tools and agents.
import type { APIRoute, GetStaticPaths } from 'astro';
import { getCollection } from 'astro:content';
import { toMarkdown } from '../markdown';

export const getStaticPaths: GetStaticPaths = async () => {
  const docs = await getCollection('docs');
  return docs.map(entry => ({ params: { slug: entry.id }, props: { entry } }));
};

export const GET: APIRoute = ({ props }) =>
  new Response(toMarkdown(props.entry), { headers: { 'Content-Type': 'text/markdown; charset=utf-8' } });
