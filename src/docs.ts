import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { CliError } from './errors.ts';

// Curated, version-matched operator guides. No network, context or credential reads.
export const guides = [
  { topic: 'getting-started', title: 'Discover, inspect, preview, execute, verify', summary: 'Agent workflow, JSON input/output, consent, pagination and evidence.', keywords: 'agent schema help search dry run diff boolean arrays limits' },
  { topic: 'authentication', title: 'Dashboard login and session recovery', summary: 'Interactive email login, profiles, OS credential storage and explicit shared-session CDP import.', keywords: 'auth email otp captcha chrome brave browser cdp refresh logout keychain doctor' },
  { topic: 'app-lifecycle', title: 'Accounts, app context and project setup', summary: 'Choose the right workspace, create/configure a dev app, bind a folder and delete deliberately.', keywords: 'new create application project privy.json profile precedence selection protect cleanup account' },
  { topic: 'providers', title: 'App login methods and OAuth providers', summary: 'Built-in login toggles versus own OAuth credentials, Telegram bots and frontend prerequisites.', keywords: 'google apple github discord telegram oauth signin sign in login authentication credentials' },
  { topic: 'secrets', title: 'API credentials and local resource secrets', summary: 'App-secret storage choice: env, Keychain, both or none; session separation, rotation and safe recovery.', keywords: 'credential key token secret stdin vault keychain env env-output overwrite storage run environment revoke export' },
  { topic: 'jwt', title: 'Bring your own JWT authentication', summary: 'Account capability versus app trust, full verifier replacement and non-atomic initial setup.', keywords: 'custom jwt firebase jwks issuer audience certificate cache enable account capability' },
  { topic: 'webhooks', title: 'Webhooks and delivery verification', summary: 'Authorized receivers, subscriptions, signing keys, history and safe replay.', keywords: 'webhook endpoint delivery receiver test resend replay subscription watchlist' },
  { topic: 'policies', title: 'Policies, rules, quorums and approvals', summary: 'Unowned policy lifecycle, full rule replacement and owner-authorization boundaries.', keywords: 'policy rule allow deny spending quorum signer ownership approval authorization' },
  { topic: 'resources', title: 'Users, wallets, organizations and exports', summary: 'Provisioning and bounded inspection without confusing configuration with signing or completed jobs.', keywords: 'user wallet organization metadata import bulk export csv archive transaction balance' },
  { topic: 'integrations', title: 'Clients, domains and external integrations', summary: 'DNS/provider prerequisites, smart wallets, cross-app availability and public logo hosting.', keywords: 'client domain dns cookie walletconnect coinbase kraken blockaid smart wallet global wallet logo image publish' },
  { topic: 'security', title: 'Customer-app security settings', summary: 'Redirect restrictions, CAPTCHA, wallet creation, export permissions and verification-key rotation.', keywords: 'redirect callback origins captcha merging session recovery embedded android fingerprint key export rotation privy home access allowlist denylist' },
  { topic: 'accounts', title: 'Workspace management and analytics', summary: 'Account-wide impact, members/invites, app organizations and honest analytics freshness.', keywords: 'account workspace team member invite billing analytics usage production' },
  { topic: 'recovery', title: 'Recover from failed or uncertain operations', summary: 'Inspect before retrying; distinguish refusal, partial completion, acknowledgement and verification.', keywords: 'error failure timeout cancelled cancelled partial uncertain retry rollback 401 403 500 520 missing credential' },
] as const;
export type GuideTopic = typeof guides[number]['topic'];

export function guidePath(topic?: string): string {
  if (topic !== undefined && !guides.some(g => g.topic === topic)) {
    throw new CliError('UNKNOWN_GUIDE', 'Unknown guide topic. Run privy docs or privy docs search "your task".', 2);
  }
  return fileURLToPath(new URL(`../docs/user/${topic === undefined ? '' : `${topic}.md`}`, import.meta.url));
}
export async function readGuide(topic: string): Promise<string> {
  const path = guidePath(topic);
  try { return await readFile(path, 'utf8'); }
  catch { throw new CliError('GUIDE_UNAVAILABLE', 'The bundled guide is missing or unreadable. Reinstall this CLI artifact; no online fallback was attempted. Command help and schema remain available.'); }
}
export function guideIndex() {
  return guides.map(({ topic, title, summary }) => ({ topic, title, summary, read: `privy docs read ${topic}` }));
}
function searchWords(text: string): string[] {
  return text.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean).map(word => word.length > 3 && word.endsWith('s') ? word.slice(0, -1) : word);
}
export async function searchGuides(terms: string[]) {
  const words = [...new Set(searchWords(terms.join(' ')))];
  if (!words.length || words.length > 32 || terms.join(' ').length > 1000) throw new CliError('INVALID_SEARCH', 'Use 1–32 search words (at most 1000 characters).', 2);
  const matches = await Promise.all(guides.map(async g => {
    const content = await readGuide(g.topic);
    const heading = searchWords(`${g.topic} ${g.title} ${g.keywords}`);
    const text = searchWords(content);
    const score = words.reduce((n, word) => n + (heading.includes(word) ? 5 : text.includes(word) ? 1 : 0), 0);
    return { ...g, content, score };
  }));
  return matches.filter(g => g.score > 0).sort((a, b) => b.score - a.score).slice(0, 5).map(g => ({
    topic: g.topic, title: g.title, read: `privy docs read ${g.topic}`,
    snippet: (g.content.split('\n').filter(line => line.trim() && !line.startsWith('#')).map(line => ({ line, matches: words.filter(w => searchWords(line).includes(w)).length })).sort((a, b) => b.matches - a.matches)[0]?.line ?? g.summary).slice(0, 320),
  }));
}
export function commandGuides(command: string): GuideTopic[] {
  if (command.includes('custom-jwt')) return ['jwt', 'recovery'];
  if (/^(auth\b|doctor$)/.test(command)) return ['authentication', 'recovery'];
  if (/^(secrets|credentials)\b/.test(command)) return ['secrets', 'recovery'];
  if (/^webhooks\b/.test(command)) return ['webhooks', 'recovery'];
  if (/^(policies|key-quorums|keys|approvals)\b/.test(command)) return ['policies', 'recovery'];
  if (/^(providers\b|clients telegram\b)/.test(command)) return ['providers', 'secrets'];
  if (/^(users|wallets|organizations|transactions)\b/.test(command)) return ['resources', 'recovery'];
  if (/^(accounts|analytics)\b/.test(command)) return ['accounts', 'recovery'];
  if (/^(integrations|global-wallet|domains|clients)\b|^config smart-wallets\b/.test(command)) return ['integrations', 'recovery'];
  if (/^(apps config|config (get|update))\b/.test(command)) return ['app-lifecycle', 'providers'];
  if (/^(config|access)\b/.test(command)) return ['security', 'recovery'];
  if (command === 'apps create') return ['app-lifecycle', 'secrets', 'recovery'];
  if (/^(apps|project)\b/.test(command)) return ['app-lifecycle', 'recovery'];
  return ['getting-started'];
}
export function guideRefs(command: string) {
  return commandGuides(command).map(topic => ({ topic, command: `privy docs read ${topic}` }));
}
export const localExamples: Record<string, string[]> = {
  'auth login': ['privy --profile work auth login'],
  'auth status': ['privy auth status', 'privy auth status --remote'],
  'auth whoami': ['privy auth whoami'],
  'auth refresh': ['privy auth refresh'],
  'auth logout': ['privy auth logout'],
  'apps use': ['privy apps list', 'privy apps use APP_ID'],
  'apps protect': ['privy apps protect APP_ID'],
  'project init': ['privy --profile work --app APP_ID project init --dry-run', 'privy --profile work --app APP_ID project init --yes'],
  'project show': ['privy project show', 'privy --no-project project show'],
  'secrets list': ['privy secrets list'],
  'secrets status': ['privy secrets status app-credential CREDENTIAL_ID'],
  'secrets forget': ['privy secrets forget app-credential CREDENTIAL_ID --dry-run'],
  'secrets run': ['privy secrets run app-credential CREDENTIAL_ID --env PRIVY_APP_SECRET --dry-run -- node server.js'],
  doctor: ['privy doctor'],
  schema: ['privy schema apps create'],
  'cli schema': ['privy cli schema apps create'],
  'cli search': ['privy cli search "enable google login"'],
  docs: ['privy docs', 'privy docs search "login providers"'],
  'docs read': ['privy docs read getting-started'],
  'docs search': ['privy docs search "uncertain write"'],
  'docs path': ['privy docs path', 'privy docs path authentication'],
};
