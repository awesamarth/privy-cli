import { CliError } from './errors.ts';
import type { JsonObject } from './operations.ts';

const contracts = {
  'users.list': {
    fields: {
      id: 'Exact user ID.',
      names: 'Distinct nonempty display_name and linked-account name values, in reported order; none is designated primary.',
      emails: 'Distinct nonempty linked-account email values and email-account addresses; none is designated primary.',
      linked_account_types: 'Distinct reported linked-account types, including wallet when present; not a claim that every type can log in.',
      wallet_count: 'Number of linked_accounts entries with type wallet, not a separate wallet-resource count.',
    },
    detail: 'Use users get <id> for one full user, or users list --full for full rows on the requested pages.',
  },
  'wallets.list': {
    fields: {
      id: 'Exact wallet ID.', address: 'Reported wallet address.', chain_type: 'Reported chain type.', type: 'Reported wallet type.',
      user_id: 'Reported associated user ID, or null when not returned.',
      owner_id: 'Reported auth_key.id, otherwise user_id, otherwise null. A summary/null is not proof of absent ownership or permission to mutate.',
    },
    detail: 'Use wallets get <id> for one full wallet, or wallets list --full for full rows on the requested pages.',
    balances: '--include-balance true also retains full rows so explicitly requested balance details are never dropped. Balance availability is determined by the API.',
  },
  'global-wallet.providers.list': {
    fields: {
      app_id: 'Exact counterpart app ID.', name: 'Provider name.', status: 'Reported relationship status.',
      availability: 'Provider availability.', allowed_permissions: 'Provider permissions.',
    },
    detail: 'Use global-wallet providers list --full to retain optional icon_url and created_at metadata. --full does not bypass the existing safe-metadata allowlist.',
  },
} as const;

export function listOutputSchema(id: string) {
  if (!Object.hasOwn(contracts, id)) return undefined;
  return {
    default: 'summary', fullFlag: '--full', ...contracts[id as keyof typeof contracts],
    scope: 'Only CLI row presentation changes. --all controls collection breadth, --full controls row detail. Pagination/truncation, filters, redaction, internal reads and mutation verification are unchanged.',
  };
}

function invalid(): never { throw new CliError('INVALID_LIST_OUTPUT', 'Cannot summarize the returned list shape. No rows were silently omitted. Inspect this command with --full for the existing detailed output.'); }
function text(value: unknown): string | null { return typeof value === 'string' && value.trim().length > 0 ? value : null; }
function distinct(values: unknown[]): string[] { return [...new Set(values.map(text).filter((value): value is string => value !== null))]; }

/** Presentation only: never call this from resource lookup, preflight or verification paths. */
export function summarizeList(id: string, result: JsonObject, full = false): JsonObject {
  if (full || !listOutputSchema(id)) return result;
  if (!result || !Array.isArray(result.data)) invalid();
  return { ...result, data: result.data.map((row: JsonObject) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) invalid();
    if (id === 'global-wallet.providers.list') {
      if (!text(row.app_id)) invalid();
      return { app_id: row.app_id, name: row.name, status: row.status, availability: row.availability, allowed_permissions: row.allowed_permissions };
    }
    if (!text(row.id)) invalid();
    if (id === 'users.list') {
      if (!Array.isArray(row.linked_accounts) || row.linked_accounts.some((account: JsonObject) => !account || typeof account !== 'object' || !text(account.type))) invalid();
      const accounts: JsonObject[] = row.linked_accounts;
      return {
        id: row.id,
        names: distinct([row.display_name, ...accounts.map(account => account.name)]),
        emails: distinct(accounts.flatMap(account => [account.email, ...(account.type === 'email' ? [account.address] : [])])),
        linked_account_types: distinct(accounts.map(account => account.type)),
        wallet_count: accounts.filter(account => account.type === 'wallet').length,
      };
    }
    return { id: row.id, address: row.address ?? null, chain_type: row.chain_type ?? null, type: row.type ?? null,
      user_id: text(row.user_id), owner_id: text(row.auth_key?.id) ?? text(row.user_id) };
  }) };
}
