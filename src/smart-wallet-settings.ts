import { isDeepStrictEqual } from 'node:util';
import { CliError } from './errors.ts';
import type { Field, JsonObject } from './operations.ts';

const providers = ['safe', 'kernel', 'light_account', 'biconomy', 'coinbase_smart_wallet', 'thirdweb', 'nexus'];
const endpoint: Field = { type: 'string', minLength: 1, maxLength: 4096, sensitive: true, description: 'HTTPS provider endpoint. May contain credentials in its path/query: stdin only; entire URL redacted from output.' };
export const smartWalletFields: Record<string, Field> = {
  enabled: { type: 'boolean', description: 'Enable future smart-wallet creation, or disable it. Does not disable existing smart wallets or perform transactions.' },
  smart_wallet_type: { type: 'string', enum: providers, description: 'Provider for the complete enabled configuration.' },
  smart_wallet_version: { type: 'string', nullable: true, enum: ['1.1'], description: 'Coinbase requires explicit 1.1. Legacy vulnerable 1 is readable but refused for writes. Other providers use null/omit.' },
  configured_networks: { type: 'array', sensitive: true, maxItems: 100, description: 'Complete chain configuration replacement. Provider URLs/context require stdin; no automatic provider provisioning or sponsorship funding.', items: { type: 'object', additionalProperties: false, required: ['chain_id', 'bundler_url'], properties: {
    chain_id: { type: 'string', pattern: '^eip155:[1-9][0-9]{0,15}$', description: 'EIP-155 chain identifier; duplicate chains refused.' },
    bundler_url: endpoint, paymaster_url: endpoint, rpc_url: endpoint,
    chain_name: { type: 'string', minLength: 1, maxLength: 100, description: 'Optional custom chain display name.' },
    paymaster_context: { type: 'object', sensitive: true, additionalProperties: false, required: ['policy_id'], properties: { policy_id: { type: 'string', pattern: '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', description: 'Alchemy sponsorship policy UUID; only persisted, never funded/executed by CLI.' } }, description: 'Observed Alchemy policy context; requires paymaster_url. Entire context redacted.' },
  } } },
};
export function validateSmartWallet(body: JsonObject): void {
  if (!body.enabled) {
    if (Object.keys(body).some(key => key !== 'enabled')) throw new CliError('SMART_WALLET_DISABLE_BODY', 'To disable, send only enabled:false. Do not assume disabled read-back retains a recoverable copy of provider configuration.', 2);
    return;
  }
  if (!providers.includes(body.smart_wallet_type) || !body.configured_networks?.length) throw new CliError('SMART_WALLET_CONFIG_REQUIRED', 'Enabling requires a provider and at least one explicitly configured chain.', 2);
  if (body.smart_wallet_type === 'coinbase_smart_wallet' ? body.smart_wallet_version !== '1.1' : body.smart_wallet_version != null) throw new CliError('SMART_WALLET_VERSION', 'Use explicit version 1.1 for Coinbase; null/omit for other providers. Vulnerable legacy Coinbase version 1 is not enabled by this CLI.', 2);
  const ids = body.configured_networks.map((row: JsonObject) => row.chain_id);
  if (new Set(ids).size !== ids.length) throw new CliError('DUPLICATE_SMART_CHAIN', 'Each chain may occur only once.', 2);
  for (const row of body.configured_networks) {
    if (!Number.isSafeInteger(Number(row.chain_id.slice(7)))) throw new CliError('INVALID_SMART_CHAIN', 'Chain ID must be a positive safe integer.', 2);
    if (row.paymaster_context && !row.paymaster_url) throw new CliError('PAYMASTER_URL_REQUIRED', 'Paymaster context requires an explicit paymaster URL.', 2);
    for (const field of ['bundler_url', 'paymaster_url', 'rpc_url']) if (row[field] !== undefined) {
      try {
        const url = new URL(row[field]);
        if (url.protocol !== 'https:' || url.username || url.password || url.hash || row[field] !== row[field].trim()) throw new Error();
      } catch { throw new CliError('INVALID_SMART_ENDPOINT', 'Provider endpoints must be HTTPS URLs without userinfo, fragments or surrounding whitespace. Values are not printed.', 2); }
    }
  }
}
export function smartWalletMetadata(raw: any): JsonObject {
  if (!raw || typeof raw.enabled !== 'boolean') throw new CliError('INVALID_SMART_WALLET_STATE', 'Expected an explicit smart-wallet enabled state.');
  if (!raw.enabled) return { enabled: false, configurationVisible: false, externalIntegrationVerified: false };
  if (!providers.includes(raw.smart_wallet_type) || !Array.isArray(raw.configured_networks) || !raw.configured_networks.length || raw.configured_networks.some((row: any) => !row || typeof row.chain_id !== 'string' || typeof row.bundler_url !== 'string')) throw new CliError('INVALID_SMART_WALLET_STATE', 'Unexpected smart-wallet provider/network configuration. No credential values are exposed.');
  return { enabled: true, smart_wallet_type: raw.smart_wallet_type, smart_wallet_version: raw.smart_wallet_version ?? null, ...(raw.smart_wallet_type === 'coinbase_smart_wallet' && (raw.smart_wallet_version ?? '1') === '1' ? { warning: 'Legacy Coinbase version 1 has a known funds-loss vulnerability; configure 1.1 and compatible SDK versions.' } : {}), configured_networks: raw.configured_networks.map((row: JsonObject) => ({ chain_id: row.chain_id, ...(typeof row.chain_name === 'string' ? { chain_name: row.chain_name } : {}), bundlerConfigured: Boolean(row.bundler_url), paymasterConfigured: Boolean(row.paymaster_url), rpcConfigured: Boolean(row.rpc_url), contextConfigured: Boolean(row.paymaster_context) })), endpointsOmitted: true, externalIntegrationVerified: false };
}
export function verifySmartWallet(body: JsonObject, raw: any): void {
  smartWalletMetadata(raw);
  if (raw.enabled !== body.enabled) throw new Error();
  if (!body.enabled) return;
  if (raw.smart_wallet_type !== body.smart_wallet_type || (raw.smart_wallet_version ?? null) !== (body.smart_wallet_version ?? null) || raw.configured_networks.length !== body.configured_networks.length) throw new Error();
  for (const desired of body.configured_networks) {
    const matches = raw.configured_networks.filter((row: JsonObject) => row.chain_id === desired.chain_id);
    if (matches.length !== 1) throw new Error();
    for (const key of ['chain_id', 'bundler_url', 'paymaster_url', 'rpc_url', 'chain_name', 'paymaster_context']) if (!isDeepStrictEqual(matches[0][key] ?? null, desired[key] ?? null)) throw new Error();
  }
}
