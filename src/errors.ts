export class CliError extends Error {
  hint?: string;
  requestId?: string;
  retryAfterSeconds?: number;
  details?: Record<string, unknown>;
  constructor(public code: string, message: string, public exitCode = 1, public status?: number) {
    super(message);
    this.name = 'CliError';
  }
}

function publicMetadataValue(value: any, accepts: (value: unknown) => boolean): boolean {
  if (accepts(value)) return true;
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  return Object.keys(value).every(key => key === 'before' || key === 'after') && Object.values(value).every(v => v === null || v === undefined || accepts(v));
}
function publicHttpUrl(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  try { const url = new URL(value); return ['https:', 'http:'].includes(url.protocol) && !url.username && !url.password; } catch { return false; }
}
function redactUrl(value: string): string {
  if (!/^https?:\/\//i.test(value)) return value;
  try {
    const url = new URL(value); let changed = false;
    if (url.username || url.password) { url.username = '[REDACTED]'; url.password = ''; changed = true; }
    const maskParams = (params: URLSearchParams): boolean => {
      let masked = false;
      for (const key of [...params.keys()]) {
        const normalized = key.replace(/([a-z0-9])([A-Z])/g, '$1_$2');
        if (/(^|[-_])(key|token|secret|password|authorization|credential|signature|code|state|nonce)([-_]|$)/i.test(normalized)) { params.set(key, '[REDACTED]'); masked = true; }
      }
      return masked;
    };
    if (maskParams(url.searchParams)) changed = true;
    if (url.hash.includes('=')) {
      const fragment = new URLSearchParams(url.hash.slice(1));
      if (maskParams(fragment)) { url.hash = fragment.toString(); changed = true; }
    }
    return changed ? url.href : value;
  } catch { return value; }
}

// API payloads and error bodies may contain secrets. Never emit raw bodies or headers.
export function redact(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, val]) => {
      const normalized = key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replaceAll('-', '_').toLowerCase();
      // Only actual public values/diffs are exempt, never schema-shaped API payloads.
      // Trusted registry schemas have a separate output path in the schema command.
      const publicMetadata = ['authorization_threshold', 'access_token_lifetime_minutes', 'id_token_lifetime_minutes'].includes(normalized) && publicMetadataValue(val, v => typeof v === 'number')
        || ['cookie_domain', 'base_cookie_domain'].includes(normalized) && publicMetadataValue(val, v => typeof v === 'string' && (v === '' || v.length <= 253 && /^(?:[a-z0-9-]+\.)+[a-z0-9-]+$/i.test(v)))
        || ['cookie_auth_enabled', 'cookie_same_site_lax', 'use_app_cookie_domain_settings'].includes(normalized) && publicMetadataValue(val, v => typeof v === 'boolean')
        || ['cookie_auth_toggled_at', 'cookie_domain_verified_at'].includes(normalized) && publicMetadataValue(val, v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(v) && Number.isFinite(Date.parse(v)))
        || ['authorization_url', 'token_url'].includes(normalized) && publicMetadataValue(val, publicHttpUrl)
        || normalized === 'authorization_keys' && Array.isArray(val);
      if (normalized === 'public_key' && typeof val === 'string' && val.includes('-----BEGIN CERTIFICATE-----')) return [key, '[PUBLIC CERTIFICATE OMITTED]'];
      return [key, !publicMetadata && /(^|_)(secret|token|password|authorization|private_key|api_key|cookie|mnemonic|seed_phrase|bundler_url|paymaster_url|rpc_url|paymaster_context|master_account_iiban|jwks_uri|jwt_additional_claims)(_|$)/i.test(normalized)
        && val !== null && typeof val !== 'boolean' ? '[REDACTED]' : redact(val)];
    }));
  }
  return typeof value === 'string' ? redactUrl(value) : value;
}
