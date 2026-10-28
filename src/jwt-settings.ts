import { X509Certificate, createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { isDeepStrictEqual } from 'node:util';
import { CliError } from './errors.ts';
import type { Field, JsonObject, Operation, RequestPlan } from './operations.ts';
import type { SecurityContext, SecurityRequest } from './security-settings.ts';
export type JwtAction = 'read' | 'configure' | 'enable' | 'disable' | 'flush';
const text: Field = { type: 'string', minLength: 1, maxLength: 512, description: 'Explicit nonempty claim name/value; no surrounding whitespace.' };
const fields: Record<string, Field> = {
  jwtTypeConfig: { type: 'object', sensitive: true, additionalProperties: false, required: ['type'], properties: { type: { type: 'string', enum: ['jws_jwks_uri', 'jws_public_key'], description: 'Verification source.' }, jwksUri: { type: 'string', minLength: 1, maxLength: 2048, description: 'Public HTTPS JWKS endpoint, fully redacted in ordinary output.' }, publicKey: { type: 'string', minLength: 1, maxLength: 32768, description: 'One RSA X.509 public certificate; no private key.' }, alg: { type: 'string', enum: ['RS256'], description: 'Certificate verification algorithm.' } }, description: 'Exactly {type:"jws_jwks_uri",jwksUri:"https://..."} or {type:"jws_public_key",publicKey:"X.509 PEM certificate",alg:"RS256"}. Stdin only: endpoint URLs can contain credentials. Never a private key.' },
  jwtCookieName: { type: 'string', nullable: true, description: 'Must be null, matching the observed dashboard contract. Custom cookie names are not exposed here.' },
  jwtClaimUserId: { ...text, description: 'JWT claim identifying the customer user or organization; typically sub.' },
  jwtClaimSubUserId: { ...text, nullable: true, description: 'Explicit sub-user claim or null.' },
  jwtAllowedAuds: { type: 'array', maxItems: 100, items: { type: 'string', maxLength: 512 }, description: 'Complete distinct allowed audiences. Firebase securetoken JWKS requires at least one.' },
  jwtAdditionalClaims: { type: 'array', sensitive: true, maxItems: 100, items: { type: 'object', additionalProperties: false, required: ['key', 'value'], properties: { key: text, value: text } }, description: 'Complete distinct-key [{key,value}] requirements, e.g. iss. Stdin only; values omitted from output.' },
  requireJwtClaims: { type: 'boolean', description: 'Require at least one audience/additional claim before saving. False requires --allow-unrestricted-jwt. Does not erase supplied checks.' },
  environment: { type: 'string', enum: ['ALL', 'CLIENT_SIDE', 'SERVER_SIDE'], description: 'Explicit accepted request environment, separate from Privy dev/prod.' },
  jwksCachingEnabled: { type: 'boolean', description: 'Optional, only with JWKS and server-reported cache eligibility. Revoked keys can remain accepted until the cached copy expires.' },
};
const required = ['jwtCookieName', 'jwtTypeConfig', 'jwtClaimUserId', 'jwtClaimSubUserId', 'jwtAllowedAuds', 'jwtAdditionalClaims', 'requireJwtClaims', 'environment'];
const root = '/api/v1/apps/{app_id}';
export const jwtOperations: Operation[] = (['read', 'configure', 'enable', 'disable', 'flush'] as const).map((action): Operation => ({
  id: `config.custom-jwt.${action === 'read' ? 'get' : action === 'flush' ? 'flush-cache' : action}`, command: `config custom-jwt ${action === 'read' ? 'get' : action === 'flush' ? 'flush-cache' : action}`, scope: 'app', method: action === 'read' ? 'GET' : 'POST', path: root + (action === 'enable' || action === 'disable' ? '/custom_jwt_auth' : action === 'flush' ? '/jwks_cache_flush' : '/custom_jwt_account_verifier'), jwtAction: action,
  ...(action === 'configure' ? { body: { type: 'object' as const, additionalProperties: false as const, required, properties: fields } } : action === 'enable' || action === 'disable' ? { body: { type: 'object' as const, additionalProperties: false as const, properties: { custom_jwt_auth: { type: 'boolean' as const, enum: [action === 'enable'], default: action === 'enable', description: 'Fixed by this command.' } } } } : action === 'flush' ? { body: { type: 'object' as const, additionalProperties: false as const, properties: {} } } : {}),
  keywords: ['JWT', 'authentication', 'issuer', 'audience', 'JWKS', 'certificate', 'existing auth', 'cache'], evidence: 'Loaded JWT-based authentication form, validation/confirmation and verifier/cache hooks; account feature gate enforced.', summary: action === 'read' ? 'Inspect custom-JWT verifier and app/account eligibility without tokens or credential-bearing URLs.' : action === 'configure' ? 'Replace custom-JWT trust configuration; stdin-only, no automatic account activation. --enable-auth explicitly permits initial app enablement.' : action === 'flush' ? 'Invalidate the external JWKS cache once; next verification fetches the document, not this CLI.' : `${action} an existing custom-JWT verifier for this app; immediate authentication impact.`,
  response: 'Writes require --confirm-name --allow-access-change --yes and production opt-in. Full verifier replacement, fresh state, no automatic rollback/retry. Initial enable+configure is two writes; partial completion is explicit. Cache flush is acknowledgement-only, not key revocation or external login proof.', examples: [`privy config custom-jwt ${action === 'read' ? 'get' : action === 'configure' ? 'configure --body - --diff' : action === 'flush' ? 'flush-cache --dry-run' : `${action} --dry-run`}`],
}));
function certificate(value: string): string {
  try {
    if (!value.startsWith('-----BEGIN CERTIFICATE-----') || !value.trimEnd().endsWith('-----END CERTIFICATE-----') || value.includes('PRIVATE KEY') || (value.match(/BEGIN CERTIFICATE/g)?.length !== 1)) throw new Error();
    const cert = new X509Certificate(value);
    if (cert.publicKey.asymmetricKeyType !== 'rsa' || (cert.publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new Error();
    return createHash('sha256').update(cert.raw).digest('hex');
  } catch { throw new CliError('INVALID_JWT_CERTIFICATE', 'Use one public RSA X.509 PEM certificate with at least2048-bit key for RS256. No private keys. Use JWKS for other algorithms.', 2); }
}
function comparableVerifier(config: JsonObject | null): JsonObject | null {
  if (config?.jwtTypeConfig?.type !== 'jws_public_key') return config;
  // The backend trims PEM whitespace. Compare exact certificate DER identity,
  // not PEM formatting; retain strict comparison of every other trust field.
  const type = config.jwtTypeConfig;
  return { ...config, jwtTypeConfig: { ...type, publicKey: certificate(type.publicKey) } };
}
export function validateJwt(op: Operation, body: JsonObject): void {
  if (op.jwtAction !== 'configure') return;
  const type = body.jwtTypeConfig;
  if (body.jwtCookieName !== null) throw new CliError('INVALID_JWT_CONFIG', 'jwtCookieName must be null for this dashboard workflow.', 2);
  if (type.type === 'jws_jwks_uri') {
    if (Object.keys(type).sort().join(',') !== 'jwksUri,type') throw new CliError('INVALID_JWT_CONFIG', 'JWKS mode requires only type and jwksUri.', 2);
    try {
      const u = new URL(type.jwksUri), host = u.hostname.replace(/\.$/, '');
      if (u.protocol !== 'https:' || u.username || u.password || u.hash || /\s/.test(type.jwksUri) || type.jwksUri.includes('\\') || isIP(host.replace(/^\[|\]$/g, '')) || !host.includes('.') || host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.home.arpa') || host.endsWith('.localhost') || new URL(u.pathname, u.origin).hostname !== u.hostname || decodeURIComponent(u.pathname).replaceAll('\\', '/').startsWith('//')) throw new Error();
      if (host === 'www.googleapis.com' && ['/service_accounts/v1/jwk/securetoken', '/robot/v1/metadata/jwk/securetoken'].some(p => decodeURIComponent(u.pathname).startsWith(p)) && !body.jwtAllowedAuds.length) throw new CliError('FIREBASE_AUDIENCE_REQUIRED', 'Firebase securetoken JWKS requires an allowed audience; unrestricted mode cannot override this.', 2);
    } catch (error) { if (error instanceof CliError) throw error; throw new CliError('INVALID_JWKS_URL', 'Use a public HTTPS JWKS hostname without userinfo, fragment, whitespace, literal IP or ambiguous path. URL omitted.', 2); }
  } else {
    if (Object.keys(type).sort().join(',') !== 'alg,publicKey,type' || type.alg !== 'RS256') throw new CliError('INVALID_JWT_CONFIG', 'Certificate mode requires exactly type, publicKey and alg:RS256.', 2);
    certificate(type.publicKey);
    if (Object.hasOwn(body, 'jwksCachingEnabled')) throw new CliError('INVALID_JWT_CONFIG', 'JWKS caching does not apply to certificate mode.', 2);
  }
  if ([body.jwtClaimUserId, ...(body.jwtClaimSubUserId === null ? [] : [body.jwtClaimSubUserId]), ...body.jwtAllowedAuds, ...body.jwtAdditionalClaims.flatMap((v: JsonObject) => [v.key, v.value])].some(v => !v.trim() || v !== v.trim())) throw new CliError('INVALID_JWT_CONFIG', 'Claim names/values and audiences must be nonempty and have no surrounding whitespace.', 2);
  if (new Set(body.jwtAllowedAuds).size !== body.jwtAllowedAuds.length || new Set(body.jwtAdditionalClaims.map((v: JsonObject) => v.key)).size !== body.jwtAdditionalClaims.length) throw new CliError('DUPLICATE_JWT_CONSTRAINT', 'Audiences and additional-claim keys must be distinct.', 2);
  if (body.requireJwtClaims && !body.jwtAllowedAuds.length && !body.jwtAdditionalClaims.length) throw new CliError('JWT_CONSTRAINT_REQUIRED', 'Provide at least one audience or additional claim.', 2);
}
export async function jwtState(context: SecurityContext, request: SecurityRequest): Promise<JsonObject> {
  const { app, account } = context;
  if (typeof app.custom_jwt_auth !== 'boolean') throw new CliError('INVALID_JWT_STATE', 'Cannot establish current app JWT authentication state.');
  let raw: any;
  try { raw = await request(`/api/v1/apps/${app.id}/custom_jwt_account_verifier`); }
  catch (error) { if (!(error instanceof CliError) || error.status !== 404) throw error; return { enabled: app.custom_jwt_auth, featureAllowed: account.customJwtAccountEnabled === true, config: null, configurationState: 'not_returned', httpStatus: 404, cachingAllowed: false }; }
  if (raw == null) return { enabled: app.custom_jwt_auth, featureAllowed: account.customJwtAccountEnabled === true, config: null, configurationState: 'not_configured', cachingAllowed: false };
  const config = Object.fromEntries(['jwtTypeConfig', 'jwtCookieName', 'jwtClaimUserId', 'jwtClaimSubUserId', 'jwtAllowedAuds', 'jwtAdditionalClaims', 'environment'].map(k => [k, raw[k] ?? (['jwtCookieName', 'jwtClaimSubUserId'].includes(k) ? null : undefined)]));
  if (!['jws_jwks_uri', 'jws_public_key'].includes(config.jwtTypeConfig?.type) || typeof config.jwtClaimUserId !== 'string' || !Array.isArray(config.jwtAllowedAuds) || !config.jwtAllowedAuds.every((v: unknown) => typeof v === 'string') || !Array.isArray(config.jwtAdditionalClaims) || !config.jwtAdditionalClaims.every((v: any) => typeof v?.key === 'string' && typeof v?.value === 'string') || config.jwtAllowedAuds.length > 100 || config.jwtAdditionalClaims.length > 100 || config.jwtCookieName !== null && typeof config.jwtCookieName !== 'string' || config.jwtClaimSubUserId !== null && typeof config.jwtClaimSubUserId !== 'string' || !['ALL', 'CLIENT_SIDE', 'SERVER_SIDE'].includes(config.environment)) throw new CliError('INVALID_JWT_STATE', 'Incomplete JWT verifier state; no response values exposed.');
  if (config.jwtTypeConfig.type === 'jws_jwks_uri' ? typeof config.jwtTypeConfig.jwksUri !== 'string' : typeof config.jwtTypeConfig.publicKey !== 'string' || config.jwtTypeConfig.alg !== 'RS256') throw new CliError('INVALID_JWT_STATE', 'Incomplete JWT verification material metadata.');
  return { enabled: app.custom_jwt_auth, featureAllowed: account.customJwtAccountEnabled === true, config, cachingAllowed: typeof raw.jwksCachingAllowedAt === 'string' && Number.isFinite(Date.parse(raw.jwksCachingAllowedAt)), cachingEnabled: typeof raw.jwksCachingEnabledAt === 'string' && Number.isFinite(Date.parse(raw.jwksCachingEnabledAt)) };
}
export function publicJwt(state: JsonObject): JsonObject {
  if (!state.config) return { ...state, externalLoginVerified: false };
  const type = state.config.jwtTypeConfig;
  return { ...state, config: { ...state.config, jwtTypeConfig: type.type === 'jws_jwks_uri' ? { type: type.type, jwksUri: '[REDACTED]' } : { type: type.type, alg: type.alg, certificateSha256: certificate(type.publicKey) }, jwtAdditionalClaims: '[REDACTED]' }, externalLoginVerified: false };
}
export async function writeJwt(op: Operation, plan: RequestPlan, context: () => Promise<SecurityContext>, request: SecurityRequest, options: { confirmName?: string; enableAuth?: boolean; allowUnrestrictedJwt?: boolean }): Promise<JsonObject> {
  const before = await context(), state = await jwtState(before, request), action = op.jwtAction!;
  if (before.app.name !== options.confirmName) throw new CliError('APP_NAME_MISMATCH', 'Use --confirm-name with the exact app name. No write was sent.', 2);
  if (!state.featureAllowed) throw new CliError('JWT_FEATURE_UNAVAILABLE', 'This account has not enabled custom JWT authentication. Inspect privy accounts features custom-jwt get --account ACCOUNT_ID; see privy docs read jwt. Account-wide activation needs separate authorization; no account feature or billing change was submitted, and no write was sent.', 2);
  if (action === 'configure') {
    if (!plan.body!.requireJwtClaims && !options.allowUnrestrictedJwt) throw new CliError('JWT_RISK_CONFIRMATION_REQUIRED', 'requireJwtClaims:false requires --allow-unrestricted-jwt. Prefer explicit issuer/audience constraints. No write was sent.', 2);
    if (!state.enabled && !options.enableAuth) throw new CliError('JWT_ENABLE_CONFIRMATION_REQUIRED', 'Use --enable-auth to explicitly permit app enablement before verifier configuration. This is a two-write, non-atomic setup; partial completion is surfaced.', 2);
    if (Object.hasOwn(plan.body!, 'jwksCachingEnabled') && !state.cachingAllowed) throw new CliError('JWKS_CACHE_UNAVAILABLE', 'Cache changes require server-reported cache eligibility. Omit jwksCachingEnabled for initial setup. No write was sent.', 2);
  }
  if (action === 'enable' && !state.config) throw new CliError('JWT_VERIFIER_REQUIRED', 'Configure a complete verifier with explicit --enable-auth first. Enabling without a verifier is refused.', 2);
  if (action === 'flush' && (state.config?.jwtTypeConfig?.type !== 'jws_jwks_uri' || !state.cachingAllowed || !state.cachingEnabled)) throw new CliError('JWKS_CACHE_UNAVAILABLE', 'Cache flush requires an existing cache-eligible, cache-enabled JWKS verifier. No write was sent.', 2);
  const latest = await context();
  if (latest.app.name !== before.app.name || latest.app.env !== before.app.env || latest.account.id !== before.account.id || !isDeepStrictEqual(state, await jwtState(latest, request))) throw new CliError('JWT_STATE_CHANGED', 'JWT configuration or eligibility changed during preflight. No write was sent.', 2);
  if ((action === 'enable' && state.enabled) || (action === 'disable' && !state.enabled)) return { verified: true, writesPerformed: false, state: publicJwt(state) };
  let enableAttempted = false;
  try {
    if (action === 'configure' && !state.enabled) {
      enableAttempted = true;
      await request(`/api/v1/apps/${before.app.id}/custom_jwt_auth`, 'POST', { custom_jwt_auth: true }, true);
      const enabledContext = await context();
      if (enabledContext.app.name !== before.app.name || enabledContext.app.env !== before.app.env || enabledContext.account.id !== before.account.id || !isDeepStrictEqual(await jwtState(enabledContext, request), { ...state, enabled: true })) throw new CliError('JWT_ENABLE_UNVERIFIED', 'App enablement or unchanged verifier/eligibility could not be verified. No verifier write was sent.');
    }
    await request(plan.path, 'POST', plan.body ?? {}, true);
  } catch (error) {
    if (enableAttempted) { const failure = new CliError('JWT_SETUP_PARTIAL_OR_UNCERTAIN', 'Initial JWT setup may have enabled app authentication without completing the verifier. Inspect config custom-jwt get before any retry or explicit disable; no automatic rollback occurred.'); failure.details = { appId: before.app.id, authEnableAttempted: true, requestMayHaveMutated: true, ...(error instanceof CliError ? { causeCode: error.code, causeStatus: error.status, causePath: typeof error.details?.path === 'string' ? error.details.path.split('?')[0] : undefined } : {}) }; throw failure; }
    throw error;
  }
  if (action === 'flush') return { appId: before.app.id, acknowledged: true, writesPerformed: true, verified: false, cacheRefreshRequested: true, nextVerificationFetchVerified: false, externalLoginVerified: false };
  try {
    const after = await jwtState(await context(), request);
    if (action === 'configure') {
      const expected = Object.fromEntries(['jwtTypeConfig', 'jwtCookieName', 'jwtClaimUserId', 'jwtClaimSubUserId', 'jwtAllowedAuds', 'jwtAdditionalClaims', 'environment'].map(k => [k, plan.body![k]]));
      if (!after.enabled || !isDeepStrictEqual(comparableVerifier(after.config), comparableVerifier(expected)) || Object.hasOwn(plan.body!, 'jwksCachingEnabled') && after.cachingEnabled !== plan.body!.jwksCachingEnabled) throw new Error();
    } else if (after.enabled !== (action === 'enable') || !isDeepStrictEqual(after.config, state.config)) throw new Error();
    return { appId: before.app.id, verified: true, writesPerformed: true, appEnablePerformed: enableAttempted, state: publicJwt(after), externalLoginVerified: false };
  } catch { const error = new CliError('JWT_VERIFY_FAILED', 'JWT write acknowledged but fresh state did not match. Inspect current verifier/app state; no retry or rollback occurred.'); error.details = { appId: before.app.id, authEnableAttempted: enableAttempted, requestMayHaveMutated: true }; throw error; }
}
