# Bring your own authentication with custom JWT

There are two independent controls: **account capability** permits apps to use JWT authentication; **app authentication and verifier** define whether/how a specific app trusts incoming tokens. Neither creates wallets or signs JWTs. Do not turn an app-only request into an account-wide capability change without authorization.

## Inspect prerequisites

```sh
privy config custom-jwt get
privy accounts features custom-jwt get --account ACCOUNT_ID
privy schema config custom-jwt configure
```

A feature-off result is not proof that development use is paid or approval-only. This CLI has an explicit account capability workflow for free, all-development workspaces (at most100 apps, no protected apps). It refuses unsupported scope; there is no production override or implicit billing/approval setup.

If the user authorizes that **whole-account** change, inspect its schema/diff, then use `accounts features custom-jwt update --enabled true` with explicit account ID, exact `--confirm-account`, `--allow-access-change` and `--yes`. This changes capability, not each app's authentication. Disabling capability refuses while any app still has JWT auth enabled. Do not disable those apps implicitly.

## Prepare a complete trust configuration

Configure is a **full replacement**, not a patch. Securely pipe all required fields through stdin. Schema is authoritative for exact names, types and supported environments. The main choices are:

- JWKS URI mode (`jws_jwks_uri`): a real public HTTPS issuer endpoint. Literal IPs, local/internal hosts, userinfo and fragments are refused. A `.invalid` placeholder is not a functioning issuer.
- Certificate mode (`jws_public_key`): one RSA X.509 public certificate, at least2048 bits, RS256. Do not supply private keys or an arbitrary PEM public-key block instead of a certificate.
- Explicit cookie choice (including null), user-ID claim, optional sub-user claim, allowed audiences and additional claims such as issuer. Prefer restrictive issuer/audience checks and `requireJwtClaims:true`.
- Firebase securetoken JWKS always requires an allowed audience. `requireJwtClaims:false` additionally needs `--allow-unrestricted-jwt`, does not discard supplied checks, and cannot bypass the Firebase guard.

JWKS URLs and additional-claim values are redacted in output. Public certificate output is a fingerprint/omission marker. Certificate read-back compares exact certificate DER identity rather than PEM whitespace; all other trust fields remain strictly checked. Do not infer original trust values from redacted read-back and resubmit placeholders.

```sh
# Feed complete JSON through a secure local producer; do not paste secrets into chat.
privy config custom-jwt configure --body - --diff
```

## Initial setup is not atomic

If app auth is disabled, `configure --enable-auth` explicitly permits **two writes**: enable app auth, then configure its verifier. It needs exact `--confirm-name`, `--allow-access-change`, `--yes`, and production opt-in where applicable. Offline preview describes the conditional first request; it cannot guarantee remote eligibility.

A failure can leave auth enabled without a valid verifier. On `JWT_SETUP_PARTIAL_OR_UNCERTAIN`, inspect `config custom-jwt get` before deciding whether to correct/configure or explicitly disable authentication. Do not blindly replay the setup or assume rollback. Safe cause metadata is included when available; absence of a cause status does not justify inventing one.

`enable` alone requires an existing verifier. `disable` stops app JWT auth without claiming verifier deletion. Separate enable/disable operations have the same name/access/production confirmations. Account capability changes never happen implicitly.

## Cache and verification

Cache options and `flush-cache` require server-reported eligibility; flush also requires an existing cache-enabled JWKS verifier. An ineligible refusal is not a reason to enable unrelated features. A flush acknowledgement is not proof that the next token verification fetched new keys, or that a revoked key can no longer validate tokens.

Report account flag, app auth and verifier persistence separately. A valid stored JWKS URL—even a real public Google endpoint—does not demonstrate an actual issuer login, project ownership, accepted JWT or token signing. Configuration responses deliberately keep `externalLoginVerified:false`. Verify actual authentication separately with your issuer/frontend and a fresh session, especially after replacing a verifier; an already-authenticated session is not proof that the new key works. If controlled issuer credentials/frontend are missing, leave external authentication explicitly unverified.
