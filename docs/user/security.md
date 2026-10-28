# Customer-app security settings

These settings affect **app users**, not the administrator session running the CLI. Inspect current app/environment and the exact schema; avoid turning a narrow request into account-wide activation, wallet ownership migration or production setup.

## Origins and OAuth redirects

`apps config update` manages allowed origins; `config redirects` manages complete OAuth redirect URL/path restrictions. Each redirect must match an explicitly configured allowed origin. Empty origins and a bare `*` do not authorize a redirect, and the CLI will not silently widen origins. Origin wildcards match within a dot-delimited segment, not arbitrary hosts.

URLs must satisfy the schema (HTTPS, dev-only loopback HTTP or supported native schemes). Credentials/query/fragment/ambiguous input are refused, not silently stripped. Redirect arrays replace the whole list; `[]` removes path restrictions. Inspect both existing lists, preserve intended entries, and obtain authorization before broadening access. Redirect writes require exact app name/access-impact confirmation and production opt-in where applicable. Persistence is not a successful OAuth callback test.

## Identity and wallet settings

- **Account merging:** future customer identity linking by shared email, not dashboard team merging. Switching back does not undo identities already linked.
- **Customer-app CAPTCHA:** hCaptcha/Turnstile settings are not the dashboard login challenge. hCaptcha needs compatible frontend SDKs; the observed React minimum is `react-auth@3.9.0`. Do not break the frontend by enabling a setting without checking compatibility.
- **Embedded-wallet auto-creation:** Ethereum/Solana can be configured independently. Preserve existing recovery options and ownership mode. Dashboard auto-create applies to Privy-modal login, not every whitelabel method; persistence does not prove a wallet was created at login.
- **Access allowlists/denylists:** app-user access, not developer membership. The list modes are mutually exclusive. Inspect bounded current lists, preserve unrelated entries, and explicitly authorize clearing/disabling; persistence is not proof of actual login enforcement.
- **Session lifetimes:** app-user sessions, not CLI session duration. Session-impact flags acknowledge disruption; they are not permission to invalidate unrelated users.
- **IP allowlist:** app-secret server-to-server requests, not local CLI networking. Use actual authorized backend ranges, not documentation examples.
- **Android fingerprints:** public certificate SHA256 fingerprints, not signing keys. Full-list replacement/clear can disrupt native login/passkeys; a synthetic fingerprint does not prove certificate ownership.

## Export permissions and Privy Home

`config key-export` blocks/allows app key exports; `config client-key-export` controls client-side export eligibility. Account and wallet-mode gates apply. A gate refusal is not permission to enable unrelated features or migrate ownership.

`config privy-home` controls users' export permission in Privy Home; it is not a generic recovery operation. It requires supported Privy login. These commands require exact-name/access-impact confirmations for changes and **never retrieve a private key**.

## Verification-key rotation

`config verification-key get` returns a fingerprint. `rotate` changes the app token verification/signing key—not an app API secret and not an external JWT verifier. It requires exact `--confirm-name`, `--allow-access-change`, `--allow-session-impact`, `--yes`, and production opt-in where applicable.

Plan consumer updates before rotation: direct-key consumers must update; JWKS consumers must obtain the current key. Successive rotations can invalidate older sessions. Rotate once for an authorized request, inspect the fingerprint afterward, and never repeat automatically after a timeout or unverified response. Fingerprint change is not a measured end-user session-invalidation test.

Custom JWT has separate account capability/app verifier semantics: `privy docs read jwt`. Custody/Bridge onboarding, paid production conversion and wallet recovery/ownership migrations are not supported management shortcuts.
