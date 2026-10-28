# Authenticate the CLI

The CLI uses a dashboard administrator session, not an app API secret or a wallet-CLI login. Normal login does not require a debugging browser or Chrome session extraction. It remains an unofficial dashboard integration, not an officially supported management authorization contract.

```sh
privy doctor
privy --profile work auth login
privy --profile work auth status --remote
```

## Reuse a saved session first

`auth login` with saved credentials attempts **one session renewal**, persists the result and directly verifies remote dashboard access. It does this before requiring an interactive terminal, so an agent can recover expired access without hitting an “already logged in” refusal. Success reports `sessionAction`, `refreshAttempted`, `credentialsChanged`, `remoteVerified` and the selected profile. It does not report success merely because credentials exist.

An explicit renewal rejection returns `LOGIN_REQUIRED` with a profile-qualified fresh-login action. Use `auth login --replace` deliberately to sign in again; no automatic fresh login, logout or local deletion occurs. Network failures,5xx, unexpected responses or storage errors stop without retry/fallback because renewal may be uncertain. `SESSION_ACCESS_UNVERIFIED` means renewal returned but the subsequent access check failed; any saved renewal is retained. Inspect `auth status --remote` before deciding what to do next.

`--replace` intentionally bypasses reuse. If saved credentials exist, `--email` or `--cdp` also requires `--replace` so a request for a specific identity/import is not silently treated as renewal of another saved identity.

## Fresh login needs a human

When no credentials exist, or when explicitly using `--replace`, use an interactive terminal and a normal browser on the same machine. Login asks for the dashboard email, opens a temporary loopback verification page, and waits for genuine browser hCaptcha verification. Complete any challenge normally. Then enter the email code at this exact terminal prompt:

`Login code (input won't be displayed):`

Input is hidden, including pasted characters. There is no code flag, environment variable, or chat-based OTP handoff. Agents should ask the operator to complete this terminal/browser step, not collect the code themselves. Login uses no-signup mode and validates dashboard access before saving credentials. No email send or exchange is automatically retried. MFA/SSO workarounds are not supported.

During fresh login, `auth login --no-open` prints the local verification URL for manual opening. `--timeout` bounds the fresh-login flow, default300 seconds. A browser opener failure can be recovered manually; a headless environment lacking an interactive terminal, same-machine browser or secure store is not a supported onboarding workflow.

## Storage and profiles

Dashboard login credentials live in the OS credential store: macOS Keychain, Windows Credential Manager or Linux Secret Service. There is no plaintext fallback. Linux needs a running Secret Service. Live validation is macOS arm64; Windows/Linux and a wider browser/MFA/SSO matrix are not claimed.

Profiles separate saved sessions and selected apps. Nonsecret configuration is at `${XDG_CONFIG_HOME:-~/.config}/privy-cli/PROFILE.json`. Profile precedence is explicit `--profile`, then `PRIVY_PROFILE`, then the nearest `privy.json` profile, then `default`. See `privy docs read app-lifecycle` for app selection and protection. Profiles and project directories are conveniences, not an OS security boundary.

## Diagnose before replacing a session

- `doctor`: local runtime/browser-launcher/terminal/store checks, no API requests. It does not prove remote authentication.
- `auth status`: saved credential presence and local expiry, no network or renewal. `access_expired` does **not** mean the saved session cannot be renewed.
- `auth status --remote`: one remote access check, no refresh, save or deletion. Inspect `state`, `remote.authenticated` and `refreshValidity`; exit0 only means inspection completed. An access401 does not establish refresh-token validity. Output includes the selected profile and a structured `recommendedAction`; the suggestion has not been executed.
- Ordinary API commands can refresh near-expiry credentials and persist rotation. `auth whoami` may refresh and returns identity/account information.
- `auth login` with saved credentials and `auth refresh`: one deliberate renewal, persistence and a direct remote access check. Expired access alone does not prove the refresh token has failed. An explicit session-expired response leaves the local entry intact for deliberate replacement; it is not treated as usable access. Do not loop refresh on a 5xx/timeout; rotation may have happened even if the response was lost.
- `auth logout`: revoke this session, then remove local credentials; revocation failure retains them. Independent resource secrets are retained.
- `auth logout --local`: remove local credentials without revoking remotely. `auth login --replace`: replace the saved session without revoking the previous one. Neither is a harmless diagnostic.

The browser need not remain open after normal login. Server/gateway failures do not alone establish invalid auth or API drift. See `privy docs read recovery`.

## Optional explicit CDP import

`auth login --cdp http://127.0.0.1:9222` imports an already-authenticated session from a debugging-enabled browser. It is never an automatic fallback and is not an independent CLI login.

Chrome includes CDP, but an ordinary open/logged-in Chrome or Brave window does not normally expose a remote-debugging endpoint. Recent Chrome requires a separate user-data directory for remote debugging. Use a dedicated profile, keep the endpoint loopback-only, authenticate there deliberately, and close debugging when finished. Do not target a personal browser profile.

**Imported browser and CLI share a session.** CLI logout revokes it; refresh-token rotation can invalidate the other client's older credentials. Do not silently import, replace or log out a shared session to fix a diagnostic error.
