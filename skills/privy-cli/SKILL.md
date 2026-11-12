---
name: privy-cli
description: Manage Privy developer accounts and apps from the terminal with the unofficial `privy` CLI (npm package @awesamarth/privy-cli). Use when the user wants to create, configure or inspect a Privy app; enable or disable login methods (email, passkeys, wallets, Google, Apple, GitHub, Discord, X/Twitter, Telegram, custom JWT and more); manage app users, wallets, policies, key quorums, webhooks, API credentials, clients, domains, integrations or Global Wallet settings; or read dashboard members and analytics. Not for signing transactions, funding wallets or agent wallets (that is Privy's separate @privy-io/agent-wallet-cli), and not a replacement for Privy SDK code inside an app.
license: MIT
compatibility: Requires Node.js 22.18+, the `privy` command installed globally, an OS credential store (macOS Keychain, Windows Credential Manager or Linux Secret Service), and a human for first-time dashboard login.
metadata:
  author: awesamarth
  homepage: https://github.com/awesamarth/privy-cli
---

# Privy CLI

`privy` does from the terminal what a developer would otherwise click through in the Privy dashboard. It signs in as a dashboard administrator and calls Privy's dashboard APIs, most of which are undocumented and can change. It outputs JSON by default and makes every mutation explicit.

The core loop is **discover → schema → preview → execute → verify**. Follow it instead of guessing flags.

## 1. Make sure it is installed

```sh
command -v privy && privy --version
```

If it is missing, ask the user before installing a global package, then:

```sh
npm install -g @awesamarth/privy-cli   # or: bun add -g / pnpm add -g
```

## 2. Check login and context

```sh
privy project show            # effective profile, app and account, and where each came from
privy auth status --remote    # read-only: one remote check, never renews or changes anything
```

- Dashboard login is stored in the OS credential store, **not** environment variables. Missing `PRIVY_*` variables do not mean the user is logged out.
- In the status output, read `state`, `remote.authenticated` and `recommendedAction`. Exit code 0 only means the check ran.
- If a saved session exists but access has expired, run `privy auth login`. With saved credentials it renews and verifies the session without any human input.
- If that returns `LOGIN_REQUIRED`, or no session exists, **stop and ask the user** to run `privy auth login` in their own terminal. Fresh login needs a browser CAPTCHA and an email code typed into a hidden terminal prompt. Never ask for the code in chat and never try to automate the CAPTCHA.
- Do not run `auth logout`, `auth login --replace` or `auth login --cdp` unless the user explicitly asks.

Then get real IDs. Never guess them, and ask if several accounts or apps could match:

```sh
privy accounts list
privy apps list
```

Target an app with `--app APP_ID` and account-scoped commands with `--account ACCOUNT_ID`. With the user's agreement, `privy --app APP_ID project init --yes` binds the current directory to an app (no credentials are stored in it). Use `--profile NAME` when the user has several dashboard logins.

## 3. Find the exact command

```sh
privy cli search "enable google login"   # up to 5 matching commands with schema and guide pointers
privy schema apps config update          # inputs, enums, required confirmations, verification behavior
privy docs read providers                # workflow guide: prerequisites and pitfalls
```

The installed version's `privy schema` is the authority on syntax. There is no top-level `privy search`; use `privy cli search`. Uppercase placeholders like `APP_ID` in examples must be replaced with values from list commands.

## 4. Preview, execute, verify

```sh
privy --app APP_ID apps config update --google-oauth true --dry-run   # validates offline, no network
privy --app APP_ID apps config update --google-oauth true --diff      # reads live state, shows the change, writes nothing
privy --app APP_ID apps config update --google-oauth true --yes       # executes, then reads back and compares
privy --app APP_ID apps config get --field google_oauth               # independent check if needed
```

- `--dry-run` and `--diff` are different modes and cannot be combined.
- Execution needs `--yes` plus whatever the schema lists, such as `--confirm-name`, `--confirm-account` or `--allow-production`. These flags confirm a change the user asked for; they are not permission to do more.
- Check the verification fields in the result, and tell the user what changed and what is still unverified.
- **No automatic retries or rollback.** If a write fails or times out, read the current state before doing anything else, and see `privy docs read recovery`.

## Common tasks

| Task | Command |
| --- | --- |
| List apps | `privy apps list` |
| Create a dev app | `privy apps create --account ACCOUNT_ID --name NAME --secret-store env --env-output .env.local --yes` |
| Read app config | `privy --app APP_ID apps config get` |
| Toggle a login method | `privy --app APP_ID apps config update --email-auth true --yes` (see `--help` for every provider flag) |
| List or search users | `privy --app APP_ID users list --query user@example.com` |
| Inspect one user or wallet | `privy --app APP_ID users get USER_ID`, `privy --app APP_ID wallets get WALLET_ID` |
| List wallets | `privy --app APP_ID wallets list --chain-type ethereum` |
| Policies | `privy --app APP_ID policies list`, then `privy schema policies create` |
| Webhooks | `privy --app APP_ID webhooks list`, `privy --app APP_ID webhooks create --url URL --yes` |
| New API credential | `privy --app APP_ID credentials create --access-mode read_only --secret-store keychain --yes` |
| Analytics | `privy --app APP_ID analytics overview` |
| Dashboard members | `privy accounts members list --account ACCOUNT_ID` |
| Delete a dev app | `privy --app APP_ID apps delete --confirm-name EXACT_NAME --yes` (only when explicitly asked) |

Add `--dry-run` or `--diff` first for any mutation.

## Input, output and secrets

- JSON results go to stdout; progress and structured errors go to stderr. Exit codes: 0 success, 1 runtime/API failure, 2 usage or safety refusal, 130 cancelled.
- JSON input comes from one source: `--body '{...}'`, `--file patch.json`, or `--body -` for stdin. Booleans are explicit (`--google-oauth true`). Array values replace the whole array, so include the entries you want to keep.
- **Secrets go through stdin only** (`--body -`), never command arguments, chat, logs or plaintext files. Do not invent credentials to get past a prerequisite.
- `apps create` and `credentials create` require `--secret-store env|keychain|both|none`. Ask the user which one; `env` and `both` also need `--env-output PATH` pointing to an untracked or git-ignored file.
- `users list`, `wallets list` and `global-wallet providers list` return summaries. Use `get` or `--full` for detail. Lists return one page; use `--all --max-pages N` and check `has_more` and `truncated`.
- Redacted output can still contain personal data. Don't copy user records into chat unless the task needs them.

## What it will not do

- No wallet signing, transactions, funding or private-key export. For agent wallets, use Privy's `@privy-io/agent-wallet-cli`.
- No billing setup, production upgrades, owner-approved policy/quorum execution or custody onboarding.
- Refusals such as `ACCOUNT_APPROVAL_REQUIRED` or `BLOCKAID_PRODUCTION_REQUIRED` are real gates. Report them to the user; don't enable unrelated features to get around them.
- Saved configuration does not prove the feature works end to end. A Google login toggle being on is not a tested Google sign-in.

## Guides

Bundled guides work offline and match the installed version:

```sh
privy docs                     # topic index
privy docs search "webhook signing"
privy docs read TOPIC
```

Topics: `getting-started`, `authentication`, `app-lifecycle`, `providers`, `jwt`, `security`, `secrets`, `webhooks`, `policies`, `resources`, `integrations`, `accounts`, `recovery`.
