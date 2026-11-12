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

`privy` does from the terminal what you'd otherwise click through in the Privy dashboard. It signs in as a dashboard admin, outputs JSON and makes every change explicit. The CLI documents itself, so use it rather than guessing.

## Setup

1. Check it's installed: `command -v privy`. If not, ask the user before running `npm install -g @awesamarth/privy-cli`.
2. Check login: `privy auth status --remote` (read-only). The session is in the OS keychain, not env vars, so missing `PRIVY_*` variables don't mean the user is logged out.
3. If access has expired, `privy auth login` renews a saved session without human input. If it returns `LOGIN_REQUIRED` or there is no session, **stop and ask the user to run `privy auth login` in their own terminal**: it needs a browser CAPTCHA and an email code typed into a hidden prompt. Never ask for the code in chat.
4. Get real IDs from `privy accounts list` and `privy apps list`. Don't guess, and ask if more than one could match.

## Then let the CLI guide you

```sh
privy cli search "what the user wants"   # finds the right command
privy schema <command>                   # inputs, required confirmations, how it verifies
privy docs read <topic>                  # workflow guides, offline
```

Preview with `--dry-run` (offline) or `--diff` (reads live state, writes nothing), then run with `--yes` plus whatever confirmations the schema lists.

## Rules

- Only make the changes the user asked for. Confirmation flags confirm a request; they don't widen it.
- Secrets go through stdin only (`--body -`), never command arguments, chat or files.
- If a write fails or times out, read the current state before doing anything else. Never retry blindly; see `privy docs read recovery`.
- Refusals like `ACCOUNT_APPROVAL_REQUIRED` are real gates. Report them; don't work around them.
- Don't run `auth logout` or `auth login --replace` unless the user asks.
- It never signs transactions, moves funds, exports private keys or touches billing.
