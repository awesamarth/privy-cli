# Privy CLI · unofficial

An agent-friendly CLI for managing **Privy developer accounts and apps**, inspired by Cloudflare `cf` and Stripe CLI. Not affiliated with or endorsed by Privy. This is **not** Privy's agent-wallet CLI and does not sign transactions.

**Discover → schema → preview/diff → execute → verify.** JSON output by default, local workflow guides, explicit mutations and OS-backed credential storage. Operations use direct HTTPS—not browser automation. Most management endpoints are undocumented dashboard APIs and can change.

## Install

**Private pre-release; not published to npm and not production-ready.** Given a locally supplied package artifact:

```sh
npm install -g ./awesamarth-privy-cli-0.1.0.tgz
privy --help
```

Requires **Node.js 22.18+** and an unlocked OS credential store. Bun is development tooling only, not an end-user requirement. Runtime dependencies are Commander and an OS-keyring adapter; no bundled browser, Playwright or SDK stack.

Live onboarding validation is macOS arm64. Linux Secret Service, Windows credential/browser integration, and wider browser/MFA/SSO support are not claimed. A headless environment without a secure store, interactive terminal and same-machine browser is not a supported onboarding workflow.

## Login and choose context

```sh
privy doctor
privy --profile work auth login
privy --profile work auth status --remote
privy --profile work accounts list
privy --profile work apps list
```

Normal login uses your browser for CAPTCHA verification and a **hidden terminal prompt** for the email code. Do not paste codes into chat. No debugging port is needed. `auth status --remote` checks access without refreshing or changing credentials; inspect `remote.authenticated`, not only the exit code.

Profiles separate sessions and saved app selections. `project show` explains effective context; `project init` can bind a directory to an app without storing credentials. Profile precedence is flag → environment → directory binding → default; app precedence is flag → matching directory binding → saved selection. Account-scoped operations require explicit `--account`.

Read `privy docs read authentication` for session recovery and the optional **shared-session** CDP import; `privy docs read app-lifecycle` covers context and protection.

## Discover the exact operation

```sh
privy cli search "enable google login"
privy schema apps config update
privy apps config update --help
privy docs read providers
```

Search returns up to five commands with schema/guide pointers. Schema is the installed version's syntax authority: inputs, scope, confirmations and verification behavior. No skill installation, source checkout, login or network is required for discovery.

A fresh agent may not discover an installed binary on its own. A request such as “Use the Privy CLI to create an app called my-new-test and enable Google login” makes the intended tool explicit without prescribing commands.

For a new development app (replace uppercase placeholders with discovered IDs):

```sh
privy --profile work apps create --account ACCOUNT_ID --name my-dev-app --secret-store env --env-output .env.local --dry-run
privy --profile work apps create --account ACCOUNT_ID --name my-dev-app --secret-store env --env-output .env.local --yes

# Use the returned app ID; creation does not select or bind it implicitly.
privy --profile work --app APP_ID apps config update --google-oauth true --diff
privy --profile work --app APP_ID apps config update --google-oauth true --yes
privy --profile work --app APP_ID project init --yes
privy project show
```

Choose app-secret storage explicitly: `env`, `keychain`, `both` or `none`. Env destinations must be untracked/ignored inside Git; existing target variables require `--overwrite-env`. CLI login sessions stay in the OS vault. See [credentials/secrets](docs/user/secrets.md) for server-only variables, storage choices and partial-failure recovery.

Google's built-in login toggle does not universally require own OAuth credentials. Provider-specific setup is separate. A persisted flag is **not** a real Google sign-in test.

## Bundled workflow guides

```sh
privy docs                         # Topic index
privy docs search "uncertain write"
privy docs read recovery           # Markdown content inside JSON
privy docs path                    # Absolute directory for a file reader
```

Guides ship with the CLI and work offline:

- [Getting started](docs/user/getting-started.md): agent workflow, input/output and consent.
- [Authentication](docs/user/authentication.md) · [App lifecycle/context](docs/user/app-lifecycle.md).
- [Login providers](docs/user/providers.md) · [JWT authentication](docs/user/jwt.md) · [Security settings](docs/user/security.md).
- [Credentials/secrets](docs/user/secrets.md) · [Webhooks](docs/user/webhooks.md).
- [Policies/approvals](docs/user/policies.md) · [Users/wallets/exports](docs/user/resources.md).
- [Clients/integrations/global wallets](docs/user/integrations.md) · [Accounts/analytics](docs/user/accounts.md).
- [Failure recovery](docs/user/recovery.md): partial success, uncertain writes and verification limits.

## Operating rules and limits

- JSON results on stdout; structured errors/progress on stderr. Exit codes: 0 success, 1 runtime/API failure, 2 usage/safety refusal, 130 cancellation. Redaction is not anonymization.
- `--dry-run` validates offline. `--diff`, where supported, reads live state without writing. Execution needs the operation's confirmations; risk flags do not authorize extra work.
- Boolean values are explicit. Arrays replace entire arrays. Sensitive API input requires piped JSON, never argv, chat or plaintext body files. Generated app API secrets can be saved directly to an explicitly chosen server env file and/or OS vault; values are never printed. `secrets run` trusts its child; **child output is not redacted**.
- No automatic write retry or rollback. After a timeout or verification failure, inspect state before repeating an operation. Check truncation, job status and pending-review fields; acknowledgement is not completion.
- Management covers users, wallets, policies/quorums, webhooks, credentials/clients, app settings/providers, workspace membership and analytics. Use the bundled guides for each workflow's prerequisites.
- No wallet signing/transactions, private-key export, owner-approval execution, billing setup, production conversion, custody onboarding or ownership/recovery migrations. Do not enable unrelated features or contact real providers just to bypass a gate.
- Configuration verification does not prove external login, DNS ownership, webhook receipt, wallet deployment or frontend behavior. Controlled credentials/resources are needed for those checks.

## Planned

- **End-to-end Global Wallet walkthrough:** two-app connection requests, approvals and enable/disable flows using a Privy-approved provider workspace. The management commands already exist; provider availability requires Privy account approval. No release date is committed.

## From a source checkout

Use `bun install`, `bun run typecheck`, `bun run build`, then `bun pm pack` to create a local artifact. Packing is not publishing. The package includes compiled code, the public `docs/user/` guides, README and package metadata. Local maintainer notes and research are git-ignored and excluded from the package.
