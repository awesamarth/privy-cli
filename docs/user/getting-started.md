# Use Privy CLI without guessing

This unofficial CLI manages Privy developer accounts and applications. It is not Privy's agent-wallet CLI, and it does not sign transactions. Dashboard APIs are undocumented and may change. A working configuration is not proof of external login, webhook delivery or wallet execution.

## Discover only what you need

Installing a CLI does not advertise it to every agent. For a fresh agent, naming “Privy CLI” in the request makes tool choice explicit without supplying commands. An agent that has not checked the CLI must not infer there is no login merely because no `PRIVY_*` environment variables exist: dashboard login credentials live in the OS store, not environment variables. App API secrets are separate and may be saved to an explicitly chosen server env file, the OS vault, both or neither.

```sh
privy cli search "enable google login"
privy schema apps config update
privy apps config update --help
privy docs read providers
```

Search returns up to five commands. Schema is the installed version's syntax authority: required arguments, body types, enums, scope, confirmations, examples and verification behavior. Use CLI input fields, not a copied raw API response; when present, `cliBody` describes input before the API envelope is applied. The `guides` field points to workflow context. Do not dump every schema or repeatedly walk nested help.

`privy docs` lists local guides; `docs search "words"` searches their contents; `docs read TOPIC` returns Markdown inside JSON. `docs path [TOPIC]` returns an absolute path for a reader. Guides are bundled with the installed CLI, require no login/network, and are not a mirror of Privy's website. Examples containing APP_ID, ACCOUNT_ID or other uppercase identifiers require real values discovered from the appropriate list command.

## A safe operating sequence

1. Check `privy project show` to learn effective context. If needed, check `auth status --remote`, then list accounts/apps. Never guess IDs or silently choose between ambiguous accounts.
2. Search the requested task and inspect the exact command's schema. Read its guide when prerequisites or impact are unclear.
3. Use `--dry-run` to validate and preview offline. Where offered, `--diff` reads live state without writing. They are different modes and cannot be combined. Offline success does not establish permissions, eligibility or that an ID exists.
4. Execute only the user's requested changes, with the listed confirmations. `--yes`, `--allow-production` and impact flags are execution controls, not permission to expand scope. Ask for human input when intent or credentials are missing, not for every routine command already authorized.
5. Check returned verification fields and fresh state where needed. Report what changed and what remains unverified. For an error after a possible write, inspect state before another mutation; see `privy docs read recovery`.

## Input and output

- JSON goes to stdout; progress and structured errors go to stderr. Exit codes: 0 success, 1 runtime/API failure, 2 usage/safety refusal, 130 cancellation. Diagnostic exit0 is not proof of authentication or successful delivery.
- Select one JSON source: `--body '{...}'`, `--file patch.json`, or `--body -`/`--file -` for stdin. Input is bounded to 1 MiB. Typed flags may add different fields; duplicate fields and unknown fields fail.
- Boolean values are explicit, such as `--google-oauth true`. Array flags contain JSON, such as `--allowed-domains '["https://app.example.com"]'`. Arrays replace the whole array; preserve intended entries. Use JSON `null` only for nullable fields. Some operations are full replacements, even when their HTTP method is PATCH.
- Before `apps create` or `credentials create`, choose `--secret-store env|keychain|both|none`; env/both also need `--env-output`. Agents must make this choice explicitly, not silently discard a generated key. Never assume the user's preferred destination; see `privy docs read secrets`.
- Sensitive fields require piped JSON. Never put credentials in shell arguments, shell history, plaintext body files, chat or logs. Do not fabricate credentials to get past a prerequisite. See `privy docs read secrets`.
- Output redaction is not anonymization. User records and public resource metadata can still be sensitive. Static schema declarations describe secret fields; that does not mean actual secret values will be returned.
- `users list`, `wallets list` and `global-wallet providers list` return summaries by default. Use the individual user/wallet `get` command or add `--full` when omitted detail is needed. Existing consumers of their old detailed rows should add `--full`. This only affects displayed fields, not internal safety checks; redaction still applies. `wallets list --include-balance true` also retains full rows to preserve requested balance detail. Other commands are unchanged. See `privy docs read resources` and `privy docs read integrations` for exact fields.
- Most paginated lists return one page (usually20, maximum100). Follow `next_cursor`, or use bounded `--all --max-pages 5`. Inspect `has_more` and `truncated`; `--all` is not unlimited. Collection-only commands describe different limits in their schema. `--all` controls how many records are returned; `--full` controls detail per record, not completeness.

## Boundaries

No automatic write retries or rollback. No billing setup, production conversion, custody onboarding, private-key export, wallet signing or owner-approval execution. Eligibility refusals are not instructions to activate unrelated account features. Authentication needs human browser/terminal input; do not automate challenges. Read the relevant guide before cross-app grants, account-wide changes, key rotation or destructive cleanup.
