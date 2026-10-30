# Users, wallets, organizations and exports

These are **app-scoped** resources. Establish the correct profile/app with `project show` and lists before using IDs. Customer user organizations are not dashboard accounts/workspaces; creating one does not create a developer team.

## Inspect narrowly and paginate honestly

```sh
privy users count
privy users list --limit 20
privy wallets list --chain-type ethereum
privy policies list
privy key-quorums list
privy cli search "organizations"
```

Use exact IDs, returned cursors and resource-specific filters from schema. Most lists are bounded to one page by default; `--all --max-pages 5` is explicit bounded traversal, not a guarantee of completeness. Preserve `truncated` and `next_cursor` in your report when relevant.

For cursor-paginated lists, `pagination.requested_limit`, `page_counts`, `returned_page_counts` and `end_reason` show what was actually fetched. `page_counts` counts rows retained per page; `returned_page_counts` also exposes lookahead rows for endpoints that require display-page slicing. `has_more` is the backward-compatible **continuation-available** indicator, not a guarantee of another nonempty page. A terminal empty page can be legitimate. Never infer an empty page merely from total count and request count, and never stop early solely because a page is shorter than requested.

User lists default to20 per request. `--all` follows cursors with the current command's page size; it does not inherit a previous invocation's `--limit 100`. To compare behavior, keep app/filter/limit identical:

```sh
privy users list --limit 100
privy users list --limit 100 --all --max-pages 5
```

For example, `page_counts: [29, 0]` explicitly shows a terminal empty page; `[20, 9]` does not. `end_reason` is `single_page`, `max_pages_reached` or `cursor_exhausted`. Pagination diagnostics contain counts rather than user records. User records/export contents may be personal data despite credential redaction.

## Summary lists and full detail

`users list` and `wallets list` now return overview rows by default. **This changes their default row shape:** callers that need the previous detailed records should add `--full`. The `data` envelope, record order, filters, pagination and truncation semantics are unchanged. Other resource lists, individual `get` commands and mutation responses are unchanged.

- **Users:** `id`, `names`, `emails`, `linked_account_types`, `wallet_count`. Names combine the reported display name and linked-account names; emails combine linked-account email values and email-account addresses. Both arrays deduplicate exact nonempty strings, preserve reported order and do not designate a primary identity. Missing names/emails produce empty arrays, not invented values. Types include wallet when present, not just login-capable accounts. `wallet_count` counts linked accounts of type `wallet`, not a separate query for wallet resources. Full linked-account details, timestamps and account state remain available through `users get` or `--full`.
- **Wallets:** `id`, `address`, `chain_type`, `type`, `user_id`, `owner_id`. The owner reference is the returned `auth_key.id`, otherwise `user_id`, otherwise null. A null summary reference is **not** authorization to change ownership or proof a wallet is unowned. Inspect `wallets get` for control/policy/entity details. `--include-balance true` retains full rows automatically so explicitly requested balance details are not stripped; the API still determines whether balances are available.

```sh
privy users list --all --max-pages 5          # summaries across pages
privy users list --all --full --max-pages 5   # full records across pages
privy users get USER_ID                      # one full record
privy wallets list --full
privy wallets get WALLET_ID
```

**`--all` means more records; `--full` means more detail per record.** `--full` alone does not fetch extra pages, bypass redaction or change any internal preflight/verification read. Summaries still contain personal data; do not expose them in public recordings or shared logs. Full output is unnecessary for routine discovery, but inspect full state before decisions that depend on omitted fields. The third summary-enabled command, `global-wallet providers list`, is described in the integrations guide.

## Users

Discover import, update, freeze/restore, unlink, revoke-session, bulk-job and delete commands by task. They have different consequences; an import submission is not proof every row succeeded. Inspect completed job status, per-record outcomes and exact user state before retrying partial imports. Do not resend invitations, email or other customer actions just to verify a configuration.

Existing-user custom metadata has dedicated public-API commands. They require a stored app API credential via `--credential CREDENTIAL_ID` plus dashboard preflight. Full replacement and merge are different operations; inspect schema and diff, retain unrelated keys, and respect the flat metadata/size limits. See `privy docs read secrets`.

Freeze/restore or session-revocation acknowledgement is not an observed real-user login/session-invalidation test. Deletion and unlinking can be irreversible; act only on the requested exact user.

## Wallets and organizations

Wallet creation provisions a wallet but does not fund or transact with it. Owner assignment, policy/signer changes and organization binding affect control. Referenced users/quorums/policies/wallets must belong to the selected app and satisfy chain/owner rules. Organization bindings are one-way; do not bind a wallet as a temporary test and promise to undo it later.

Owner-managed mutations are refused without a supported authorization path; do not ask for private keys or bypass approval. Wallet archive is **not deletion**: it stops writes/signing, needs an explicit stored full-access app credential and exact wallet confirmation, and has no CLI restoration. Only eligible unowned wallets can be archived through this workflow.

Deleting an app-user organization requires verified zero active **and archived** wallet bindings and exact name confirmation. Do not infer it is empty from a single truncated active-wallet page. Read-only transaction history and balances do not execute transactions.

## Private CSV exports

Export commands submit jobs; warehouse data can lag. Inspect readiness before downloading. A job acknowledgement or zero-row file does not independently prove there are no live users/wallets.

Downloads require `--output` naming a new private file. They do not print personal records to stdout, overwrite existing files, or follow arbitrary signed-download redirects. Keep exports out of repositories and shared logs, and delete them when no longer needed. CSV wallet export is **not private-key export**.
