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

Use exact IDs, returned cursors and resource-specific filters from schema. Most lists are bounded to one page by default; `--all --max-pages 5` is explicit bounded traversal, not a guarantee of completeness. Preserve `truncated` and `next_cursor` in your report when relevant. User records/export contents may be personal data despite credential redaction.

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
