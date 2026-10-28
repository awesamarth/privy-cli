# Policies, rules and owner authorization

Policies describe wallet authorization; creating one does not attach it to a wallet or execute a transaction. Changes to an already-attached policy can change existing wallets' permissions. Inspect its owner and use before editing.

```sh
privy schema policies create
privy policies create --name payout-guard --chain-type ethereum --dry-run
privy policies create --name payout-guard --chain-type ethereum --yes
privy policies get POLICY_ID
```

An empty rules array defaults to deny. Supported chain values and policy version are listed in schema; `ethereum` also covers EVM/Tempo networks. Creation can assign a same-app owner quorum only with explicit `--confirm-owner`. That assignment changes later authorization requirements and does not authorize the CLI to sign.

## Rule lifecycle

A rule has `name`, `method`, `action` (ALLOW/DENY) and `conditions`. For example, a rule that denies all methods:

```json
{"name":"deny-all","method":"*","action":"DENY","conditions":[]}
```

Save nonsecret policy definitions locally if useful; body files are appropriate for these public definitions. Inspect `schema policies rules create` before writing. Privy validates nested policy-language semantics and chain/method compatibility; do not extrapolate unverified conditions from an unrelated chain.

```sh
privy policies rules create POLICY_ID --file rule.json --dry-run
privy policies rules create POLICY_ID --file rule.json --yes
privy policies get POLICY_ID
privy policies rules update POLICY_ID RULE_ID --file rule.json --diff
privy policies rules update POLICY_ID RULE_ID --file rule.json --yes
```

Rule update is a **complete four-field replacement**, despite HTTP PATCH. Conditions arrays replace the entire array. Remove response-only `id` fields before reusing a fetched object as input. Policy update currently renames only. Writes require `--yes` and production opt-in when applicable; fresh policy reads verify configuration, not transaction enforcement.

Rule deletion verifies absence in the parent policy. Policy deletion requires exact `--confirm-name`, unowned status and backend `deletable:true`; it verifies absence while retaining app access. Do not detach wallets, migrate ownership or delete dependent resources implicitly to make a policy deletable.

## Quorums and approvals

Key quorums register **public** P-256 keys and/or nested quorum members, unique membership and threshold. The CLI does not generate/store their private halves. Retain your signing keys in an appropriate secure system; a registered public key is not proof you possess its private key.

Owner-managed policy/wallet changes require owner authorization or a dashboard approval flow. The CLI deliberately refuses rather than forging signatures or bypassing approval. `approvals` commands inspect metadata and hand off human review (use `--no-open` to print the URL). They do not authorize or execute proposals. Do not ask for private keys or pursue MFA/signing simply to bypass a refusal.
