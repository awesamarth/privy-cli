# Accounts, memberships and analytics

An account/workspace owns apps, capabilities and developer members. The dashboard API's `teams` terminology does not prove you have collaborators. App-user `organizations` are different resources. App-user account merging is also unrelated to developer membership.

```sh
privy accounts list
privy cli search "account members"
privy schema accounts get
privy accounts billing status --account ACCOUNT_ID
```

Use an explicit account ID discovered from the authenticated account list. Selecting an app does not authorize changing the account that owns it. Account-wide operations can affect every app, including ones not selected locally. Protected-app accounts are refused for mutation.

## Members and invitations

Inspect schema for list/invite/change/remove/revoke operations. Membership identities are omitted by default where supported; request `--include-identities` only when needed and keep output private. Use an authorized actual invitee for real delivery; a reserved `.invalid` address can only demonstrate persistence/revocation, not acceptance.

Changes require the exact account name and `--yes`. Accounts containing production apps additionally require production opt-in where supported. Self-impact needs explicit acknowledgement; the last-admin guard remains non-bypassable. Quorum/member dependencies can block removal. Do not delete dependencies or demote someone else automatically to make an operation succeed.

Acceptance may ask an existing identity to leave its current account before joining. Do not leave, migrate or empty an existing account merely to complete a test; use a separate controlled identity instead. Any real account migration needs its own explicit authorization and impact review.

An invitation acknowledgement is not an accepted second member. Positive role-change/removal verification requires that controlled member to have actually joined. Fresh membership read-back verifies stored role/state, not every downstream permission effect. No automatic write retries or rollback.

## Capabilities and billing

`accounts features custom-jwt` is a narrowly implemented free/all-development capability workflow, separate from per-app JWT authentication; read `privy docs read jwt`. It is not a generic feature-activation command. A disabled feature does not by itself prove a billing requirement, but it also does not authorize account activation.

`accounts billing status` reports safe tier/payment-presence metadata only. Missing default-payment-method information is not a guarantee that production conversion is free or can proceed without payment setup. There are no billing-write/checkout or automatic production-conversion workflows. Do not submit approval requests, payment information or paid provisioning just to complete a CLI check.

## Analytics

`cli search "analytics"` finds direct JSON analytics commands. Inspect schema for date, chain and filter bounds; date ranges are capped at366 days. Treat sparse/zero data and freshness metadata honestly. Empty data does not make the endpoint unimplemented, nor prove live resources are absent. Warehouse delays and a bounded requested interval matter. Use dedicated live resource lists/counts when the question is about current resources, and preserve truncation/freshness caveats.
