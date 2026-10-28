# Configure webhooks without confusing submission with delivery

Use only an authorized HTTPS receiver. Callbacks can disclose user data, and replay can repeat business actions. A reserved `.invalid` URL can demonstrate configuration/failure handling, not successful delivery. Do not create a public third-party receiver or send real user records there merely to get a green check.

```sh
privy cli search "webhook endpoint"
privy schema webhooks create
privy webhooks list
privy docs read secrets
```

Discover the exact create/subscription/history commands with `cli search` and schema. Endpoint creation does not retrieve its signing key automatically. After creation, the explicit `webhooks signing-key save ENDPOINT_ID --yes` workflow retrieves it directly into the selected profile/app OS vault, not stdout. Inspect the returned reference with `secrets status`; do not print the key. Subscription settings affect **all app endpoints**, not only the endpoint currently being inspected. Adding an endpoint does not implicitly change subscriptions.

## Configuration and verification

1. Inspect existing endpoints/subscriptions and the selected app/environment.
2. Preview the requested operation and preserve intended complete lists.
3. Execute with `--yes` and production opt-in when needed. Delete/test/resend/enable additionally require the exact `--confirm-url` where listed by schema.
4. Inspect fresh endpoint/subscription state and signing-key presence. Metadata verification is not receiver delivery proof.
5. If explicitly authorized, submit a test event and inspect history/attempt status. Validate receipt and signature at the controlled receiver separately. A202 or message ID only acknowledges submission.

There is no automatic replay or write retry. After a timeout, inspect history/status before resending. Even if Privy reports delivery, downstream processing may have failed or may not be idempotent; do not repeatedly trigger a business event to force success.

History pagination is bounded. Some message-ID filters can return more rows than the requested page size; the CLI reports this without discarding records. Check truncation and continuation instead of assuming the first page is the entire history.

Deleting an endpoint verifies remote absence and removes its indexed local signing key. If local cleanup fails after verified deletion, use the reported reference to repair local state; do not repeat deletion. `secrets forget` alone does not delete the endpoint or revoke its remote key.
