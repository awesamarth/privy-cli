# External integrations and app clients

Use the CLI to configure integrations and inspect their prerequisites. Vendor setup and frontend connection flows are separate from management commands; `externalIntegrationVerified` distinguishes those outcomes from saved configuration. The CLI does not provision paid services, fund wallets, deploy smart wallets, sign transactions, configure a vendor account, or silently enable unrelated features.

## Clients, origins and cookie domains

App clients represent frontend/native configurations and may override session, origin, Telegram or Apple settings. Their IDs and public SDK IDs are not app API secrets. Inspect app inheritance before replacing a client override.

Allowed origins and OAuth redirect restrictions are distinct from **HTTP-only cookie domains**. Cookie-domain configure/verify/delete needs an authorized owned hostname and DNS changes. A configured hostname is not verified DNS. App and web-client domain scopes differ; deleting an override can affect inheritance. Disabling/deleting cookies requires explicit session-impact acknowledgement, and deletion needs the exact current hostname. Do not change unrelated DNS or broaden origins to bypass eligibility. See `privy docs read security`.

Client-domain `configure` is setup-only, unlike the app-level toggle. Repeating the same existing client configuration is a read-only no-op; trying to toggle it refuses with `CLIENT_DOMAIN_SETUP_ONLY`. To remove a client domain, use explicit `clients domains delete` with the exact hostname and session-impact confirmation. Recreating it is a separate action and requires checking DNS/certificate verification again.

## Provider configuration

Use `cli search` and schema for exact fields:

- **WalletConnect/Reown:** a public cloud project ID; set/clear does not create a Reown project or test pairing.
- **Coinbase Onramp:** controlled provider credentials through stdin. Configuration does not enable a funding method or initiate a purchase.
- **Kraken Embed:** full credential configuration and explicit provider staging/production. That environment is separate from Privy app dev/prod. A404 read represented as `not_returned` is not proof that the configuration never existed.
- **Blockaid:** configuration changes require a production app, plus cookie-domain/ecosystem eligibility. Development writes refuse with `BLOCKAID_PRODUCTION_REQUIRED`, even with verified cookies. Do not convert to production, set up billing, publish the app or request account approval merely to get past this restriction.
- **Smart wallets:** full enabled provider/network configuration, or explicit disable. Endpoint arrays require stdin because URL paths/queries may contain credentials. Schema lists supported provider versions and chain fields. A stored bundler/paymaster URL does not demonstrate deployment, sponsorship, funding or signing. Disabled read-back does not establish whether hidden inactive settings were retained.

Never submit fake secrets or `.invalid` endpoints and describe the resulting persistence as successful external behavior. Read `privy docs read secrets` for input handling.

## Global-wallet connections and availability

Global-wallet availability means **this app's embedded wallets are available to other apps**, not npm publication or wallet deployment. `global-wallet availability get` reports prerequisites. Development needs verified enabled cookies or custom experience URLs; production needs verified enabled cookies; account approval is also required. This CLI does not perform approval/billing/production setup implicitly. Pending review is not published.

Custom connect/transact/auth URLs can be configured without publishing. Permission/signup changes have their own cookie gate. Keep unrelated controls unchanged.

Provider/requester commands act on exact counterparts from the selected app's connection lists. Protect both app IDs. An enable is not an implicit request for invite-only access; use a deliberate request only when authorized. Accept/reject can grant/revoke cross-app access, and approval may have irreversible effects after the other app enables integration. Do not send requests to real vendors just to test the CLI. Fresh relationship status is not proof of an end-user SDK connection.

### Planned: complete two-app walkthrough

An end-to-end Global Wallet walkthrough will cover controlled provider/requester setup and connection request, approval, enable and disable flows on a Privy-approved workspace. The existing commands above remain available for eligible apps; this planned walkthrough does not promise account approval or a release date.

## Public logo hosting

`global-wallet logo` edits the cross-app connection icon, not the login-modal branding logo. Upload accepts a regular PNG/JPEG/WebP file up to8 MiB; signature checks are not a complete image decoder. **Original bytes and metadata go to public image hosting even when the app stays private.** Upload only public-safe files.

Inspect schema before `upload`. `--stage-only` hosts the image without attaching it; `status UPLOAD_ID` and `finalize UPLOAD_ID` use an app/profile-bound OS-vault checkpoint. After partial failure, inspect status before another transfer. Checkpoints are removed after verified attachment. Forgetting one only abandons local recovery metadata; it does not delete the hosted image. No image-deletion or atomic attachment guarantee is claimed. The local SHA256 need not match CDN-transformed bytes, and HTTP200 is not browser-rendering proof.
