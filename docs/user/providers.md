# Configure app-user login methods

App-user authentication is separate from the administrator session used by this CLI. Enabling a login method does not authenticate a user, create a frontend, or demonstrate a successful sign-in.

## Built-in OAuth versus own credentials

For a task such as “enable Google login,” start with:

```sh
privy cli search "login providers"
privy schema apps config update
privy apps config update --google-oauth true --diff
privy apps config update --google-oauth true --yes
privy apps config get --field google_oauth
```

Google and Apple can use built-in/shared configuration; custom credentials are optional/recommended, not universally mandatory. GitHub/Discord and other supported toggles likewise have provider-specific rules. Inspect the field description and provider metadata rather than assuming every provider needs a client secret. Spotify, Instagram and Telegram OAuth require own configuration in the observed contract.

`providers get PROVIDER` reads own configuration metadata. `providers update PROVIDER` edits credentials/options; it does **not** silently enable the app login method. `providers delete PROVIDER` removes editable own configuration; it does not disable login or revoke sessions, and default fallback is provider-specific. Use schema for provider-specific fields and constraints. Secret-bearing updates require stdin JSON; see `privy docs read secrets`.

Custom OAuth is a separate lifecycle (`providers custom ...`). Creation enables the custom provider; it is immutable and deletion may become unavailable after signup. Do not create a throwaway or fake provider as a substitute for controlled real credentials.

## Telegram has distinct modes

Bot-based `telegram_auth` is different from `telegram_oauth`. For bot-based login:

```sh
privy providers telegram get
privy schema providers telegram update
privy schema apps config update
```

Initial bot configuration requires `bot_id`, `bot_secret`, `bot_name`, and `seamless_auth_enabled`. The numeric token prefix is `bot_id`; the secret portion is `bot_secret`; the bot username is `bot_name`. Both token parts must be supplied together through stdin. Ask the operator to provision the authorized bot and supply credentials through a secure local input path, **not chat, arguments or plaintext files**. Do not invent a bot/token or enable login before the required configuration exists.

Bot configuration does not silently enable app login. After configuration and public metadata read-back, enable the intended app toggle explicitly if authorized. Client-specific bot overrides use `clients telegram`; deleting an override can restore app inheritance. A successful public-field read-back does not verify the masked bot secret or a Telegram login.

## Frontend, redirects and related settings

Allowed origins, OAuth redirect restrictions and HTTP-only cookie domains are separate controls. Do not broaden origins to `*` or configure DNS just to bypass a failure. Redirects must match explicitly configured allowed origins; see `privy docs read security`. Cookie domains need an authorized owned hostname and DNS changes; see `privy docs read integrations`.

Embedded-wallet creation, passkey signup, email filters, app-user session lifetimes and CAPTCHA have dependencies described in their schemas. Preserve recovery/ownership settings. Do not activate administrator MFA/SSO, change billing, or perform a real user login as an implicit side effect of a settings request.

Report the exact evidence: “Google flag persisted and read back” is not “Google sign-in tested.” When actual provider credentials/frontend setup are unavailable, state the prerequisite and stop rather than claiming completion.
