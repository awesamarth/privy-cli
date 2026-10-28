# Choose context and manage a development app

An **account/workspace** owns apps and developer membership. An **app** owns customer users, wallets and settings. The API calls accounts `teams`; that does not imply collaborators exist. App-scoped user **organizations** are a third, different resource.

## Resolve context before touching resources

```sh
privy project show
privy accounts list
privy apps list
```

`project show` is local and reports effective profile/app and their sources; it does not establish remote access. Use exact IDs from lists when names are ambiguous. Account-scoped operations require an explicit `--account ACCOUNT_ID`; selecting an app does not select its account for unrelated account commands.

Profile precedence: `--profile` → `PRIVY_PROFILE` → nearest `privy.json` profile → `default`.
App precedence: `--app` → nearest project binding for the matching profile → saved profile selection → error. There is no automatic first-app selection. An explicit/environment profile different from a manifest's profile ignores that manifest's app binding.

`apps use APP_ID` saves a profile selection; `project init` writes a directory binding instead. `--no-project` ignores the directory binding, not profile protection. Inspect/trust repository bindings before operational use; malformed files and symlinks fail closed.

## Create, configure, bind

Discover the account first. If more than one fits and the user did not specify one, ask rather than guess.

```sh
privy schema apps create
privy apps create --account ACCOUNT_ID --name my-dev-app --secret-store env --env-output .env.local --dry-run
privy apps create --account ACCOUNT_ID --name my-dev-app --secret-store env --env-output .env.local --yes
```

Creation returns read-back verified app ID/name/environment plus the chosen secret-storage result. Choose `--secret-store env|keychain|both|none` before creation; non-interactive commands and dry-runs require it. Env/both need `--env-output`, use `PRIVY_APP_SECRET` by default, preserve unrelated variables and require `--overwrite-env` to replace an existing target variable. Inside Git the destination must be untracked/ignored. Values never appear in output; `none` deliberately discards the value. Read `privy docs read secrets` for file safeguards, interactive choices and partial storage failures. CLI login storage is unchanged.

Creation does not implicitly select the app or bind a folder. Use the returned ID explicitly in subsequent commands. If creation times out, list apps in the intended account and inspect matches **before** creating again; if local storage/read-back fails after creation, inspect the reported app ID and destination statuses instead of creating another app. See `privy docs read recovery`.

For ordinary Google login, own OAuth credentials are optional; the built-in login toggle is separate from `providers update google`:

```sh
privy --app APP_ID apps config update --google-oauth true --diff
privy --app APP_ID apps config update --google-oauth true --yes
privy --app APP_ID apps config get --field google_oauth
privy --profile work --app APP_ID project init --dry-run
privy --profile work --app APP_ID project init --yes
privy project show
```

Use the actual profile instead of `work`. Binding writes only `privy.json` in the current folder:

```json
{"version":1,"profile":"work","appId":"APP_ID"}
```

It contains no credentials and does not create a remote app. Existing files require `--force --yes`. Binding does not change the profile's saved selection. Read `privy docs read providers` for provider-specific prerequisites; successful configuration is not an end-user sign-in test.

## Update narrowly

`apps config update` patches only supplied fields. Arrays such as allowed origins replace the complete existing list. Inspect schema and live diff first; preserve unrelated entries. `config get/update` are compatibility aliases. More specialized settings have their own commands; use task search instead of guessing fields on the generic patch.

Writes require `--yes`; supported production mutations additionally require `--allow-production`. Unknown environments fail closed. A risk flag acknowledges a requested action; it is not authorization to upgrade, enable unrelated features or alter another account.

## Protection and deletion

`apps protect APP_ID` records a per-profile local block, filters app lists and refuses app-specific operations before credential access, including previews. It is not server authorization or OS credential isolation. Account-wide mutations refuse accounts containing a protected app. A manifest cannot override protection.

```sh
privy --app DISPOSABLE_APP_ID apps delete --dry-run
privy --app DISPOSABLE_APP_ID apps delete --confirm-name exact-app-name --yes
```

Deletion is irreversible and removes the app and its users. It requires explicit `--app` even with a binding, exact current name and `--yes`. Only development apps are supported; there is no production-delete override. The confirmation body is generated, not supplied by the caller.

Deletion is verified by absence from the same still-visible account, not an assumed HTTP404. A matching saved selection and indexed resource secrets are cleaned up after verified deletion. Directory manifests are not rewritten; inspect `projectBindingNeedsUpdate` and deliberately remove/rebind a stale manifest. Local cleanup failure is not a reason to repeat remote deletion.
