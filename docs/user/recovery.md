# Recover without duplicating writes

A failed command does not always mean nothing changed. The CLI does not automatically retry writes or roll them back. If a response was lost, a write was acknowledged but verification failed, or cancellation happened after sending, inspect remote state before any new mutation.

## Read the structured error

Errors go to stderr and expose safe `code`, `message`, and available `status`, `hint`, `requestId`, `retryAfterSeconds` or `details`. Raw API error bodies/auth headers are omitted. Do not invent a cause when metadata is absent. Keep request IDs for support, not credentials.

| Situation | Next step |
| --- | --- |
| Usage/unknown field/type error | Read the exact command schema and compare local inputs. Unknown names are intentionally omitted because they can contain credentials. Correct input; do not guess endpoint paths. |
| Protection/confirmation/production refusal | Check target and user's actual authorization. Do not remove protection or add risk flags simply to force success. |
| Missing external secret, DNS ownership, owner authorization or feature eligibility | State the prerequisite and stop. Do not fabricate credentials, automate challenges, submit unrelated approval requests or change billing. |
| Expired/rejected access401 | Inspect `auth status`; expired access does not establish invalid refresh. A deliberate `auth refresh` may recover it. Do not repeatedly log in/import/replace/logout shared sessions. |
| 5xx/520, timeout, cancellation or unreadable successful response | Outcome may be uncertain. Inspect the exact resource/collection, including current permissions and pagination. A server/gateway failure alone does not prove bad credentials or a changed API contract. |
| Acknowledged write, `verified:false`, pending review or verification failure | Report incomplete verification, not rollback or completion. Read current state. Do not repeat a state-changing operation just to get a verified response. |
| Local vault/index/context cleanup failure after remote success | Repair the reported local reference/context. Do not recreate or repeat remote deletion. |

`retryAfterSeconds` does not grant permission to blindly retry a write. Be especially careful with session refresh: the server may have rotated credentials even if the response was lost.

## Common partial-success cases

- **App create:** list apps in the intended account and inspect exact-name matches before another create. Names may not be unique. Do not guess an app ID; if matches are ambiguous, ask. A later config failure does not erase an already-created app.
- **JWT initial setup:** `JWT_SETUP_PARTIAL_OR_UNCERTAIN` can mean app auth enabled but verifier configuration failed. Read `config custom-jwt get`; explicitly correct or disable if authorized. No rollback occurred.
- **Generated app API secrets:** `apps create` and `credentials create` require a choice of env, Keychain, both or none. `APP_SECRET_CAPTURE_FAILED` means remote creation succeeded but local storage did not fully complete. Inspect the resource/reference, per-destination statuses and reason; `both` writes Keychain first, so a file failure need not mean the value is lost. Inspect env files privately, never print them in chat. `none` is deliberate discard, not a failure. If metadata verification fails after capture, saved values are retained. No automatic rollback/recreation occurs; see `privy docs read secrets`.
- **Webhook signing-key save / vault indexing:** a remote resource may exist even if local capture/indexing failed. Inspect metadata and the reported `secrets status` reference. Webhook creation and key retrieval remain separate operations. `SECRET_INDEX_FAILED` explicitly means vault storage succeeded but indexing failed.
- **Logo upload:** inspect `global-wallet logo status UPLOAD_ID` and the current icon. A retained checkpoint can permit explicit finalize without repeating transfer. Forgetting it does not delete a public hosted image.
- **Webhook test/replay:** an acknowledgement is not delivery, and another send can duplicate receiver actions. Check history and controlled receiver logs before any deliberate replay.
- **Bulk import/export:** submission is not completion. Inspect job status and partial results; export warehouse lag is not proof of absence.
- **Delete:** verify absence while retaining parent/account access. A permission error is not absence. Verified app deletion does not rewrite a stale `privy.json` or remove app secrets from env files; repair bindings and obsolete local variables deliberately.

## Report evidence, not optimism

Separate request acceptance, persisted configuration, local secret capture, external behavior and cleanup. For example: “Google login flag is enabled and read back; a real Google sign-in was not exercised.” If the prerequisite is missing, a safe, precise stop is preferable to unauthorized expansion or false completion.
