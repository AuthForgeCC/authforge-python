# Changelog

## 1.5.0

### Features

- Self-serve offline activation: `AuthForgeClient.activate_offline(license_key, path=None) -> bool` calls `POST /auth/offline/activate` once and turns a license key into a lifetime `.authforge` file bound to this machine's HWID (the same HWID `login()` sends). The SDK verifies the file locally (public key(s), app id, HWID) before writing it, writes it byte-for-byte and atomically to `path` (creating parent directories), and authenticates the client exactly as `login_from_file()` does. `get_offline_license()["replay"]` is `True` when the server returned a file the machine already had. Needs the App Secret. Billing: 1 new offline activation = 2 credits for the app owner; re-activating the same machine is free.
- On failure `activate_offline()` raises `AuthForgeError`, writes nothing (an existing file at `path` is left untouched), does not authenticate the client (an existing session is kept) and never calls `on_failure` or `os._exit`. An empty license key, then a missing App Secret, raise the usual `ValueError` before any request.
- New server codes, all fatal and added to `KNOWN_SERVER_ERRORS` and `DEFINITIVE_ERROR_CODES`: `offline_activation_disabled`, `offline_activation_requires_perpetual`, `offline_activation_requires_seats`, `offline_activation_limit_reached`.
- New SDK codes: `offline_file_rejected` (fatal, also listed in `KNOWN_SERVER_ERRORS` and `DEFINITIVE_ERROR_CODES`; the returned file failed local verification, the verifier's reason is in the message) and `file_write_failed` (transient; the verified file could not be written). A success response without a `file` raises `unexpected_response` (transient).
- Tests run the shared `self_serve_activation_vectors.json` conformance vectors.

## 1.4.1

### Fixes

- Without an `on_failure` callback, a transient background check failure (network outage, timeout, `rate_limited`, `system_error`, `no_credits`, ...) no longer ends the process. The SDK prints one line to stderr, `AuthForge: background check failed (<code>); retrying next interval`, keeps the session and checks in again on the next interval. Previously a brief outage killed any app that enabled online check-ins without setting a callback.
- Unchanged: without a callback, definitive failures (including the `session_expired` a transient failure becomes once the session TTL has passed) and failed `login()` calls still call `os._exit(1)`.

### Docs

- The README and `AGENTS.md` examples no longer call `os._exit(1)` from `on_failure`. They set a `threading.Event` that the main thread checks so it can save work and exit, mention `_thread.interrupt_main()` for blocked main threads, and keep `os._exit` as a last resort after saving.

## 1.4.0

### Behavior changes for callers

- `on_failure("heartbeat_failed", exc)` now always receives an `AuthForgeError` (a `ValueError` subclass) with `exc.code`, `exc.transient` and `exc.fatal`. For server codes `str(exc)` equals the code. `is_transient_error()` and `DEFINITIVE_ERROR_CODES` are exported; `TRANSIENT_ERROR_CODES` lists the named transient codes for reference.
- Classification: only `revoked`, `expired`, `hwid_mismatch`, `blocked`, `session_expired`, `malformed_request`, `app_disabled`, `invalid_app` and `signature_mismatch` are definitive. Everything else is transient, including `no_credits`, `demo_quota_exceeded`, `app_burn_cap_reached`, `bad_request`, `invalid_key`, every `http_error_<status>` and unknown codes.
- Transient heartbeat failures are reported and background checks keep running on the next interval. Previously the loop stopped after any failure. After the session TTL passes, the next transient failure is reported as a definitive `session_expired`; grace-period expiry also reports `session_expired`.
- Definitive heartbeat failures clear the stored session (as `logout()` does) and stop background checks before `on_failure` runs. Previously the session stayed authenticated.
- New code `unexpected_response` (transient): a failed check-in whose body is not a JSON object with `"status": "failed"` and a non-empty `error` string. The message includes the raw `status` and `error`.
- Request retries: only `rate_limited`, or HTTP 429 with no error code, is retried (after 2s, then 5s). `no_credits`, `demo_quota_exceeded` and `app_burn_cap_reached` on HTTP 429 are no longer retried. This also applies to `login()` and `validate_license()`.
- Heartbeat network failures no longer also fire `on_failure("network_error", ...)`; they are reported once as `heartbeat_failed` with code `network_error` or `timeout`.
- Server codes this SDK doesn't know are passed through as-is instead of becoming `unknown_error` (also in `validate_license()` results).
- HTTP errors with a non-JSON body (`http_error_<status>`), network failures and unparseable responses now raise `AuthForgeError` instead of `RuntimeError` / plain `ValueError`.
- `on_failure` runs with no SDK lock held, so it may call `logout()`, `is_authenticated()` or `login()`. A check-in still in flight during `logout()` or `login()` is discarded instead of restoring the old session.
