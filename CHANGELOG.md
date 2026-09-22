# Changelog

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
