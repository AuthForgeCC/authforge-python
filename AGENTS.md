# AuthForge SDK: AI Agent Reference

> This file is optimized for AI coding agents (Cursor, Copilot, Claude Code, etc.).
> It contains everything needed to correctly integrate AuthForge licensing into a project.

## What AuthForge does

AuthForge is a license key validation service. Your app activates by sending a license key + hardware ID to `POST /auth/validate`; the server checks revocation, expiry, HWID binding, and credits, then returns an Ed25519-signed session with a TTL. By default the app then runs through the **grace period**: it keeps running on the signed session with no network calls, and a background check fails when the session TTL expires. Optionally, enable **online check-ins** (`online_heartbeat=True`): periodic `POST /auth/heartbeat` calls for fast revocation and concurrent-use detection. If the license is revoked or expired, the check-in fails and you handle it (typically exit the app).

There is also a **separate** mode for machines that can never reach the internet: **offline license files (`.authforge`)**. The operator mints a signed file in the AuthForge cloud; `login_from_file()` verifies it locally with the app public key and the machine HWID, with zero network calls. Do not ship the App Secret in those builds (`app_secret=None`). Only use it when the user explicitly asks for air-gapped / offline-file licensing. The default integration is always online `login()` + grace period.

## Billing model (so you can pick sensible intervals)

- **1 `login()` or `validate_license()` = 1 credit** (one `/auth/validate` debit each).
- **10 online check-ins = 1 credit** (billed on every 10th successful `/auth/heartbeat` per license). Grace period checks are local and free.
- **1 offline file mint = 1 credit** (charged to the operator when the file is minted). `login_from_file()` / `verify_license_file()` cost nothing.
- Keep `heartbeat_interval` at `>= 10` seconds (`900` / 15 min is the typical desktop default). `/auth/heartbeat` is limited to 6 requests/minute per license key, and revocations still take effect on the **next** check-in.

## Installation

Prefer **`pip install authforge-sdk`** from [PyPI](https://pypi.org/project/authforge-sdk/) (installs the `cryptography` dependency). Imports remain **`from authforge import ...`**. For a vendored single-file layout, copy `authforge.py` and add `cryptography` to your environment. Requires Python 3.9+.

## Minimal working integration

```python
import sys
from typing import Optional

from authforge import AuthForgeClient


def on_failure(reason: str, exc: Optional[Exception]) -> None:
    print(f"AuthForge: {reason}", file=sys.stderr)
    if exc is not None:
        print(exc, file=sys.stderr)
    sys.exit(1)


def main() -> None:
    client = AuthForgeClient(
        app_id="YOUR_APP_ID",
        app_secret="YOUR_APP_SECRET",
        public_key="YOUR_PUBLIC_KEY",  # required: base64 Ed25519 key from the dashboard
        on_failure=on_failure,
    )
    license_key = input("Enter license key: ").strip()
    if not client.login(license_key):
        print("Login failed.", file=sys.stderr)
        sys.exit(1)
    # --- Your application code starts here ---
    print("Running with a valid license.")
    # --- Your application code ends here ---
    client.logout()


if __name__ == "__main__":
    main()
```

This activates once and then runs through the grace period (no network) until the session TTL expires. To detect revocations quickly or catch concurrent use, add `online_heartbeat=True` (and optionally tune `heartbeat_interval`).

## Constructor parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `app_id` | `str` | yes | n/a | Application ID |
| `app_secret` | `str \| None` | for online APIs | n/a | Application secret. Required for `login` / `validate_license` / `self_ban`. Pass `None` or `""` for `login_from_file` only; do not ship it in air-gapped binaries. |
| `public_key` | `str \| Sequence[str]` | yes | n/a | Base64 Ed25519 public key from the dashboard. Accepts one key, a list, or a comma-separated string; the SDK trusts a signature matching **any** entry (key rotation) |
| `heartbeat_mode` | `str \| None` | no | `None` | Deprecated shim: `"LOCAL"` maps to the default (grace period), `"SERVER"` maps to `online_heartbeat=True`. Emits a `DeprecationWarning` when provided (case-insensitive) |
| `heartbeat_interval` | `int` | no | `900` | Seconds between background checks (minimum `10`); applies to grace period checks and online check-ins |
| `api_base_url` | `str` | no | `https://auth.authforge.cc` | API base URL |
| `on_failure` | `Callable[[str, Optional[Exception]], None] \| None` | no | `None` | Called on activation/check-in/network failure; if omitted, process exits via `os._exit(1)` (not used by `validate_license`) |
| `request_timeout` | `int` | no | `15` | HTTP timeout (seconds) |
| `ttl_seconds` | `int \| None` | no | `None` (server default: 86400) | The grace period duration: how long the app keeps running on the signed session without contacting AuthForge. Server clamps to `[3600, 604800]` (1h to 7d); preserved across check-in refreshes. |
| `hwid_override` | `str \| None` | no | `None` | Optional custom HWID/subject string. When set to a non-empty value (for example `tg:123456789`), the SDK sends it instead of generating a machine fingerprint. |
| `online_heartbeat` | `bool` (keyword-only) | no | `False` | Enable online check-ins: periodic `POST /auth/heartbeat` for fast revocation and concurrent-use detection |

For Telegram/Discord bot flows, prefer immutable IDs (`tg:<user_id>`, `discord:<user_id>`) instead of usernames.

## Migrating from heartbeat_mode

Earlier releases required `heartbeat_mode="LOCAL"` or `"SERVER"` as the 4th argument. It is now optional and deprecated (still accepted, but emits a `DeprecationWarning`):

- `heartbeat_mode="LOCAL"`: remove the argument; the grace period is the default.
- `heartbeat_mode="SERVER"`: replace with `online_heartbeat=True`.

The attribute `client.heartbeat_mode` still exists for back-compat and reflects the effective policy (`"SERVER"` when online check-ins are enabled, `"LOCAL"` otherwise).

## Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `login(license_key: str)` | `bool` | Activates: validates the license online, verifies signatures, starts the background check thread |
| `validate_license(license_key: str)` | `ValidateLicenseResult` | Same validate + signatures as login; no session persistence or background checks; **never** calls `on_failure` or `os._exit` |
| `login_from_file(path_or_text: str)` | `bool` | Offline mode: verifies a `.authforge` file locally (no network), authenticates the client, never starts background checks. Failures -> `on_failure("offline_login_failed", exc)` + `False`; never `os._exit` |
| `verify_license_file(path_or_text, *, now=None)` | `VerifyLicenseFileResult` | Same offline checks without changing client state |
| `get_offline_license()` | `dict \| None` | `jti`, `expires_at`, `hwid_policy`, … of the offline file in use |
| `get_session_kind()` | `"online" \| "offline" \| None` | Kind of session the client holds; `None` when logged out |
| `get_hwid()` | `str` | HWID this client sends; the customer reports it so the operator can mint a bound file |
| `logout()` | `None` | Stops background checks and clears session state |
| `is_authenticated()` | `bool` | Whether a session token is present and marked authenticated |
| `get_session_data()` | `dict \| None` | Decoded signed payload map |
| `get_app_variables()` | `dict \| None` | App-scoped variables |
| `get_license_variables()` | `dict \| None` | License-scoped variables |

## Error codes the server can return

Full set (`KNOWN_SERVER_ERRORS`): invalid_app, invalid_key, expired, revoked, hwid_mismatch, no_credits, app_burn_cap_reached, blocked, rate_limited, replay_detected, app_disabled, session_expired, revoke_requires_session, bad_request, malformed_request, system_error

Notes:
- `replay_detected` is validate-only. `rate_limited` can be returned by `/auth/validate` and `/auth/heartbeat` (heartbeat is license-limited at 6/min and has no app-layer IP limit).
- `app_burn_cap_reached` means the app's configured credit burn cap is hit; `revoke_requires_session` means a pre-session self-ban tried to revoke a license (only session-authenticated self-ban can revoke).
- `session_expired` is also raised locally when the grace period (session TTL) runs out.

## Common patterns

### Reading license variables (feature gating)

```python
vars_map = client.get_license_variables() or {}
tier = vars_map.get("tier")
```

### Graceful shutdown

```python
client.logout()
```

### Offline license file (air-gapped machine, only when asked)

```python
# Step 1 (customer machine): print the HWID so the operator can bind the file to it.
print(client.get_hwid())

# Step 2 (operator): mint the .authforge file in the dashboard or via
# POST /v1/licenses/{licenseKey}/offline-files and deliver it out-of-band.

# Step 3 (customer machine): authorize with the file. No network, no check-ins.
if not client.login_from_file("license.authforge"):
    # on_failure already received ("offline_login_failed", ValueError(code)) where code is one of
    # bad_armor | bad_signature | unsupported_version | malformed_payload | wrong_app | expired | hwid_mismatch
    sys.exit(1)
```

Offline file error codes (in check order): `bad_armor`, `bad_signature`, `unsupported_version`, `malformed_payload`, `wrong_app`, `expired`, `hwid_mismatch`.

### Custom error handling

Server error codes appear as `ValueError` in the `exc` passed to `on_failure` from failed validation (e.g. `invalid_key`). Reasons are `login_failed`, `heartbeat_failed`, or `network_error`.

```python
import sys
from typing import Optional

def on_failure(reason: str, exc: Optional[Exception]) -> None:
    if isinstance(exc, ValueError) and exc.args:
        code = str(exc.args[0])
        if code in {"invalid_key", "expired", "revoked"}:
            print(f"License issue: {code}", file=sys.stderr)
    sys.exit(1)
```

## Do NOT

- Do not hardcode the app secret as a plain string literal in source: use environment variables or encrypted config
- Do not embed the App Secret in air-gapped / `login_from_file` builds: pass `None` or `""`; verification only needs app id + public key
- Do not skip the `on_failure` callback: without it, background check failures terminate the process via `os._exit(1)` without your cleanup
- Do not call `login()` on every app action: call it once at startup; the grace period (or online check-ins) handles the rest
- Do not pass `heartbeat_mode` in new code: it is deprecated. Use the default grace period, or `online_heartbeat=True` when you need fast revocation or concurrent-use detection
- Do not treat the grace period as persistent offline licensing: it is session continuation after one successful online activation, and revocations are only picked up at the next online validate or check-in
- Do not reach for `login_from_file()` unless the user explicitly needs air-gapped / offline-file licensing: the default is online `login()` + grace period
- Do not expect an online revoke to disable an offline file that is already on a customer machine: the file stays valid until its own `expiresAt`; prefer short expiries and HWID-bound files
- Do not mint or accept `hwid.mode: "any"` files casually: anyone who copies an unbound file has a working license
- Do not call `login_from_file()` with another app's public key or app id: the file is rejected with `bad_signature` / `wrong_app` by design
- Do not try to build `.authforge` files client-side: only the AuthForge cloud holds the signing key; there is no BYO issuer
- Do not call `self_ban()` or any other online method after `login_from_file()`: an offline session has no server session (`get_session_kind()` is `"offline"`), so `self_ban()` raises `ValueError("offline_session")` without contacting the server and online check-ins never start; machines that can reach AuthForge should use online `login()`
- Do not bind an offline file to an HWID reported by a different SDK or language: HWID fingerprints are not portable across SDKs, so collect the HWID from the exact SDK build that will load the file (or use the HWID override with an identifier you control)
