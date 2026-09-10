# AuthForge SDK: AI Agent Reference

> This file is optimized for AI coding agents (Cursor, Copilot, Claude Code, etc.).
> It contains everything needed to correctly integrate AuthForge licensing into a project.

## What AuthForge does

AuthForge is a license key validation service. Your app activates by sending a license key + hardware ID to `POST /auth/validate`; the server checks revocation, expiry, HWID binding, and credits, then returns an Ed25519-signed session with a TTL. By default the app then runs through the **grace period**: it keeps running on the signed session with no network calls, and a background check fails when the session TTL expires. Optionally, enable **online check-ins** (`online_heartbeat=True`): periodic `POST /auth/heartbeat` calls for fast revocation and concurrent-use detection. If the license is revoked or expired, the check-in fails and you handle it (typically exit the app).

## Billing model (so you can pick sensible intervals)

- **1 `login()` or `validate_license()` = 1 credit** (one `/auth/validate` debit each).
- **10 online check-ins = 1 credit** (billed on every 10th successful `/auth/heartbeat` per license). Grace period checks are local and free.
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
| `app_secret` | `str` | yes | n/a | Application secret |
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
- Do not skip the `on_failure` callback: without it, background check failures terminate the process via `os._exit(1)` without your cleanup
- Do not call `login()` on every app action: call it once at startup; the grace period (or online check-ins) handles the rest
- Do not pass `heartbeat_mode` in new code: it is deprecated. Use the default grace period, or `online_heartbeat=True` when you need fast revocation or concurrent-use detection
