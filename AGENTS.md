# AuthForge SDK — AI Agent Reference

> This file is optimized for AI coding agents (Cursor, Copilot, Claude Code, etc.).
> It contains everything needed to correctly integrate AuthForge licensing into a project.

## What AuthForge does

AuthForge is a license key validation service. Your app sends a license key + hardware ID to the AuthForge API, gets back a cryptographically signed response, and runs background heartbeats to maintain the session. If the license is revoked or expired, the heartbeat fails and you handle it (typically exit the app).

## Billing model (so you can pick sensible intervals)

- **1 `login()` = 1 credit** (one `/auth/validate` debit).
- **10 heartbeats = 1 credit** (billed on every 10th successful heartbeat per license).
- Any `heartbeat_interval` is safe — from `1` (server apps) to `900` (15 min, desktop apps). Revocations always take effect on the **next** heartbeat regardless of interval.

## Installation

Copy `authforge.py` into your project (single file, stdlib only). Requires Python 3.9+.

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
        heartbeat_mode="SERVER",
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

## Constructor parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `app_id` | `str` | yes | — | Application ID |
| `app_secret` | `str` | yes | — | Application secret |
| `heartbeat_mode` | `str` | yes | — | `"SERVER"` or `"LOCAL"` (case-insensitive) |
| `heartbeat_interval` | `int` | no | `900` | Seconds between heartbeats (any value ≥ 1) |
| `api_base_url` | `str` | no | `https://auth.authforge.cc` | API base URL |
| `on_failure` | `Callable[[str, Optional[Exception]], None] \| None` | no | `None` | Called on login/heartbeat/network failure; if omitted, process exits via `os._exit(1)` |
| `request_timeout` | `int` | no | `15` | HTTP timeout (seconds) |
| `ttl_seconds` | `int \| None` | no | `None` (server default: 86400) | Requested session token lifetime. Server clamps to `[3600, 604800]`; preserved across heartbeat refreshes. |

## Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `login(license_key: str)` | `bool` | Validates license, verifies signatures, starts heartbeat thread |
| `logout()` | `None` | Stops heartbeat and clears session state |
| `is_authenticated()` | `bool` | Whether a session token is present and marked authenticated |
| `get_session_data()` | `dict \| None` | Decoded signed payload map |
| `get_app_variables()` | `dict \| None` | App-scoped variables |
| `get_license_variables()` | `dict \| None` | License-scoped variables |

## Error codes the server can return

invalid_app, invalid_key, expired, revoked, hwid_mismatch, no_credits, blocked, rate_limited, replay_detected, session_expired, app_disabled, bad_request

Notes:
- `rate_limited` and `replay_detected` can only be returned from `/auth/validate`. Heartbeats are not IP rate-limited and do not enforce nonce replay.

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

- Do not hardcode the app secret as a plain string literal in source — use environment variables or encrypted config
- Do not skip the `on_failure` callback — without it, heartbeat failures terminate the process via `os._exit(1)` without your cleanup
- Do not call `login()` on every app action — call it once at startup; heartbeats handle the rest
- Do not use `heartbeat_mode="LOCAL"` unless the app has no internet after initial auth
