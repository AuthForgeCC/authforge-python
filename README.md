# AuthForge Python SDK

Official Python SDK for [AuthForge](https://authforge.cc) — credit-based license key authentication with Ed25519-verified responses.

Uses `cryptography` for Ed25519 verification. Works on Python 3.9+.

## Quick Start

Install from PyPI:

```bash
pip install authforge
```

Or copy `authforge.py` into your project directly, then:

```python
from authforge import AuthForgeClient

client = AuthForgeClient(
    app_id="YOUR_APP_ID",           # from your AuthForge dashboard
    app_secret="YOUR_APP_SECRET",   # from your AuthForge dashboard
    public_key="YOUR_PUBLIC_KEY",   # from your AuthForge dashboard
    heartbeat_mode="SERVER",        # "SERVER" or "LOCAL"
)

license_key = input("Enter license key: ")

if client.login(license_key):
    print("Authenticated!")
    # Your app logic here — heartbeats run automatically in the background
else:
    print("Invalid license key.")
    exit(1)
```

## Configuration

| Parameter | Type | Default | Description |
|---|---|---|---|
| `app_id` | str | required | Your application ID from the AuthForge dashboard |
| `app_secret` | str | required | Your application secret from the AuthForge dashboard |
| `public_key` | str | required | App Ed25519 public key (base64) from dashboard |
| `heartbeat_mode` | str | required | `"SERVER"` or `"LOCAL"` (see below) |
| `heartbeat_interval` | int | `900` | Seconds between heartbeat checks (any value ≥ 1; default 15 min) |
| `api_base_url` | str | `https://auth.authforge.cc` | API endpoint |
| `on_failure` | callable | `None` | Callback `(reason: str, exc: Exception | None)` on auth failure |
| `request_timeout` | int | `15` | HTTP request timeout in seconds |
| `ttl_seconds` | `int \| None` | `None` (server default: 86400) | Requested session token lifetime. Server clamps to `[3600, 604800]`; preserved across heartbeat refreshes. |

## Billing

- **1 `login()` call = 1 credit** (one `/auth/validate` debit).
- **10 heartbeats on the same license = 1 credit** (billed every 10th successful heartbeat).

A desktop app running 6h/day at a 15-minute interval burns ~3–4 credits/day. A server app running 24/7 at a 1-minute interval burns ~145 credits/day — pick the interval based on how fast you need revocations to propagate (they always land on the **next** heartbeat).

## Methods

| Method | Returns | Description |
|---|---|---|
| `login(license_key)` | `bool` | Validates key and stores signed session (`sessionToken`, `expiresIn`, `appVariables`, `licenseVariables`) |
| `logout()` | `None` | Stops heartbeat and clears all session/auth state |
| `is_authenticated()` | `bool` | True when an active authenticated session exists |
| `get_session_data()` | `dict \| None` | Full decoded payload map |
| `get_app_variables()` | `dict \| None` | App-scoped variables map |
| `get_license_variables()` | `dict \| None` | License-scoped variables map |

## Heartbeat Modes

**SERVER** — The SDK calls `/auth/heartbeat` every `heartbeat_interval` seconds with a fresh nonce, verifies signature + nonce, and triggers failure on invalid session state.

**LOCAL** — No network calls. The SDK re-verifies stored signature state and checks expiry timestamp locally. If expired, it triggers failure with `session_expired`.

## Failure Handling

If authentication fails (login rejected, heartbeat fails, signature mismatch, etc.), the SDK calls your `on_failure` callback if one is provided. If no callback is set, **the SDK calls `os._exit(1)` to terminate the process.** This is intentional — it prevents your app from running without a valid license.

Recognized server errors:
`invalid_app`, `invalid_key`, `expired`, `revoked`, `hwid_mismatch`, `no_credits`, `blocked`, `rate_limited`, `replay_detected`, `app_disabled`, `session_expired`, `bad_request`

Request retries are automatic inside the internal HTTP layer:
- `rate_limited`: retry after 2s, then 5s (max 3 attempts total)
- network failure: retry once after 2s
- every retry regenerates a fresh nonce

```python
def handle_auth_failure(reason, exception):
    print(f"Auth failed: {reason}")
    if exception:
        print(f"Details: {exception}")
    # Clean up and exit gracefully
    sys.exit(1)

client = AuthForgeClient(
    app_id="YOUR_APP_ID",
    app_secret="YOUR_APP_SECRET",
    public_key="YOUR_PUBLIC_KEY",
    heartbeat_mode="SERVER",
    on_failure=handle_auth_failure,
)
```

## How It Works

1. **Login** — Collects a hardware fingerprint (MAC, CPU, disk serial), generates a random nonce, and sends everything to the AuthForge API. The server validates the license key, binds the HWID, deducts a credit, and returns a signed payload. The SDK verifies the Ed25519 signature and nonce to prevent replay attacks.

2. **Heartbeat** — A background daemon thread checks in at the configured interval. In SERVER mode, it sends a fresh nonce and verifies the response. In LOCAL mode, it re-verifies the stored signature and checks expiry without network calls.

3. **Crypto** — Both `/validate` and `/heartbeat` responses are signed by AuthForge with your app's Ed25519 private key. The SDK verifies every signed `payload` using your configured `public_key` and rejects tampered responses.

## Hardware ID

The SDK generates a deterministic hardware fingerprint by hashing:
- MAC address
- CPU identifier
- Disk serial number

Each component falls back gracefully if it can't be read (e.g. permissions issues). The HWID is sent with every auth request so the server can enforce per-device license limits.

## Test Vectors

The shared `test_vectors.json` file validates cross-language Ed25519 verification behavior.

## Requirements

- Python 3.9+
- Dependency: `cryptography`

## License

MIT