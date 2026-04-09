# AuthForge Python SDK

Official Python SDK for [AuthForge](https://authforge.cc) — credit-based license key authentication with HMAC-verified heartbeats.

**Zero dependencies.** Standard library only. Works on Python 3.9+.

## Quick Start

Copy `authforge.py` into your project, then:

```python
from authforge import AuthForgeClient

client = AuthForgeClient(
    app_id="YOUR_APP_ID",           # from your AuthForge dashboard
    app_secret="YOUR_APP_SECRET",   # from your AuthForge dashboard
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
| `heartbeat_mode` | str | required | `"SERVER"` or `"LOCAL"` (see below) |
| `heartbeat_interval` | int | `900` | Seconds between heartbeat checks (default 15 min) |
| `api_base_url` | str | `https://auth.authforge.cc` | API endpoint |
| `on_failure` | callable | `None` | Callback `(reason: str, exc: Exception | None)` on auth failure |
| `request_timeout` | int | `15` | HTTP request timeout in seconds |

## Heartbeat Modes

**SERVER** — The SDK pings the AuthForge API every `heartbeat_interval` seconds with a fresh nonce. Each response is cryptographically verified. If the license is revoked or the session expires, the failure handler triggers.

**LOCAL** — No network requests during heartbeats. The SDK verifies the stored HMAC signature and checks that the session hasn't expired. When the prepaid block runs out, it makes a single network call to refresh. Use this for apps where you want minimal network overhead.

## Failure Handling

If authentication fails (login rejected, heartbeat fails, signature mismatch, etc.), the SDK calls your `on_failure` callback if one is provided. If no callback is set, **the SDK calls `os._exit(1)` to terminate the process.** This is intentional — it prevents your app from running without a valid license.

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
    heartbeat_mode="SERVER",
    on_failure=handle_auth_failure,
)
```

## How It Works

1. **Login** — Collects a hardware fingerprint (MAC, CPU, disk serial), generates a random nonce, and sends everything to the AuthForge API. The server validates the license key, binds the HWID, deducts a credit, and returns a signed payload. The SDK verifies the HMAC-SHA256 signature and nonce to prevent replay attacks.

2. **Heartbeat** — A background daemon thread checks in at the configured interval. In SERVER mode, it sends a fresh nonce and verifies the response. In LOCAL mode, it re-verifies the stored signature and checks expiry without network calls.

3. **Crypto** — Every response is signed with a key derived from `SHA256(appSecret + nonce)`. The signing key changes on every call, making replay and MITM attacks impractical.

## Hardware ID

The SDK generates a deterministic hardware fingerprint by hashing:
- MAC address
- CPU identifier
- Disk serial number

Each component falls back gracefully if it can't be read (e.g. permissions issues). The HWID is sent with every auth request so the server can enforce per-device license limits.

## Test Vectors

The `generate_vectors.py` script and `test_vectors.json` file are provided for cross-SDK verification. If you're porting this SDK to another language, your implementation must produce identical `derivedKeyHex` and `signatureHex` values for the same inputs.

## Requirements

- Python 3.9+
- No external packages

## License

MIT