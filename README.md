# AuthForge Python SDK

Official Python SDK for [AuthForge](https://authforge.cc): credit-based license key authentication with Ed25519-verified responses.

Uses `cryptography` for Ed25519 verification. Works on Python 3.9+.

## How licensing works

1. **Activate online.** `login()` calls `POST /auth/validate`. The server checks revocation, expiry, HWID binding, and credits, then returns an Ed25519-signed session with a TTL.
2. **Run through the grace period.** By default the app keeps running on the signed session with no further network calls. A background check re-verifies the signature locally and fails when the session TTL expires. The grace period equals the session TTL: default 24h, and the server clamps requested values to 1h to 7d.
3. **Optionally enable online check-ins.** With `online_heartbeat=True`, the SDK also calls `POST /auth/heartbeat` every `heartbeat_interval` seconds for fast revocation and concurrent-use detection.

Separately, for machines that can **never** reach the internet, an operator can mint a signed **offline license file (`.authforge`)** in the AuthForge dashboard or Developer API. The SDK verifies it locally with your app public key: see [Offline license files](#offline-license-files-authforge).

## Features

Everything in this list ships in `authforge.py` today:

- **License validation** via `POST /auth/validate`, returning a signed session payload.
- **Ed25519 signature verification** on every `/auth/validate` and `/auth/heartbeat` response; tampered or unsigned responses are rejected.
- **Key rotation**: `public_key` accepts a single key, a list of keys, or a comma-separated string. The SDK trusts a signature that matches **any** key in the list, so you can roll the server-side signing key without breaking deployed clients.
- **Grace period by default**: after one successful activation, the app runs on the signed session (no network) until the TTL expires.
- **Online check-ins** (opt-in): periodic `/auth/heartbeat` calls for fast revocation and concurrent-use detection.
- **Offline license files (`.authforge`)**: `login_from_file()` / `verify_license_file()` verify a cloud-minted, Ed25519-signed file with zero network access for air-gapped machines.
- **Nonce anti-replay**: a fresh 128-bit nonce is sent on every request and the echoed nonce in the signed payload is checked before the response is accepted.
- **HWID fingerprinting**: deterministic device hash from MAC + CPU + disk serial, with graceful per-component fallback.
- **`hwid_override`**: bind to any identity instead of the machine (for example `tg:<id>`, `discord:<id>`).
- **Seat enforcement**: the server binds each HWID into a license's free slots up to `maxHwidSlots`; `hwid_count` / `max_hwid_slots` are surfaced on the result. A shared (unlimited-seat) key skips per-device binding.
- **Self-ban** (`self_ban()`) for anti-tamper response, both pre-session and post-session.
- **Grace period duration** control via `ttl_seconds`, with server-side clamping to `[3600, 604800]`.
- **App variables / license variables** for feature flags and tiered licensing.
- **Automatic retries** for rate-limited and transient network failures, with a fresh nonce per retry.

## Installation

Install from [PyPI](https://pypi.org/project/authforge-sdk/) as **`authforge-sdk`**. In code, import the **`authforge`** module:

```bash
pip install authforge-sdk
```

**Alternative:** copy `authforge.py` into your project if you need a single-file vendored layout (you must still satisfy the `cryptography` dependency yourself).

## Quick Start

After **`pip install authforge-sdk`** (or vendoring `authforge.py`), use:

```python
from authforge import AuthForgeClient

client = AuthForgeClient(
    app_id="YOUR_APP_ID",           # from your AuthForge dashboard
    app_secret="YOUR_APP_SECRET",   # from your AuthForge dashboard
    public_key="YOUR_PUBLIC_KEY",   # from your AuthForge dashboard
)

license_key = input("Enter license key: ")

if client.login(license_key):
    print("Activated!")
    # Your app logic here. The app runs through the grace period by default:
    # no further network calls until the session TTL expires.
else:
    print("Invalid license key.")
    exit(1)
```

To detect revocations quickly (or concurrent use), enable online check-ins:

```python
client = AuthForgeClient(
    app_id="YOUR_APP_ID",
    app_secret="YOUR_APP_SECRET",
    public_key="YOUR_PUBLIC_KEY",
    heartbeat_interval=900,   # check in every 15 minutes
    online_heartbeat=True,    # periodic POST /auth/heartbeat
)
```

## Configuration

| Parameter | Type | Default | Description |
|---|---|---|---|
| `app_id` | str | required | Your application ID from the AuthForge dashboard |
| `app_secret` | str | required for online APIs; `None` / `""` for `login_from_file` only | Your application secret from the AuthForge dashboard. Do not ship it in air-gapped binaries. |
| `public_key` | `str \| Sequence[str]` | required | App Ed25519 public key(s) (base64) from dashboard. Pass one key, a list of keys, or a comma-separated string to trust multiple keys during rotation (see [Key rotation](#key-rotation)). |
| `heartbeat_mode` | `str \| None` | `None` | Deprecated shim (see [Migrating from heartbeat_mode](#migrating-from-heartbeat_mode)). Use `online_heartbeat` instead. |
| `heartbeat_interval` | int | `900` | Seconds between background checks (minimum `10`; default 15 min). Applies to both grace period checks and online check-ins. |
| `api_base_url` | str | `https://auth.authforge.cc` | API endpoint |
| `on_failure` | callable | `None` | Callback `(reason: str, exc: Exception | None)` on auth failure |
| `request_timeout` | int | `15` | HTTP request timeout in seconds |
| `ttl_seconds` | `int \| None` | `None` (server default: 86400) | The grace period duration: how long the app keeps running on the signed session without contacting AuthForge. Server clamps to `[3600, 604800]` (1h to 7d); preserved across check-in refreshes. |
| `hwid_override` | `str \| None` | `None` | Optional custom hardware/subject identifier. When set to a non-empty value, the SDK uses it instead of machine fingerprinting. |
| `online_heartbeat` | bool (keyword-only) | `False` | Enable online check-ins: periodic `POST /auth/heartbeat` for fast revocation and concurrent-use detection. |

### Identity-based binding example (Telegram/Discord)

```python
client = AuthForgeClient(
    app_id="YOUR_APP_ID",
    app_secret="YOUR_APP_SECRET",
    public_key="YOUR_PUBLIC_KEY",
    hwid_override=f"tg:{telegram_user_id}",  # or f"discord:{discord_user_id}"
)
```

### Key rotation

`public_key` is a trust list. To rotate the server-side signing key without a
flag-day, ship the **new** key alongside the **previous** one; the SDK accepts a
signature that matches any entry:

```python
client = AuthForgeClient(
    app_id="YOUR_APP_ID",
    app_secret="YOUR_APP_SECRET",
    public_key=["NEW_PUBLIC_KEY", "PREVIOUS_PUBLIC_KEY"],  # or "NEW,PREVIOUS"
)
```

`client.public_keys` exposes the full trust list; `client.public_key` is the
first (primary) entry.

## Grace period and online check-ins

**Grace period (default).** After a successful activation, the SDK re-verifies the cached signed session payload and checks the expiry timestamp locally at each `heartbeat_interval`: no network calls. When the session TTL expires, it triggers failure with `session_expired`. The grace period is **session continuation within the session TTL** (default 24h, server clamps 1h to 7d) after one successful online activation. It is not persistent offline licensing, and a mid-session revocation is not picked up until the next online validate or check-in.

**Online check-ins (opt-in, `online_heartbeat=True`).** The SDK calls `/auth/heartbeat` every `heartbeat_interval` seconds with a fresh nonce, verifies signature + nonce, and triggers failure on invalid session state. Use this when you need fast revocation propagation or concurrent-use detection.

Tune `ttl_seconds` to set the grace period duration (server default 24h, clamped to 1h to 7d).

## Offline license files (`.authforge`)

For machines that never connect to the internet, the operator mints a **signed offline license file** in the AuthForge dashboard (License page -> *Mint .authforge file*) or via `POST /v1/licenses/{licenseKey}/offline-files`. The file is a standalone Ed25519-signed document; the SDK verifies it with **only** your app public key and the machine HWID. It never contacts AuthForge and never starts online check-ins. Pass `app_secret=None` (or `""`) so the air-gapped binary does not contain the App Secret.

| | Grace period (default) | Offline license file |
| --- | --- | --- |
| Needs network | Once, at `login()` | Never on the end machine |
| What is verified | Signed *session* from `/auth/validate` | Signed *document* minted in the cloud |
| Lifetime | Session TTL: 1h to 7d | Operator-chosen expiry or lifetime (perpetual licenses only) |
| Revocation | Picked up at the next online validate / check-in | **Not** reachable: the file stays valid until its own expiry |
| Cost | 1 credit per `login()` | 1 credit per mint; verifying is free |

```python
from authforge import AuthForgeClient

client = AuthForgeClient(
    app_id="YOUR_APP_ID",
    app_secret=None,  # login_from_file does not use the App Secret; do not ship it in air-gapped builds
    public_key="YOUR_PUBLIC_KEY",
    on_failure=lambda reason, exc: print(reason, exc),
)

# 1. Write an activation request the operator drops into the mint dialog:
client.write_activation_request("machine.authforge-request")

# 2. Later, authorize from the minted file (path or armored text). No network.
if client.login_from_file("license.authforge"):
    info = client.get_offline_license()
    print("Offline license OK until", info["expires_at"] or "forever")
    print(client.get_license_variables())
```

Collect the HWID from the same SDK build that will load the file: fingerprints are not portable across SDKs or languages. After `login_from_file()`, `get_session_kind()` returns `"offline"` (`"online"` after `login()`, `None` when logged out).

`verify_license_file()` (module function and client method) performs the same checks without touching client state. Failure codes, in check order: `bad_armor`, `bad_signature`, `unsupported_version`, `malformed_payload`, `wrong_app`, `expired`, `hwid_mismatch`. `login_from_file()` reports them through `on_failure("offline_login_failed", exc)` and returns `False`; it never calls `os._exit`.

File format (version 1): PEM-style armor with informational headers, a base64 JSON payload (`v`, `appId`, `licenseKey`, `jti`, `kid`, `issuedAt`, `expiresAt`, `hwid` policy, optional label/variable snapshots) and a detached Ed25519 signature over the UTF-8 bytes of the base64 payload string - the same contract as `/auth/validate`. See `offline_license_vectors.json` for conformance vectors.

## Migrating from heartbeat_mode

Earlier releases required `heartbeat_mode="LOCAL"` or `"SERVER"`. The argument is now optional and deprecated; it still works but emits a `DeprecationWarning`.

- `heartbeat_mode="LOCAL"` maps to the default behavior (the grace period): just remove the argument.
- `heartbeat_mode="SERVER"` maps to `online_heartbeat=True`.
- If both arguments are set, either one enables online check-ins: `heartbeat_mode="SERVER"` is not overridden by `online_heartbeat=False`.

```python
# Before
client = AuthForgeClient(app_id, app_secret, public_key, heartbeat_mode="SERVER")

# After
client = AuthForgeClient(app_id, app_secret, public_key, online_heartbeat=True)
```

For code that still reads it, `client.heartbeat_mode` remains available and reflects the effective policy (`"SERVER"` when online check-ins are enabled, `"LOCAL"` otherwise).

## Billing

- **1 `login()` or `validate_license()` call = 1 credit** (one `/auth/validate` debit each).
- **10 online check-ins on the same license = 1 credit** (billed every 10th successful `/auth/heartbeat`). Grace period checks are local and free.

A desktop app running 6h/day with online check-ins at a 15-minute interval burns ~3-4 credits/day. The server enforces `/auth/heartbeat` at 6 requests/minute per license key, so keep intervals at 10 seconds or higher and pick the interval based on how fast you need revocations to propagate (they always land on the **next** check-in).

## Methods

| Method | Returns | Description |
|---|---|---|
| `login(license_key)` | `bool` | Activates: validates the key online and stores the signed session (`sessionToken`, `expiresIn`, `appVariables`, `licenseVariables`) |
| `validate_license(license_key)` | `ValidateLicenseResult` | Same `/auth/validate` + signatures as `login`; does not store session or start background checks; returns a dict with `valid` / `code` and **never** calls `on_failure` or `os._exit` |
| `self_ban(...)` | `dict` | Requests `/auth/selfban` to blacklist HWID/IP and optionally revoke (session-authenticated only) |
| `login_from_file(path_or_text)` | `bool` | Authorizes from an offline `.authforge` file with no network; never starts background checks; failures go to `on_failure("offline_login_failed", …)` |
| `verify_license_file(path_or_text, *, now=None)` | `VerifyLicenseFileResult` | Verifies a `.authforge` file with this client's app id / keys / HWID without changing state |
| `get_offline_license()` | `dict \| None` | Metadata of the offline file in use (`jti`, `expires_at`, `hwid_policy`, …) |
| `get_session_kind()` | `"online" \| "offline" \| None` | Which kind of session the client holds (`None` when logged out) |
| `get_hwid()` | `str` | The HWID this client sends (or `hwid_override`); customers share it to receive a bound file |
| `create_activation_request(**kwargs)` | `str` | Unsigned `.authforge-request` for this machine. No network, no secret. Hostname omitted unless `include_machine_name=True` |
| `write_activation_request(path, **kwargs)` | `None` | Writes that file as UTF-8 |
| `logout()` | `None` | Stops background checks and clears all session/auth state |
| `is_authenticated()` | `bool` | True when an active authenticated session exists |
| `get_session_data()` | `dict \| None` | Full decoded payload map |
| `get_app_variables()` | `dict \| None` | App-scoped variables map |
| `get_license_variables()` | `dict \| None` | License-scoped variables map |

## Failure Handling

If authentication fails (activation rejected, check-in fails, signature mismatch, grace period expired, etc.), the SDK calls your `on_failure` callback if one is provided. If no callback is set, **the SDK calls `os._exit(1)` to terminate the process.** This is intentional: it prevents your app from running without a valid license.

**`validate_license()`** does not trigger `on_failure` or `os._exit`: check `result["valid"]` and `result["code"]`.

Recognized server errors (`KNOWN_SERVER_ERRORS`):
`invalid_app`, `invalid_key`, `expired`, `revoked`, `hwid_mismatch`, `no_credits`, `app_burn_cap_reached`, `blocked`, `rate_limited`, `replay_detected`, `app_disabled`, `session_expired`, `revoke_requires_session`, `bad_request`, `malformed_request`, `system_error`

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
    on_failure=handle_auth_failure,
)
```

## Self-ban (tamper response)

Use `self_ban()` when anti-tamper checks trigger:

```python
# Post-session (authenticated): defaults to revoke + HWID/IP blacklist.
client.self_ban()

# Pre-session: pass license_key, SDK automatically disables revoke_license.
client.self_ban(license_key="AF-XXXX-XXXX-XXXX")

# Custom flags:
client.self_ban(
    blacklist_hwid=True,
    blacklist_ip=True,
    revoke_license=False,
)
```

`self_ban()` automatically chooses mode:
- Uses post-session mode when a session token is available (`session_token` arg or current SDK session).
- Falls back to pre-session mode using `license_key` + nonce + app secret.
- In pre-session mode, revoke is forced off client-side to avoid unsafe key revocations.
- Not available after `login_from_file()`: offline sessions have no server session, so `self_ban()` with no explicit `license_key` / `session_token` raises `ValueError("offline_session")` without contacting the server.

## How It Works

1. **Activate**: `login()` uses `hwid_override` if provided; otherwise it collects a hardware fingerprint (MAC, CPU, disk serial). It then generates a random nonce and sends everything to the AuthForge API. The server validates the license key, binds the HWID, deducts a credit, and returns a signed payload with a TTL. The SDK verifies the Ed25519 signature and nonce to prevent replay attacks.

2. **Background checks**: a daemon thread wakes at the configured interval. By default it enforces the grace period: it re-verifies the stored signature and checks expiry without network calls. With `online_heartbeat=True`, it instead sends `/auth/heartbeat` with a fresh nonce and verifies the response.

3. **Crypto**: both `/validate` and `/heartbeat` responses are signed by AuthForge with your app's Ed25519 private key. The SDK verifies every signed `payload` using your configured `public_key` and rejects tampered responses.

## Hardware ID

The SDK generates a deterministic hardware fingerprint by hashing:
- MAC address
- CPU identifier
- Disk serial number

Each component falls back gracefully if it can't be read (e.g. permissions issues). The HWID is sent with every auth request so the server can enforce per-device license limits.

For non-device identities (for example Telegram users), pass `hwid_override` such as `tg:<user_id>`.

## Test Vectors

The shared `test_vectors.json` file validates cross-language Ed25519 verification behavior. `offline_license_vectors.json` (generated from a fixed test seed in the Node SDK repo) is the cross-SDK conformance suite for `.authforge` offline license files: good files plus the `bad_signature`, wrong key, `wrong_app`, `expired`, `hwid_mismatch`, `unsupported_version` and `bad_armor` rejects.

## Requirements

- Python 3.9+
- Dependency: `cryptography`

## License

MIT
