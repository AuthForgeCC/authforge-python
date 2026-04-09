import base64
import hashlib
import hmac
import json
from pathlib import Path


APP_SECRET = "af_test_secret_2026_reference"
NONCE = "0123456789abcdeffedcba9876543210"
SESSION_SIGNING_SECRET = "authforge-dev-session-signing-secret-rotate-before-production"


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _build_realistic_session_token() -> str:
    body = {
        "appId": "test-app",
        "licenseKey": "test-key",
        "hwid": "testhwid",
        "appSecret": APP_SECRET,
        "expiresIn": 1740433200,
    }
    body_json = json.dumps(body, separators=(",", ":")).encode("utf-8")
    body_b64 = _b64url_no_pad(body_json)

    digest = hmac.new(
        SESSION_SIGNING_SECRET.encode("utf-8"),
        body_b64.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    sig_b64 = _b64url_no_pad(digest)
    return f"{body_b64}.{sig_b64}"


def _build_payload_b64() -> str:
    payload_obj = {
        "sessionToken": _build_realistic_session_token(),
        "timestamp": 1740429600,
        "expiresIn": 1740433200,
        "nonce": NONCE,
    }
    payload_json = json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(payload_json).decode("ascii")


PAYLOAD = _build_payload_b64()


def main() -> None:
    derived_key_bytes = hashlib.sha256(f"{APP_SECRET}{NONCE}".encode("utf-8")).digest()
    signature_hex = hmac.new(
        derived_key_bytes,
        PAYLOAD.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    vectors = {
        "algorithm": {
            "keyDerivation": "SHA256(appSecret + nonce)",
            "signature": "HMAC-SHA256(raw_base64_payload_string, derivedKey)",
        },
        "inputs": {
            "appSecret": APP_SECRET,
            "nonce": NONCE,
            "payload": PAYLOAD,
        },
        "outputs": {
            "derivedKeyHex": derived_key_bytes.hex(),
            "signatureHex": signature_hex,
        },
    }

    output_path = Path(__file__).with_name("test_vectors.json")
    output_path.write_text(json.dumps(vectors, indent=2), encoding="utf-8")
    print(str(output_path))


if __name__ == "__main__":
    main()
