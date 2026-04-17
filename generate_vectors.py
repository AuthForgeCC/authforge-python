import base64
import hashlib
import hmac
import json
from pathlib import Path


APP_SECRET = "af_test_secret_2026_reference"
SIG_KEY = "af_test_sig_key_2026_reference_0123456789abcdef"
NONCE = "0123456789abcdeffedcba9876543210"
SESSION_SIGNING_SECRET = "authforge-dev-session-signing-secret-rotate-before-production"
EXPIRES_IN = 1740433200
TIMESTAMP = 1740429600
APP_ID = "test-app"
LICENSE_KEY = "test-key"
HWID = "testhwid"


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _build_session_token() -> str:
    body = {
        "appId": APP_ID,
        "licenseKey": LICENSE_KEY,
        "hwid": HWID,
        "sigKey": SIG_KEY,
        "expiresIn": EXPIRES_IN,
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
        "sessionToken": _build_session_token(),
        "timestamp": TIMESTAMP,
        "expiresIn": EXPIRES_IN,
        "nonce": NONCE,
    }
    payload_json = json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(payload_json).decode("ascii")


def _hmac_hex(key: bytes, message: str) -> str:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def main() -> None:
    payload = _build_payload_b64()

    validate_key = hashlib.sha256(f"{APP_SECRET}{NONCE}".encode("utf-8")).digest()
    validate_sig = _hmac_hex(validate_key, payload)

    heartbeat_key = hashlib.sha256(f"{SIG_KEY}{NONCE}".encode("utf-8")).digest()
    heartbeat_sig = _hmac_hex(heartbeat_key, payload)

    vectors = {
        "validate": {
            "algorithm": {
                "keyDerivation": "SHA256(appSecret + nonce)",
                "signature": "HMAC-SHA256(raw_base64_payload_string, derivedKey)",
            },
            "inputs": {
                "appSecret": APP_SECRET,
                "nonce": NONCE,
                "payload": payload,
            },
            "outputs": {
                "derivedKeyHex": validate_key.hex(),
                "signatureHex": validate_sig,
            },
        },
        "heartbeat": {
            "algorithm": {
                "keyDerivation": "SHA256(sigKey + nonce)",
                "signature": "HMAC-SHA256(raw_base64_payload_string, derivedKey)",
            },
            "inputs": {
                "sigKey": SIG_KEY,
                "nonce": NONCE,
                "payload": payload,
            },
            "outputs": {
                "derivedKeyHex": heartbeat_key.hex(),
                "signatureHex": heartbeat_sig,
            },
        },
    }

    output_path = Path(__file__).with_name("test_vectors.json")
    output_path.write_text(json.dumps(vectors, indent=2), encoding="utf-8")
    print(str(output_path))


if __name__ == "__main__":
    main()
