"""Unit tests for the AuthForge Python SDK (stdlib unittest + mock only)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from authforge import AuthForgeClient


def _load_test_vectors() -> dict:
    path = Path(__file__).resolve().parent / "test_vectors.json"
    with path.open(encoding="utf-8") as f:
        return json.load(f)


class CryptoTests(unittest.TestCase):
    """Verify key derivation and HMAC signing against test_vectors.json."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors = _load_test_vectors()

    def test_derive_signing_key_matches_vectors(self) -> None:
        app_secret = self.vectors["inputs"]["appSecret"]
        nonce = self.vectors["inputs"]["nonce"]
        expected_hex = self.vectors["outputs"]["derivedKeyHex"]

        client = AuthForgeClient(
            "test-app-id",
            app_secret,
            "LOCAL",
            heartbeat_interval=86400,
        )
        derived = client._derive_key(nonce)
        self.assertEqual(derived.hex(), expected_hex)

        # Documented algorithm: SHA256(secret + nonce) digest
        seed = f"{app_secret}{nonce}".encode("utf-8")
        self.assertEqual(hashlib.sha256(seed).digest(), derived)

    def test_sign_payload_matches_vectors(self) -> None:
        """HMAC-SHA256(base64 payload string, derived key) == signatureHex."""
        vectors = self.vectors
        key = bytes.fromhex(vectors["outputs"]["derivedKeyHex"])
        payload_b64 = vectors["inputs"]["payload"]
        expected_sig = vectors["outputs"]["signatureHex"]

        actual = hmac.new(
            key,
            payload_b64.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(actual, expected_sig)

        client = AuthForgeClient(
            "test-app-id",
            vectors["inputs"]["appSecret"],
            "LOCAL",
            heartbeat_interval=86400,
        )
        client._verify_signature(payload_b64, key, expected_sig)

    def test_verify_signature_rejects_tampered_payload(self) -> None:
        vectors = self.vectors
        key = bytes.fromhex(vectors["outputs"]["derivedKeyHex"])
        payload_b64 = vectors["inputs"]["payload"]
        bad_payload = payload_b64[:-1] + ("a" if payload_b64[-1] != "a" else "b")

        client = AuthForgeClient(
            "test-app-id",
            vectors["inputs"]["appSecret"],
            "LOCAL",
            heartbeat_interval=86400,
        )
        with self.assertRaises(ValueError) as ctx:
            client._verify_signature(bad_payload, key, vectors["outputs"]["signatureHex"])
        self.assertEqual(ctx.exception.args[0], "signature_mismatch")


class HwidTests(unittest.TestCase):
    def test_hwid_is_64_char_hex_sha256(self) -> None:
        with (
            patch.object(AuthForgeClient, "_safe_mac_address", return_value="001122334455"),
            patch.object(AuthForgeClient, "_safe_cpu_info", return_value="test-cpu"),
            patch.object(AuthForgeClient, "_safe_disk_serial", return_value="test-disk"),
        ):
            client = AuthForgeClient(
                "app-id",
                "app-secret",
                "LOCAL",
                heartbeat_interval=86400,
            )

        hwid = client._hwid
        self.assertEqual(len(hwid), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in hwid))

        material = "mac:001122334455|cpu:test-cpu|disk:test-disk"
        expected = hashlib.sha256(material.encode("utf-8")).hexdigest()
        self.assertEqual(hwid, expected)


class NonceTests(unittest.TestCase):
    def test_nonces_are_unique_and_sufficient_length(self) -> None:
        client = AuthForgeClient(
            "app-id",
            "app-secret",
            "LOCAL",
            heartbeat_interval=86400,
        )
        seen: set[str] = set()
        for _ in range(200):
            n = client._generate_nonce()
            self.assertGreaterEqual(len(n), 8)
            self.assertTrue(all(c in "0123456789abcdef" for c in n))
            seen.add(n)
        self.assertEqual(len(seen), 200)


class ClientStateTests(unittest.TestCase):
    def test_not_authenticated_before_login(self) -> None:
        client = AuthForgeClient(
            "app-id",
            "app-secret",
            "LOCAL",
            heartbeat_interval=86400,
        )
        self.assertFalse(client.is_authenticated())
        self.assertIsNone(client.get_session_data())
        self.assertIsNone(client.get_app_variables())
        self.assertIsNone(client.get_license_variables())

    def test_logout_clears_authentication_state(self) -> None:
        vectors = _load_test_vectors()
        app_secret = vectors["inputs"]["appSecret"]
        nonce = vectors["inputs"]["nonce"]
        payload_b64 = vectors["inputs"]["payload"]
        signature_hex = vectors["outputs"]["signatureHex"]

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {
                "status": "ok",
                "payload": payload_b64,
                "signature": signature_hex,
            },
            separators=(",", ":"),
        ).encode("utf-8")

        urlopen_cm = MagicMock()
        urlopen_cm.__enter__.return_value = mock_resp
        urlopen_cm.__exit__.return_value = None

        with (
            patch("authforge.urllib.request.urlopen", return_value=urlopen_cm),
            patch.object(AuthForgeClient, "_generate_nonce", return_value=nonce),
        ):
            client = AuthForgeClient(
                "app-id",
                app_secret,
                "LOCAL",
                heartbeat_interval=86400,
            )
            self.assertTrue(client.login("license-key"))

        self.assertTrue(client.is_authenticated())
        self.assertIsNotNone(client.get_session_data())

        client.logout()
        self.assertFalse(client.is_authenticated())
        self.assertIsNone(client.get_session_data())
        self.assertIsNone(client.get_app_variables())
        self.assertIsNone(client.get_license_variables())


class HeartbeatModeTests(unittest.TestCase):
    def test_invalid_heartbeat_mode_rejected(self) -> None:
        for bad in ("", "OFF", "both", "server-only", None):
            with self.subTest(mode=bad):
                with self.assertRaises(ValueError) as ctx:
                    AuthForgeClient("app-id", "secret", bad)  # type: ignore[arg-type]
                self.assertIn("heartbeat_mode", ctx.exception.args[0].lower())

    def test_valid_heartbeat_modes_accepted(self) -> None:
        for mode in ("LOCAL", "SERVER", "local", "server"):
            with self.subTest(mode=mode):
                c = AuthForgeClient("app-id", "secret", mode, heartbeat_interval=1)
                self.assertIn(c.heartbeat_mode, ("LOCAL", "SERVER"))


class MockLoginTests(unittest.TestCase):
    def test_login_with_mocked_http_succeeds_and_exposes_session(self) -> None:
        vectors = _load_test_vectors()
        app_secret = vectors["inputs"]["appSecret"]
        nonce = vectors["inputs"]["nonce"]
        payload_b64 = vectors["inputs"]["payload"]
        signature_hex = vectors["outputs"]["signatureHex"]

        inner = json.loads(base64.urlsafe_b64decode(_padded_b64(payload_b64)))
        self.assertEqual(inner.get("nonce"), nonce)

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {
                "status": "ok",
                "payload": payload_b64,
                "signature": signature_hex,
            },
            separators=(",", ":"),
        ).encode("utf-8")

        cm = MagicMock()
        cm.__enter__.return_value = mock_resp
        cm.__exit__.return_value = None

        with (
            patch("authforge.urllib.request.urlopen", return_value=cm),
            patch.object(AuthForgeClient, "_generate_nonce", return_value=nonce),
        ):
            client = AuthForgeClient(
                "vector-app",
                app_secret,
                "LOCAL",
                heartbeat_interval=86400,
            )
            ok = client.login("test-license")

        self.assertTrue(ok)
        self.assertTrue(client.is_authenticated())
        session = client.get_session_data()
        self.assertIsNotNone(session)
        assert session is not None
        self.assertEqual(session.get("nonce"), nonce)
        self.assertIn("sessionToken", session)


def _padded_b64(value: str) -> str:
    pad = (4 - len(value) % 4) % 4
    return value + ("=" * pad)


if __name__ == "__main__":
    unittest.main()
