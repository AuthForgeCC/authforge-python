"""Unit tests for the AuthForge Python SDK."""

from __future__ import annotations

import base64
import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from authforge import AuthForgeClient


def _load_test_vectors() -> dict:
    path = Path(__file__).resolve().parent / "test_vectors.json"
    with path.open(encoding="utf-8") as f:
        return json.load(f)


class Ed25519VectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors = _load_test_vectors()
        cls.public_key = cls.vectors["publicKey"]

    def _make_client(self) -> AuthForgeClient:
        return AuthForgeClient(
            "test-app-id",
            "test-app-secret",
            self.public_key,
            "LOCAL",
            heartbeat_interval=86400,
        )

    def test_valid_vectors_verify(self) -> None:
        client = self._make_client()
        for case in self.vectors["cases"]:
            if not case["shouldVerify"]:
                continue
            with self.subTest(case=case["id"]):
                client._verify_signature(case["payload"], case["signature"])

    def test_invalid_vectors_fail(self) -> None:
        client = self._make_client()
        for case in self.vectors["cases"]:
            if case["shouldVerify"]:
                continue
            with self.subTest(case=case["id"]):
                with self.assertRaises(ValueError) as ctx:
                    client._verify_signature(case["payload"], case["signature"])
                self.assertEqual(ctx.exception.args[0], "signature_mismatch")


class ValidateLicenseTests(unittest.TestCase):
    def test_validate_license_success_no_heartbeat(self) -> None:
        vectors = _load_test_vectors()
        success_case = next(
            case for case in vectors["cases"] if case["id"] == "validate_success"
        )
        nonce = "nonce-validate-001"
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps(
            {
                "status": "ok",
                "payload": success_case["payload"],
                "signature": success_case["signature"],
                "keyId": "signing-key-1",
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
                "app-secret",
                vectors["publicKey"],
                "LOCAL",
                heartbeat_interval=86400,
            )
            result = client.validate_license("license-key")

        self.assertTrue(result["valid"])
        self.assertFalse(client._heartbeat_started)
        self.assertFalse(client.is_authenticated())
        self.assertEqual(result["session_token"], "session.validate.token")
        self.assertEqual(result["app_variables"], {"tier": "pro"})

    def test_validate_license_failure_no_heartbeat(self) -> None:
        vectors = _load_test_vectors()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps(
            {"status": "invalid_key", "error": "invalid_key"},
            separators=(",", ":"),
        ).encode("utf-8")

        urlopen_cm = MagicMock()
        urlopen_cm.__enter__.return_value = mock_resp
        urlopen_cm.__exit__.return_value = None

        with patch("authforge.urllib.request.urlopen", return_value=urlopen_cm):
            client = AuthForgeClient(
                "app-id",
                "app-secret",
                vectors["publicKey"],
                "LOCAL",
                heartbeat_interval=86400,
            )
            result = client.validate_license("bad")

        self.assertFalse(result["valid"])
        self.assertEqual(result["code"], "invalid_key")
        self.assertFalse(client._heartbeat_started)


class LoginFlowTests(unittest.TestCase):
    def test_login_parses_and_stores_signed_payload(self) -> None:
        vectors = _load_test_vectors()
        success_case = next(case for case in vectors["cases"] if case["id"] == "validate_success")
        payload = json.loads(base64.b64decode(success_case["payload"]).decode("utf-8"))

        nonce = "nonce-validate-001"
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps(
            {
                "status": "ok",
                "payload": success_case["payload"],
                "signature": success_case["signature"],
                "keyId": "signing-key-1",
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
                "app-secret",
                vectors["publicKey"],
                "LOCAL",
                heartbeat_interval=86400,
            )
            self.assertTrue(client.login("license-key"))

        self.assertTrue(client.is_authenticated())
        self.assertEqual(client._key_id, "signing-key-1")
        self.assertEqual(client._last_nonce, nonce)
        self.assertIsNotNone(client.get_session_data())
        self.assertEqual(client.get_app_variables(), {"tier": "pro"})
        self.assertEqual(client.get_license_variables(), {"region": "us-east-1"})
        self.assertEqual(payload["nonce"], nonce)


if __name__ == "__main__":
    unittest.main()
