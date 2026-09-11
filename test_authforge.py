"""Unit tests for the AuthForge Python SDK."""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
import warnings
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from authforge import AuthForgeClient, parse_license_file, verify_license_file


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


class MultiKeyRotationTests(unittest.TestCase):
    """The SDK must verify against any public key in the configured trust
    list, so a deployment can rotate the server-side key while clients are
    still pinned to the old one."""

    DECOY_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    def test_list_form_accepts_real_key(self) -> None:
        vectors = _load_test_vectors()
        case = next(c for c in vectors["cases"] if c["id"] == "validate_success")
        client = AuthForgeClient(
            "app",
            "secret",
            [self.DECOY_KEY, vectors["publicKey"]],
            heartbeat_interval=86400,
        )
        # Bogus key is first; verification must walk to the second entry.
        client._verify_signature(case["payload"], case["signature"])
        self.assertEqual(client.public_keys[0], self.DECOY_KEY)
        self.assertEqual(client.public_keys[1], vectors["publicKey"])

    def test_comma_separated_form_accepts_real_key(self) -> None:
        vectors = _load_test_vectors()
        case = next(c for c in vectors["cases"] if c["id"] == "validate_success")
        combined = f"{self.DECOY_KEY},{vectors['publicKey']}"
        client = AuthForgeClient(
            "app", "secret", combined, heartbeat_interval=86400
        )
        client._verify_signature(case["payload"], case["signature"])

    def test_all_unknown_keys_still_fails(self) -> None:
        vectors = _load_test_vectors()
        case = next(c for c in vectors["cases"] if c["id"] == "validate_success")
        client = AuthForgeClient(
            "app",
            "secret",
            [self.DECOY_KEY],
            heartbeat_interval=86400,
        )
        with self.assertRaises(ValueError) as ctx:
            client._verify_signature(case["payload"], case["signature"])
        self.assertEqual(ctx.exception.args[0], "signature_mismatch")


class ConstructorPolicyTests(unittest.TestCase):
    """Grace period is the default; online check-ins are opt-in; the legacy
    heartbeat_mode argument still works behind a DeprecationWarning."""

    PUBLIC_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    def test_default_is_grace_period(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            client = AuthForgeClient("app", "secret", self.PUBLIC_KEY)
        self.assertFalse(client.online_heartbeat)
        self.assertEqual(client.heartbeat_mode, "LOCAL")
        deprecations = [
            w for w in caught if issubclass(w.category, DeprecationWarning)
        ]
        self.assertEqual(deprecations, [])

    def test_legacy_server_mode_maps_to_online_heartbeat(self) -> None:
        with pytest.warns(DeprecationWarning):
            client = AuthForgeClient(
                "app", "secret", self.PUBLIC_KEY, heartbeat_mode="SERVER"
            )
        self.assertTrue(client.online_heartbeat)
        self.assertEqual(client.heartbeat_mode, "SERVER")

    def test_legacy_local_mode_maps_to_grace_period(self) -> None:
        with pytest.warns(DeprecationWarning):
            client = AuthForgeClient(
                "app", "secret", self.PUBLIC_KEY, heartbeat_mode="LOCAL"
            )
        self.assertFalse(client.online_heartbeat)
        self.assertEqual(client.heartbeat_mode, "LOCAL")

    def test_online_heartbeat_flag_without_legacy_mode(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            client = AuthForgeClient(
                "app", "secret", self.PUBLIC_KEY, online_heartbeat=True
            )
        self.assertTrue(client.online_heartbeat)
        self.assertEqual(client.heartbeat_mode, "SERVER")
        deprecations = [
            w for w in caught if issubclass(w.category, DeprecationWarning)
        ]
        self.assertEqual(deprecations, [])

    def test_invalid_legacy_mode_still_raises(self) -> None:
        with pytest.raises(ValueError, match="heartbeat_mode must be LOCAL or SERVER"):
            AuthForgeClient(
                "app", "secret", self.PUBLIC_KEY, heartbeat_mode="SOMETIMES"
            )


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

        # Grace period check: re-verifies the stored signed session locally
        # and must not touch the network before the session TTL expires.
        with patch(
            "authforge.urllib.request.urlopen",
            side_effect=AssertionError("grace period check must not use the network"),
        ):
            client._grace_period_check()


# ---------------------------------------------------------------------------
# Offline license files (`.authforge`)
# ---------------------------------------------------------------------------


def _load_offline_vectors() -> dict:
    path = Path(__file__).resolve().parent / "offline_license_vectors.json"
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class OfflineLicenseFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors = _load_offline_vectors()
        cls.by_name = {c["name"]: c for c in cls.vectors["cases"]}
        cls.good = cls.by_name["good_bound"]
        # Client-level tests run against the wall clock: use the lifetime vector
        # (expiresAt null) so they never turn into "expired" in 2027.
        cls.lifetime = cls.by_name["good_lifetime"]

    def _make_client(self, **overrides) -> tuple[AuthForgeClient, list]:
        failures: list = []
        kwargs = dict(
            app_id=self.good["appId"],
            app_secret="unused-offline",
            public_key=self.good["publicKey"],
            hwid_override=self.good["hwid"],
            on_failure=lambda reason, exc: failures.append((reason, str(exc) if exc else None)),
        )
        kwargs.update(overrides)
        return AuthForgeClient(**kwargs), failures

    def test_every_vector_case_matches(self) -> None:
        self.assertGreaterEqual(len(self.vectors["cases"]), 15)
        for case in self.vectors["cases"]:
            with self.subTest(case=case["name"]):
                result = verify_license_file(
                    case["file"],
                    case["appId"],
                    case["publicKey"],
                    case["hwid"],
                    now=_iso(case["now"]),
                )
                got = "ok" if result["ok"] else result["error"]
                self.assertEqual(got, case["expect"])
                if result["ok"] and "payload" in case:
                    self.assertEqual(result["license"]["payload"], case["payload"])
                    self.assertEqual(result["payload_base64"], case["payloadBase64"])
                    self.assertEqual(result["signature_base64"], case["signatureBase64"])

    def test_parse_recovers_canonical_signed_string(self) -> None:
        parsed = parse_license_file(self.good["file"])
        assert parsed is not None
        self.assertEqual(parsed["payload_base64"], self.good["payloadBase64"])
        self.assertEqual(parsed["signature_base64"], self.good["signatureBase64"])
        self.assertEqual(parsed["headers"]["Version"], "1")
        self.assertEqual(parsed["headers"]["App-Id"], self.good["appId"])
        self.assertIsNone(parse_license_file("nope"))

    def test_good_file_exposes_entitlements(self) -> None:
        result = verify_license_file(
            self.good["file"], self.good["appId"], self.good["publicKey"], self.good["hwid"],
            now=_iso(self.good["now"]),
        )
        assert result["ok"]
        lic = result["license"]
        self.assertEqual(lic["license_key"], "TEST-KEY0-0000-0000")
        self.assertEqual(lic["key_id"], "kid-test-0001")
        self.assertEqual(lic["hwid_policy"], {"mode": "bound", "hwids": ["testhwid", "second-machine"]})
        self.assertEqual(lic["license_variables"], {"tier": "pro", "seats": 3, "beta": True})
        self.assertEqual(lic["app_variables"], {"theme": "dark"})
        self.assertEqual(lic["label"], "Vector license")

    def test_login_from_file_is_offline_and_starts_no_heartbeat(self) -> None:
        client, failures = self._make_client()
        self.assertEqual(client.get_hwid(), self.good["hwid"])
        with patch(
            "authforge.urllib.request.urlopen",
            side_effect=AssertionError("offline files must not use the network"),
        ):
            self.assertTrue(client.login_from_file(self.lifetime["file"]))
        self.assertTrue(client.is_authenticated())
        self.assertEqual(client.get_session_kind(), "offline")
        # No token sentinel: an offline session has no server session at all.
        self.assertIsNone(client._session_token)
        self.assertFalse(client._heartbeat_started)
        self.assertIsNone(client._heartbeat_thread)
        self.assertEqual(client.get_license_variables(), {"tier": "pro", "seats": 3, "beta": True})
        self.assertEqual(client.get_app_variables(), {"theme": "dark"})
        self.assertEqual(client.get_session_data()["licenseKey"], "TEST-KEY0-0000-0000")
        offline = client.get_offline_license()
        assert offline is not None
        self.assertEqual(offline["jti"], "00000000-0000-4000-8000-000000000003")
        self.assertIsNone(offline["expires_at"])
        self.assertEqual(failures, [])

        client.logout()
        self.assertFalse(client.is_authenticated())
        self.assertIsNone(client.get_session_kind())
        self.assertIsNone(client.get_offline_license())

    def test_offline_self_ban_is_local_error_and_never_posts(self) -> None:
        # Closed port: any accidental network call fails loudly instead of hanging.
        client, _ = self._make_client(api_base_url="http://127.0.0.1:9")
        self.assertTrue(client.login_from_file(self.lifetime["file"]))
        posts: list = []

        def fake_post(path, body, **_kwargs):
            posts.append((path, body))
            return {"status": "ok"}

        with patch.object(client, "_post_json", side_effect=fake_post):
            with self.assertRaises(ValueError) as ctx:
                client.self_ban()
            self.assertEqual(str(ctx.exception), "offline_session")
            with self.assertRaises(ValueError) as ctx:
                client.self_ban(revoke_license=False, blacklist_hwid=False)
            self.assertEqual(str(ctx.exception), "offline_session")
            self.assertEqual(posts, [])
            # Still authenticated offline afterwards; nothing was torn down.
            self.assertTrue(client.is_authenticated())

            # An explicit license_key is a request about a different credential
            # and legitimately takes the pre-session path with a fresh nonce.
            client.self_ban(license_key="OTHER-KEY0-0000-0000")
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0][0], "/auth/selfban")
        self.assertEqual(posts[0][1]["licenseKey"], "OTHER-KEY0-0000-0000")
        self.assertFalse(posts[0][1]["revokeLicense"])
        self.assertTrue(posts[0][1]["nonce"])
        self.assertNotIn("sessionToken", posts[0][1])

    def test_offline_heartbeat_entry_points_are_no_ops(self) -> None:
        client, failures = self._make_client(online_heartbeat=True)
        self.assertTrue(client.login_from_file(self.lifetime["file"]))
        # Make the loop's wait return immediately so the offline guard is what ends it.
        client.heartbeat_interval = 0
        with patch(
            "authforge.urllib.request.urlopen",
            side_effect=AssertionError("offline files must not use the network"),
        ):
            # Even if something calls the internal entry points, an offline
            # session never starts a thread, never checks in and never runs
            # the grace check.
            client._start_heartbeat_once()
            self.assertFalse(client._heartbeat_started)
            self.assertIsNone(client._heartbeat_thread)
            client._heartbeat_loop()
        self.assertTrue(client.is_authenticated())
        self.assertEqual(client.get_session_kind(), "offline")
        self.assertEqual(failures, [])

    def test_unsupported_version_bool_vector_is_rejected(self) -> None:
        case = self.by_name["unsupported_version_bool"]
        result = verify_license_file(case["file"], case["appId"], case["publicKey"], case["hwid"], now=_iso(case["now"]))
        self.assertEqual(result, {"ok": False, "error": "unsupported_version"})

    def test_login_from_file_rejects_via_on_failure(self) -> None:
        cases = [
            ({}, self.by_name["bad_signature_tampered_body"]["file"], "bad_signature"),
            ({"public_key": self.vectors["keys"]["wrongPublicKey"]}, self.lifetime["file"], "bad_signature"),
            ({}, self.by_name["expired"]["file"], "expired"),
            ({"hwid_override": "otherhwid"}, self.lifetime["file"], "hwid_mismatch"),
            ({"app_id": "other-app"}, self.lifetime["file"], "wrong_app"),
            ({}, self.by_name["unsupported_version"]["file"], "unsupported_version"),
        ]
        for overrides, file_text, expected in cases:
            with self.subTest(expected=expected):
                client, failures = self._make_client(**overrides)
                self.assertFalse(client.login_from_file(file_text))
                self.assertEqual(failures, [("offline_login_failed", expected)])
                self.assertFalse(client.is_authenticated())

    def test_login_from_file_unreadable_input_never_exits(self) -> None:
        client, failures = self._make_client()
        with patch("authforge.os._exit", side_effect=AssertionError("must not exit")):
            self.assertFalse(client.login_from_file("garbage-not-a-path"))
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0][0], "offline_login_failed")

    def test_login_from_file_reads_from_disk_and_verify_is_side_effect_free(self) -> None:
        client, _ = self._make_client()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "license.authforge"
            path.write_text(self.lifetime["file"], encoding="utf-8")
            checked = client.verify_license_file(str(path))
            self.assertTrue(checked["ok"])
            self.assertFalse(client.is_authenticated())
            self.assertTrue(client.login_from_file(str(path)))
            self.assertTrue(client.is_authenticated())


if __name__ == "__main__":
    unittest.main()
