"""Unit tests for the AuthForge Python SDK."""

from __future__ import annotations

import base64
import io
import json
import re
import socket
import tempfile
import threading
import time
import unittest
import urllib.error
import warnings
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import authforge
from authforge import AuthForgeClient, format_activation_request, parse_license_file, verify_license_file


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


def _urlopen_ok(body: dict) -> MagicMock:
    resp = MagicMock()
    resp.status = 200
    resp.read.return_value = json.dumps(body).encode("utf-8")
    cm = MagicMock()
    cm.__enter__.return_value = resp
    cm.__exit__.return_value = None
    return cm


def _http_error(status: int, raw: bytes) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://auth.test/auth/heartbeat", status, "err", {}, io.BytesIO(raw))


def _failed_response(status: int, code: str):
    """urlopen side effect: every call fails with a fresh HTTPError."""
    return _http_error_response(status, json.dumps({"status": "failed", "error": code}).encode("utf-8"))


def _http_error_response(status: int, raw: bytes):
    def side_effect(*_args, **_kwargs):
        raise _http_error(status, raw)

    return side_effect


def _ok_response(raw: bytes):
    """urlopen side effect: every call returns HTTP 200 with ``raw``."""

    def side_effect(*_args, **_kwargs):
        resp = MagicMock()
        resp.status = 200
        resp.read.return_value = raw
        cm = MagicMock()
        cm.__enter__.return_value = resp
        cm.__exit__.return_value = None
        return cm

    return side_effect


def _run_in_thread(target) -> None:
    """Run ``target`` on a worker thread; fail instead of hanging on a deadlock."""
    errors: list = []

    def run() -> None:
        try:
            target()
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(5)
    if worker.is_alive():
        raise AssertionError("heartbeat tick deadlocked")
    if errors:
        raise errors[0]


class HeartbeatFailureTests(unittest.TestCase):
    """Every /auth/heartbeat failure reaches on_failure with its code and
    classification; definitive failures drop the stored session."""

    DEFINITIVE = [
        ("revoked", 410),
        ("expired", 410),
        ("hwid_mismatch", 403),
        ("blocked", 403),
        ("app_disabled", 403),
        ("session_expired", 401),
        ("invalid_app", 401),
        ("malformed_request", 400),
    ]
    TRANSIENT = [
        ("rate_limited", 429),
        ("system_error", 500),
        ("server_error", 500),
        ("no_credits", 429),
        ("demo_quota_exceeded", 429),
        ("app_burn_cap_reached", 429),
        ("bad_request", 400),
        ("invalid_key", 401),
        ("some_future_code", 400),
    ]
    NOT_RETRIED_429 = ("no_credits", "demo_quota_exceeded", "app_burn_cap_reached")

    def setUp(self) -> None:
        self.vectors = _load_test_vectors()
        sleep_patch = patch("authforge.time.sleep")
        self.sleep = sleep_patch.start()
        self.addCleanup(sleep_patch.stop)
        self._fresh_client()

    def _fresh_client(self) -> None:
        self.sleep.reset_mock()
        self.failures: list = []
        self.client = AuthForgeClient(
            "app-id",
            "app-secret",
            self.vectors["publicKey"],
            heartbeat_interval=86400,
            online_heartbeat=True,
            on_failure=lambda reason, exc: self.failures.append((reason, exc)),
        )
        validate = next(c for c in self.vectors["cases"] if c["id"] == "validate_success")
        c = self.client
        c._license_key = "license-key"
        c._session_token = "session.validate.token"
        c._session_kind = "online"
        c._session_expires_in = int(time.time()) + 3600
        c._raw_payload_b64 = validate["payload"]
        c._signature = validate["signature"]
        c._session_data = {"tier": "pro"}
        c._authenticated = True

    def _tick(self, urlopen_side_effect) -> bool:
        with patch("authforge.urllib.request.urlopen", side_effect=urlopen_side_effect) as urlopen:
            keep_running = self.client._heartbeat_tick()
        self.urlopen_calls = urlopen.call_count
        return keep_running

    def _only_failure(self) -> authforge.AuthForgeError:
        self.assertEqual(len(self.failures), 1, self.failures)
        reason, exc = self.failures[0]
        self.assertEqual(reason, "heartbeat_failed")
        self.assertIsInstance(exc, authforge.AuthForgeError)
        self.assertIsInstance(exc, ValueError)
        return exc

    def _assert_invalidated(self) -> None:
        self.assertFalse(self.client.is_authenticated())
        self.assertIsNone(self.client.get_session_kind())
        self.assertIsNone(self.client.get_session_data())
        self.assertIsNone(self.client._raw_payload_b64)
        self.assertFalse(self.client._heartbeat_started)
        self.assertTrue(self.client._heartbeat_stop.is_set())
        with self.assertRaises(RuntimeError):
            self.client._grace_period_check()

    def _assert_session_kept(self) -> None:
        self.assertTrue(self.client.is_authenticated())
        self.assertEqual(self.client._session_token, "session.validate.token")
        self.assertFalse(self.client._heartbeat_stop.is_set())

    def _assert_definitive(self, code: str) -> None:
        exc = self._only_failure()
        self.assertEqual(exc.code, code)
        self.assertEqual(str(exc), code)
        self.assertTrue(exc.fatal)
        self.assertFalse(exc.transient)
        self.assertFalse(authforge.is_transient_error(exc))
        self.assertEqual(self.urlopen_calls, 1, "definitive codes are not retried")
        self.sleep.assert_not_called()
        self._assert_invalidated()

    def _assert_transient(self, code: str) -> authforge.AuthForgeError:
        exc = self._only_failure()
        self.assertEqual(exc.code, code)
        self.assertTrue(exc.transient)
        self.assertFalse(exc.fatal)
        self._assert_session_kept()
        return exc

    def test_definitive_codes_from_non_2xx_invalidate_session(self) -> None:
        for code, status in self.DEFINITIVE:
            with self.subTest(code=code, status=status):
                self._fresh_client()
                self.assertFalse(self._tick(_failed_response(status, code)))
                self._assert_definitive(code)

    def test_definitive_codes_in_200_body_invalidate_session(self) -> None:
        for code, _status in self.DEFINITIVE:
            with self.subTest(code=code):
                self._fresh_client()
                body = json.dumps({"status": "failed", "error": code}).encode("utf-8")
                self.assertFalse(self._tick(_ok_response(body)))
                self._assert_definitive(code)

    def test_verdict_status_and_code_are_normalized(self) -> None:
        body = json.dumps({"status": " FAILED ", "error": " Revoked "}).encode("utf-8")
        self.assertFalse(self._tick(_ok_response(body)))
        self._assert_definitive("revoked")

    def test_tampered_signature_is_definitive(self) -> None:
        heartbeat = next(c for c in self.vectors["cases"] if c["id"] == "heartbeat_success")
        forged = json.loads(base64.b64decode(heartbeat["payload"]))
        forged["sessionToken"] = "session.forged.token"
        wrong_key = next(c for c in self.vectors["cases"] if c["id"] == "wrong_app_key")
        cases = [
            ("tampered", base64.b64encode(json.dumps(forged).encode("utf-8")).decode("ascii"),
             heartbeat["signature"], "nonce-heartbeat-001"),
            ("wrong_app_key", wrong_key["payload"], wrong_key["signature"], "nonce-validate-001"),
        ]
        for label, payload, signature, nonce in cases:
            with self.subTest(case=label):
                self._fresh_client()
                body = json.dumps({"status": "ok", "payload": payload, "signature": signature}).encode("utf-8")
                with patch.object(AuthForgeClient, "_generate_nonce", return_value=nonce):
                    self.assertFalse(self._tick(_ok_response(body)))
                self._assert_definitive("signature_mismatch")

    def test_transient_codes_keep_session_and_loop(self) -> None:
        for code, status in self.TRANSIENT:
            for label, side_effect in (
                ("non-2xx", _failed_response(status, code)),
                ("200 body", _ok_response(json.dumps({"status": "failed", "error": code}).encode("utf-8"))),
            ):
                with self.subTest(code=code, response=label):
                    self._fresh_client()
                    self.assertTrue(self._tick(side_effect))
                    exc = self._assert_transient(code)
                    self.assertEqual(str(exc), code)

    def test_rate_limited_is_retried_before_reporting(self) -> None:
        self.assertTrue(self._tick(_failed_response(429, "rate_limited")))
        self.assertEqual(self.urlopen_calls, 3)
        self.assertEqual([c.args[0] for c in self.sleep.call_args_list], [2, 5])
        self._assert_transient("rate_limited")

    def test_bare_429_is_retried_as_rate_limit(self) -> None:
        self.assertTrue(self._tick(_http_error_response(429, b'{"status":"failed"}')))
        self.assertEqual(self.urlopen_calls, 3)
        self.assertEqual([c.args[0] for c in self.sleep.call_args_list], [2, 5])
        self._assert_transient("unexpected_response")

    def test_credit_429s_are_not_retried(self) -> None:
        for code in self.NOT_RETRIED_429:
            with self.subTest(code=code):
                self._fresh_client()
                self.assertTrue(self._tick(_failed_response(429, code)))
                self.assertEqual(self.urlopen_calls, 1)
                self.sleep.assert_not_called()
                self._assert_transient(code)

    def test_non_json_error_responses_are_transient(self) -> None:
        for status in (403, 500, 502):
            with self.subTest(status=status):
                self._fresh_client()
                self.assertTrue(self._tick(_http_error_response(status, b"<html>error</html>")))
                self.assertEqual(self.urlopen_calls, 1)
                self._assert_transient(f"http_error_{status}")

    def test_unparseable_200_bodies_are_transient(self) -> None:
        cases = [
            (b"", "invalid_json_response"),
            (b"<html>ok</html>", "invalid_json_response"),
            (b'["failed","revoked"]', "response_not_json_object"),
            (b'"revoked"', "response_not_json_object"),
        ]
        for raw, code in cases:
            with self.subTest(raw=raw):
                self._fresh_client()
                self.assertTrue(self._tick(_ok_response(raw)))
                self._assert_transient(code)

    def test_malformed_failure_bodies_are_unexpected_response(self) -> None:
        bodies = [
            {"error": "revoked"},
            {"status": "revoked"},
            {"status": "failed"},
            {"status": "failed", "error": ""},
            {"status": "failed", "error": 7},
            {"status": "denied", "error": "revoked"},
        ]
        for body in bodies:
            for label, side_effect in (
                ("200", _ok_response(json.dumps(body).encode("utf-8"))),
                ("403", _http_error_response(403, json.dumps(body).encode("utf-8"))),
            ):
                with self.subTest(body=body, response=label):
                    self._fresh_client()
                    self.assertTrue(self._tick(side_effect))
                    exc = self._assert_transient("unexpected_response")
                    self.assertIn(f"status={body.get('status')!r}", str(exc))
                    self.assertIn(f"error={body.get('error')!r}", str(exc))

    def test_network_error_is_transient_and_reported_once(self) -> None:
        self.assertTrue(self._tick(urllib.error.URLError("connection refused")))
        self.assertEqual(self.urlopen_calls, 2)
        exc = self._assert_transient("network_error")
        self.assertTrue(str(exc).startswith("url_error: "))

    def test_timeout_is_transient_and_reported_once(self) -> None:
        self.assertTrue(self._tick(socket.timeout("timed out")))
        self.assertEqual(self.urlopen_calls, 2)
        self._assert_transient("timeout")

    def test_transient_failure_after_session_ttl_becomes_fatal(self) -> None:
        for cause, side_effect in (
            ("network_error", urllib.error.URLError("offline")),
            ("no_credits", _failed_response(429, "no_credits")),
            ("unexpected_response", _ok_response(b'{"status":"revoked"}')),
        ):
            with self.subTest(cause=cause):
                self._fresh_client()
                self.client._session_expires_in = int(time.time()) - 1
                self.assertFalse(self._tick(side_effect))
                exc = self._only_failure()
                self.assertEqual(exc.code, "session_expired")
                self.assertTrue(exc.fatal)
                self.assertEqual(exc.__cause__.code, cause)
                self._assert_invalidated()

    def test_success_after_transient_failure_refreshes_session(self) -> None:
        heartbeat = next(c for c in self.vectors["cases"] if c["id"] == "heartbeat_success")
        with patch.object(AuthForgeClient, "_generate_nonce", return_value="nonce-heartbeat-001"):
            self.assertTrue(self._tick(urllib.error.URLError("offline")))
            self.assertTrue(
                self._tick(
                    [_urlopen_ok({"status": "ok", "payload": heartbeat["payload"], "signature": heartbeat["signature"]})]
                )
            )
        self.assertEqual(len(self.failures), 1)
        self.assertTrue(self.client.is_authenticated())
        self.assertEqual(self.client._session_token, "session.heartbeat.token")

    def test_session_is_dropped_before_on_failure_runs(self) -> None:
        seen = MagicMock()
        self.client.on_failure = lambda reason, exc: seen(self.client.is_authenticated())
        self._tick(_failed_response(410, "revoked"))
        seen.assert_called_once_with(False)

    def test_grace_period_expiry_invalidates_session(self) -> None:
        self.client.online_heartbeat = False
        self.client._session_expires_in = int(time.time()) - 1
        self.assertFalse(self._tick(AssertionError("grace period must not use the network")))
        exc = self._only_failure()
        self.assertEqual(exc.code, "session_expired")
        self.assertTrue(exc.fatal)
        self._assert_invalidated()

    def test_without_on_failure_transient_failure_warns_and_keeps_checking_in(self) -> None:
        for code, side_effect in (
            ("network_error", urllib.error.URLError("offline")),
            ("system_error", _failed_response(500, "system_error")),
        ):
            with self.subTest(code=code):
                self._fresh_client()
                self.client.on_failure = None
                stderr = io.StringIO()
                with patch("authforge.os._exit") as exit_mock, patch("authforge.sys.stderr", stderr):
                    self.assertTrue(self._tick(side_effect))
                exit_mock.assert_not_called()
                self.assertEqual(
                    stderr.getvalue(),
                    f"AuthForge: background check failed ({code}); retrying next interval\n",
                )
                self._assert_session_kept()

    def test_without_on_failure_transient_warning_tolerates_missing_stderr(self) -> None:
        self.client.on_failure = None
        with patch("authforge.os._exit") as exit_mock, patch("authforge.sys.stderr", None):
            self.assertTrue(self._tick(urllib.error.URLError("offline")))
        exit_mock.assert_not_called()
        self._assert_session_kept()

    def test_without_on_failure_definitive_failure_exits(self) -> None:
        for label, expires_in, side_effect in (
            ("revoked", None, _failed_response(410, "revoked")),
            ("ttl-promoted session_expired", int(time.time()) - 1, urllib.error.URLError("offline")),
        ):
            with self.subTest(case=label):
                self._fresh_client()
                self.client.on_failure = None
                if expires_in is not None:
                    self.client._session_expires_in = expires_in
                stderr = io.StringIO()
                with patch("authforge.os._exit") as exit_mock, patch("authforge.sys.stderr", stderr):
                    self.assertFalse(self._tick(side_effect))
                exit_mock.assert_called_once_with(1)
                self.assertEqual(stderr.getvalue(), "")
                self._assert_invalidated()

    def test_without_on_failure_login_failure_exits(self) -> None:
        self.client.on_failure = None
        with patch("authforge.os._exit") as exit_mock:
            with patch("authforge.urllib.request.urlopen", side_effect=_failed_response(401, "invalid_key")):
                self.assertFalse(self.client.login("license-key"))
        exit_mock.assert_called_once_with(1)

    def test_is_transient_error_classification(self) -> None:
        definitive = {
            "revoked",
            "expired",
            "hwid_mismatch",
            "blocked",
            "session_expired",
            "malformed_request",
            "app_disabled",
            "invalid_app",
            "signature_mismatch",
        }
        self.assertEqual(authforge.DEFINITIVE_ERROR_CODES, definitive)
        self.assertEqual(authforge.TRANSIENT_ERROR_CODES & definitive, frozenset())
        for code in definitive:
            self.assertFalse(authforge.is_transient_error(code), code)
            self.assertTrue(authforge.AuthForgeError(code).fatal, code)
        for code in (
            *authforge.TRANSIENT_ERROR_CODES,
            "server_error",
            "http_error_400",
            "http_error_403",
            "http_error_404",
            "http_error_429",
            "http_error_503",
            "some_future_code",
            "",
            None,
        ):
            self.assertTrue(authforge.is_transient_error(code), code)
        self.assertFalse(authforge.is_transient_error(authforge.AuthForgeError("revoked")))
        self.assertTrue(authforge.is_transient_error(authforge.AuthForgeError("no_credits")))
        self.assertTrue(authforge.is_transient_error(RuntimeError("revoked")))

    def test_on_failure_can_logout_and_query_state_without_deadlock(self) -> None:
        for label, side_effect, fatal in (
            ("transient", _failed_response(500, "system_error"), False),
            ("fatal", _failed_response(410, "revoked"), True),
        ):
            with self.subTest(failure=label):
                self._fresh_client()
                seen: list = []

                def on_failure(reason, exc):
                    seen.append(("before", self.client.is_authenticated()))
                    self.client.logout()
                    seen.append(("after", self.client.is_authenticated()))

                self.client.on_failure = on_failure
                _run_in_thread(lambda: self._tick(side_effect))
                self.assertEqual(seen, [("before", not fatal), ("after", False)])
                self._assert_invalidated()

    def test_logout_during_in_flight_heartbeat_stays_logged_out(self) -> None:
        heartbeat = next(c for c in self.vectors["cases"] if c["id"] == "heartbeat_success")
        success = _ok_response(
            json.dumps(
                {"status": "ok", "payload": heartbeat["payload"], "signature": heartbeat["signature"]}
            ).encode("utf-8")
        )
        for label, response in (("success", success), ("revoked", _failed_response(410, "revoked"))):
            with self.subTest(response=label):
                self._fresh_client()
                entered = threading.Event()
                release = threading.Event()

                def blocking_urlopen(*args, **kwargs):
                    entered.set()
                    if not release.wait(5):
                        raise AssertionError("heartbeat was never released")
                    return response(*args, **kwargs)

                results: list = []

                def tick() -> None:
                    with patch.object(AuthForgeClient, "_generate_nonce", return_value="nonce-heartbeat-001"):
                        results.append(self._tick(blocking_urlopen))

                worker = threading.Thread(target=tick, daemon=True)
                worker.start()
                self.assertTrue(entered.wait(5))
                self.client.logout()
                release.set()
                worker.join(5)
                self.assertFalse(worker.is_alive())
                self.assertEqual(len(results), 1)
                self.assertFalse(self.client.is_authenticated())
                self.assertIsNone(self.client._session_token)
                self.assertIsNone(self.client.get_session_kind())
                self.assertEqual(self.failures, [], "a stale tick must not report")

    def test_late_heartbeat_does_not_overwrite_a_new_login(self) -> None:
        heartbeat = next(c for c in self.vectors["cases"] if c["id"] == "heartbeat_success")
        validate = next(c for c in self.vectors["cases"] if c["id"] == "validate_success")
        entered = threading.Event()
        release = threading.Event()
        success = _ok_response(
            json.dumps(
                {"status": "ok", "payload": heartbeat["payload"], "signature": heartbeat["signature"]}
            ).encode("utf-8")
        )

        def blocking_urlopen(*args, **kwargs):
            entered.set()
            release.wait(5)
            return success(*args, **kwargs)

        def tick() -> None:
            with patch.object(AuthForgeClient, "_generate_nonce", return_value="nonce-heartbeat-001"):
                self._tick(blocking_urlopen)

        worker = threading.Thread(target=tick, daemon=True)
        worker.start()
        self.assertTrue(entered.wait(5))
        self.client._apply_signed_response(
            {"status": "ok", "payload": validate["payload"], "signature": validate["signature"]},
            expected_nonce="nonce-validate-001",
            license_key="new-license-key",
            context="validate",
        )
        release.set()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(self.client._license_key, "new-license-key")
        self.assertEqual(self.client._session_token, "session.validate.token")

    def test_loop_keeps_checking_in_after_transient_failures(self) -> None:
        self.client.heartbeat_interval = 0

        def on_failure(reason, exc):
            self.failures.append((reason, exc))
            if len(self.failures) == 3:
                self.client.logout()

        self.client.on_failure = on_failure
        with patch("authforge.urllib.request.urlopen", side_effect=_failed_response(503, "system_error")):
            self.client._start_heartbeat_once()
            thread = self.client._heartbeat_thread
            assert thread is not None
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual([exc.code for _reason, exc in self.failures], ["system_error"] * 3)
        self.assertFalse(self.client.is_authenticated())

    def test_loop_stops_after_definitive_failure(self) -> None:
        self.client.heartbeat_interval = 0
        with patch("authforge.urllib.request.urlopen", side_effect=_failed_response(410, "revoked")) as urlopen:
            self.client._start_heartbeat_once()
            thread = self.client._heartbeat_thread
            assert thread is not None
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(urlopen.call_count, 1)
        self.assertEqual([exc.code for _reason, exc in self.failures], ["revoked"])
        self._assert_invalidated()


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
            app_secret=None,
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

    def test_login_from_file_does_not_need_app_secret(self) -> None:
        client, failures = self._make_client(app_secret="")
        self.assertEqual(client.app_secret, "")
        self.assertTrue(client.login_from_file(self.lifetime["file"]))
        self.assertTrue(client.is_authenticated())
        self.assertEqual(failures, [])

    def test_login_requires_app_secret(self) -> None:
        client, _ = self._make_client(app_secret=None)
        with self.assertRaises(ValueError) as ctx:
            client.login("XXXX-XXXX-XXXX-XXXX")
        self.assertIn("app_secret is required for online APIs", str(ctx.exception))
        self.assertFalse(client.is_authenticated())

    def test_offline_self_ban_is_local_error_and_never_posts(self) -> None:
        # Closed port: any accidental network call fails loudly instead of hanging.
        client, _ = self._make_client(
            api_base_url="http://127.0.0.1:9",
            # Explicit-license SelfBan is an online API; this test covers that
            # dual-mode path. Offline-only clients omit the secret entirely.
            app_secret="online-selfban",
        )
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


class ActivationRequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        path = Path(__file__).resolve().parent / "activation_request_vectors.json"
        with path.open(encoding="utf-8") as handle:
            cls.vectors = json.load(handle)

    def test_create_activation_request_matches_vectors(self) -> None:
        dummy_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        for case in self.vectors["cases"]:
            inputs = case.get("inputs")
            if not inputs:
                continue
            with self.subTest(case=case["name"]):
                client = AuthForgeClient(
                    app_id=inputs["appId"],
                    app_secret=None,
                    public_key=dummy_key,
                    hwid_override=inputs["hwid"],
                )
                got = client.create_activation_request(
                    created_at=inputs["createdAt"],
                    omit_os="os" not in inputs,
                    omit_sdk="sdk" not in inputs,
                    include_machine_name=bool(inputs.get("machineName")),
                    machine_name=inputs.get("machineName"),
                    os=inputs.get("os"),
                    sdk=inputs.get("sdk"),
                    license_key=inputs.get("licenseKey") or "",
                )
                self.assertEqual(got, case["file"])
                self.assertEqual(
                    format_activation_request(
                        app_id=inputs["appId"],
                        hwid=inputs["hwid"],
                        created_at=inputs["createdAt"],
                        machine_name=inputs.get("machineName"),
                        os=inputs.get("os"),
                        sdk=inputs.get("sdk"),
                        license_key=inputs.get("licenseKey"),
                    ),
                    case["file"],
                )

    def test_works_without_app_secret_before_login(self) -> None:
        client = AuthForgeClient(
            app_id="test-app",
            app_secret=None,
            public_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            hwid_override="testhwid",
        )
        text = client.create_activation_request(
            created_at="2026-09-11T12:00:00.000Z",
            omit_os=True,
            omit_sdk=True,
        )
        self.assertIn("BEGIN AUTHFORGE ACTIVATION REQUEST", text)
        self.assertNotIn("BEGIN AUTHFORGE LICENSE", text)
        self.assertNotIn("machineName", text)

    def test_sdk_tag_matches_pyproject_version(self) -> None:
        text = (Path(__file__).resolve().parent / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'(?m)^version = "([^"]+)"', text)
        self.assertIsNotNone(match)
        self.assertEqual(authforge._SDK_TAG, f"python/{match.group(1)}")

    def test_write_activation_request(self) -> None:
        client = AuthForgeClient(
            app_id="test-app",
            app_secret=None,
            public_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            hwid_override="testhwid",
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "machine.authforge-request"
            client.write_activation_request(
                str(path),
                created_at="2026-09-11T12:00:00.000Z",
                omit_os=True,
                omit_sdk=True,
            )
            self.assertEqual(
                path.read_text(encoding="utf-8"),
                client.create_activation_request(
                    created_at="2026-09-11T12:00:00.000Z",
                    omit_os=True,
                    omit_sdk=True,
                ),
            )


if __name__ == "__main__":
    unittest.main()
