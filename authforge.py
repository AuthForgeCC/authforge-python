import base64
import hashlib
import hmac
import json
import os
import platform
import secrets
import subprocess
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Callable, Dict, Optional


DEFAULT_API_BASE_URL = "https://auth.authforge.cc"
RATE_LIMIT_RETRY_DELAYS = (2, 5)
NETWORK_RETRY_DELAY = 2
KNOWN_SERVER_ERRORS = {
    "invalid_app",
    "invalid_key",
    "expired",
    "revoked",
    "hwid_mismatch",
    "no_credits",
    "blocked",
    "rate_limited",
    "replay_detected",
    "app_disabled",
    "session_expired",
    "bad_request",
    "checksum_required",
    "checksum_mismatch",
}


class AuthForgeClient:
    def __init__(
        self,
        app_id: str,
        app_secret: str,
        heartbeat_mode: str,
        heartbeat_interval: int = 900,
        api_base_url: str = DEFAULT_API_BASE_URL,
        on_failure: Optional[Callable[[str, Optional[Exception]], None]] = None,
        request_timeout: int = 15,
    ) -> None:
        if not app_id or not isinstance(app_id, str):
            raise ValueError("app_id must be a non-empty string")
        if not app_secret or not isinstance(app_secret, str):
            raise ValueError("app_secret must be a non-empty string")
        mode = (heartbeat_mode or "").upper()
        if mode not in {"LOCAL", "SERVER"}:
            raise ValueError("heartbeat_mode must be LOCAL or SERVER")
        if heartbeat_interval <= 0:
            raise ValueError("heartbeat_interval must be > 0")

        self.app_id = app_id
        self.app_secret = app_secret
        self.heartbeat_mode = mode
        self.heartbeat_interval = int(heartbeat_interval)
        self.api_base_url = api_base_url.rstrip("/")
        self.on_failure = on_failure
        self.request_timeout = request_timeout

        self._lock = threading.Lock()
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._heartbeat_started = False
        self._heartbeat_stop = threading.Event()

        self._license_key: Optional[str] = None
        self._session_token: Optional[str] = None
        self._session_expires_in: Optional[int] = None
        self._last_nonce: Optional[str] = None
        self._raw_payload_b64: Optional[str] = None
        self._signature: Optional[str] = None
        self._derived_key: Optional[bytes] = None
        self._session_data: Optional[Dict[str, Any]] = None
        self._app_variables: Optional[Dict[str, Any]] = None
        self._license_variables: Optional[Dict[str, Any]] = None
        self._authenticated = False
        self._hwid = self._get_hwid()

    def login(self, license_key: str) -> bool:
        if not license_key or not isinstance(license_key, str):
            raise ValueError("license_key must be a non-empty string")

        try:
            self._validate_and_store(license_key)
            self._start_heartbeat_once()
            return True
        except Exception as exc:
            self._fail("login_failed", exc)
            return False

    def _start_heartbeat_once(self) -> None:
        with self._lock:
            if self._heartbeat_started:
                return
            self._heartbeat_stop.clear()
            self._heartbeat_started = True
            self._heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop,
                name="AuthForgeHeartbeat",
                daemon=True,
            )
            self._heartbeat_thread.start()

    def _heartbeat_loop(self) -> None:
        while not self._heartbeat_stop.wait(self.heartbeat_interval):
            try:
                if self.heartbeat_mode == "SERVER":
                    self._server_heartbeat()
                else:
                    self._local_heartbeat()
            except Exception as exc:
                self._fail("heartbeat_failed", exc)
                break

    def _server_heartbeat(self) -> None:
        with self._lock:
            session_token = self._session_token
            hwid = self._hwid
        if not session_token:
            raise RuntimeError("missing_session_token")

        body = {
            "appId": self.app_id,
            "sessionToken": session_token,
            "nonce": self._generate_nonce(),
            "hwid": hwid,
        }
        response_obj = self._post_json("/auth/heartbeat", body)
        expected_nonce = str(body.get("nonce", "")).strip()
        self._apply_signed_response(response_obj, expected_nonce=expected_nonce, license_key=None)

    def _local_heartbeat(self) -> None:
        with self._lock:
            raw_payload_b64 = self._raw_payload_b64
            signature = self._signature
            derived_key = self._derived_key
            expires_in = self._session_expires_in
        if not raw_payload_b64 or not signature or not derived_key:
            raise RuntimeError("missing_local_verification_state")

        self._verify_signature(raw_payload_b64, derived_key, signature)

        if expires_in is None:
            raise RuntimeError("missing_session_expiry")

        now = int(time.time())
        if now >= int(expires_in):
            raise RuntimeError("session_expired")

    def _validate_and_store(self, license_key: str) -> None:
        body = {
            "appId": self.app_id,
            "appSecret": self.app_secret,
            "licenseKey": license_key,
            "hwid": self._hwid,
            "nonce": self._generate_nonce(),
        }
        response_obj = self._post_json("/auth/validate", body)
        expected_nonce = str(body.get("nonce", "")).strip()
        self._apply_signed_response(response_obj, expected_nonce=expected_nonce, license_key=license_key)

    def _apply_signed_response(
        self,
        response_obj: Dict[str, Any],
        expected_nonce: str,
        license_key: Optional[str],
    ) -> None:
        status = response_obj.get("status")
        if not self._is_success_status(status):
            error_code = self._extract_server_error(response_obj)
            raise ValueError(error_code)

        raw_payload_b64 = self._require_str(response_obj, "payload")
        signature = self._require_str(response_obj, "signature")
        payload_json = self._decode_payload_json(raw_payload_b64)

        received_nonce = str(payload_json.get("nonce", "")).strip()
        if received_nonce != expected_nonce:
            raise ValueError("nonce_mismatch")

        derived_key = self._derive_key(expected_nonce)
        self._verify_signature(raw_payload_b64, derived_key, signature)

        session_token = str(payload_json.get("sessionToken", "")).strip()
        if not session_token:
            raise ValueError("missing_sessionToken")

        expires_from_token = self._extract_expires_in_from_session_token(session_token)
        expires_from_payload = payload_json.get("expiresIn")

        expires_in = expires_from_token
        if expires_in is None and expires_from_payload is not None:
            expires_in = int(expires_from_payload)
        if expires_in is None:
            raise ValueError("missing_expiresIn")

        with self._lock:
            if license_key is not None:
                self._license_key = license_key
            self._session_token = session_token
            self._session_expires_in = int(expires_in)
            self._last_nonce = expected_nonce
            self._raw_payload_b64 = raw_payload_b64
            self._signature = signature
            self._derived_key = derived_key
            self._session_data = dict(payload_json)
            self._app_variables = self._extract_optional_map(payload_json.get("appVariables"))
            self._license_variables = self._extract_optional_map(payload_json.get("licenseVariables"))
            self._authenticated = True

    def _post_json(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.api_base_url}{path}"
        body = dict(data)
        rate_attempt = 0
        while True:
            if rate_attempt > 0 and "nonce" in body:
                body["nonce"] = self._generate_nonce()

            network_attempt = 0
            while True:
                payload_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
                request = urllib.request.Request(
                    url=url,
                    data=payload_bytes,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(request, timeout=self.request_timeout) as response:
                        raw_response = response.read().decode("utf-8")
                    obj = self._parse_response_object(raw_response)
                    data.clear()
                    data.update(body)
                    break
                except urllib.error.HTTPError as exc:
                    detail = ""
                    parsed: Optional[Dict[str, Any]] = None
                    try:
                        detail = exc.read().decode("utf-8")
                        parsed = self._parse_response_object(detail)
                    except Exception:
                        detail = str(exc)
                    if parsed is not None:
                        obj = parsed
                        data.clear()
                        data.update(body)
                        break
                    raise RuntimeError(f"http_error_{exc.code}: {detail}") from exc
                except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
                    if network_attempt == 0:
                        network_attempt += 1
                        time.sleep(NETWORK_RETRY_DELAY)
                        continue
                    self._fail("network_error", exc)
                    raise RuntimeError(f"url_error: {exc}") from exc

            if self._extract_server_error(obj) == "rate_limited" and rate_attempt < len(RATE_LIMIT_RETRY_DELAYS):
                time.sleep(RATE_LIMIT_RETRY_DELAYS[rate_attempt])
                rate_attempt += 1
                continue
            return obj

    def _parse_response_object(self, raw_response: str) -> Dict[str, Any]:
        try:
            obj = json.loads(raw_response)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid_json_response") from exc
        if not isinstance(obj, dict):
            raise ValueError("response_not_json_object")
        return obj

    def _get_hwid(self) -> str:
        mac = self._safe_mac_address()
        cpu = self._safe_cpu_info()
        disk = self._safe_disk_serial()
        material = f"mac:{mac}|cpu:{cpu}|disk:{disk}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _safe_mac_address(self) -> str:
        try:
            return f"{uuid.getnode():012x}"
        except Exception:
            return "mac-unavailable"

    def _safe_cpu_info(self) -> str:
        try:
            value = platform.processor() or platform.machine() or "cpu-unavailable"
            return str(value)
        except Exception:
            return "cpu-unavailable"

    def _safe_disk_serial(self) -> str:
        system = platform.system().lower()
        try:
            if "windows" in system:
                return self._run_command(["wmic", "diskdrive", "get", "serialnumber"])
            if "linux" in system:
                out = self._run_command(["lsblk", "-ndo", "SERIAL"])
                if out and out.strip():
                    return out
                return self._run_command(["udevadm", "info", "--query=property", "--name=sda"])
            if "darwin" in system:
                return self._run_command(["system_profiler", "SPStorageDataType"])
        except Exception:
            pass
        return "disk-unavailable"

    def _run_command(self, command: list[str]) -> str:
        try:
            output = subprocess.check_output(
                command,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            cleaned = " ".join(output.decode("utf-8", errors="ignore").split())
            return cleaned[:256] if cleaned else "empty"
        except Exception:
            return "unavailable"

    def _decode_payload_json(self, payload_b64: str) -> Dict[str, Any]:
        payload_bytes = self._decode_base64_any(payload_b64)
        try:
            payload_obj = json.loads(payload_bytes.decode("utf-8"))
        except Exception as exc:
            raise ValueError("invalid_payload_json") from exc
        if not isinstance(payload_obj, dict):
            raise ValueError("payload_not_json_object")
        return payload_obj

    def _decode_base64_any(self, value: str) -> bytes:
        padded = self._add_base64_padding(value)
        try:
            return base64.b64decode(padded, validate=False)
        except Exception:
            return base64.urlsafe_b64decode(padded)

    def _extract_expires_in_from_session_token(self, session_token: str) -> Optional[int]:
        parts = session_token.split(".")
        if len(parts) < 2:
            return None
        payload_part = parts[0]
        padded = self._add_base64_padding(payload_part)
        try:
            decoded = base64.urlsafe_b64decode(padded)
            payload = json.loads(decoded.decode("utf-8"))
        except Exception:
            return None
        value = payload.get("expiresIn")
        if value is None:
            return None
        return int(value)

    def _add_base64_padding(self, text: str) -> str:
        remainder = len(text) % 4
        if remainder == 0:
            return text
        return text + ("=" * (4 - remainder))

    def _derive_key(self, nonce: str) -> bytes:
        seed = f"{self.app_secret}{nonce}".encode("utf-8")
        return hashlib.sha256(seed).digest()

    def _verify_signature(self, raw_payload_b64: str, derived_key: bytes, signature: str) -> None:
        expected = hmac.new(
            derived_key,
            raw_payload_b64.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        received = signature.strip().lower()
        if not hmac.compare_digest(expected, received):
            raise ValueError("signature_mismatch")

    def _generate_nonce(self) -> str:
        return secrets.token_hex(16)

    def _is_success_status(self, status: Any) -> bool:
        if isinstance(status, bool):
            return status
        if status is None:
            return False
        value = str(status).strip().lower()
        return value in {"ok", "success", "valid", "true", "1"}

    def _require_str(self, obj: Dict[str, Any], key: str) -> str:
        value = obj.get(key)
        if value is None:
            raise ValueError(f"missing_{key}")
        text = str(value)
        if not text:
            raise ValueError(f"empty_{key}")
        return text

    def _extract_server_error(self, obj: Dict[str, Any]) -> str:
        raw_error = str(obj.get("error", "")).strip().lower()
        if raw_error in KNOWN_SERVER_ERRORS:
            return raw_error
        status = str(obj.get("status", "")).strip().lower()
        if status in KNOWN_SERVER_ERRORS:
            return status
        return "unknown_error"

    def _extract_optional_map(self, value: Any) -> Optional[Dict[str, Any]]:
        if isinstance(value, dict):
            return dict(value)
        return None

    def _fail(self, reason: str, exc: Optional[Exception] = None) -> None:
        if self.on_failure is not None:
            try:
                self.on_failure(reason, exc)
                return
            except Exception:
                pass
        os._exit(1)

    def logout(self) -> None:
        self._heartbeat_stop.set()
        with self._lock:
            self._license_key = None
            self._session_token = None
            self._session_expires_in = None
            self._last_nonce = None
            self._raw_payload_b64 = None
            self._signature = None
            self._derived_key = None
            self._session_data = None
            self._app_variables = None
            self._license_variables = None
            self._authenticated = False
            self._heartbeat_started = False
            self._heartbeat_thread = None

    def is_authenticated(self) -> bool:
        with self._lock:
            return self._authenticated and bool(self._session_token)

    def get_session_data(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return dict(self._session_data) if self._session_data is not None else None

    def get_app_variables(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return dict(self._app_variables) if self._app_variables is not None else None

    def get_license_variables(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return dict(self._license_variables) if self._license_variables is not None else None
