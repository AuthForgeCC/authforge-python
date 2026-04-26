import base64
import hashlib
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
from typing import Any, Callable, Dict, Iterable, List, Literal, Optional, Sequence, TypedDict, Union
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


PublicKeyArg = Union[str, Sequence[str]]


DEFAULT_API_BASE_URL = "https://auth.authforge.cc"
RATE_LIMIT_RETRY_DELAYS = (2, 5)
NETWORK_RETRY_DELAY = 2
class ValidateLicenseSuccess(TypedDict):
    valid: Literal[True]
    session_token: str
    expires_in: int
    session_data: Dict[str, Any]
    app_variables: Optional[Dict[str, Any]]
    license_variables: Optional[Dict[str, Any]]
    key_id: Optional[str]


class ValidateLicenseFailure(TypedDict):
    valid: Literal[False]
    code: str
    error: str


ValidateLicenseResult = Union[ValidateLicenseSuccess, ValidateLicenseFailure]


KNOWN_SERVER_ERRORS = {
    "invalid_app",
    "invalid_key",
    "expired",
    "revoked",
    "hwid_mismatch",
    "no_credits",
    "app_burn_cap_reached",
    "blocked",
    "rate_limited",
    "replay_detected",
    "app_disabled",
    "session_expired",
    "revoke_requires_session",
    "bad_request",
    "system_error",
}


class AuthForgeClient:
    def __init__(
        self,
        app_id: str,
        app_secret: str,
        public_key: PublicKeyArg,
        heartbeat_mode: str,
        heartbeat_interval: int = 900,
        api_base_url: str = DEFAULT_API_BASE_URL,
        on_failure: Optional[Callable[[str, Optional[Exception]], None]] = None,
        request_timeout: int = 15,
        ttl_seconds: Optional[int] = None,
        hwid_override: Optional[str] = None,
    ) -> None:
        if not app_id or not isinstance(app_id, str):
            raise ValueError("app_id must be a non-empty string")
        if not app_secret or not isinstance(app_secret, str):
            raise ValueError("app_secret must be a non-empty string")
        public_key_list = self._normalize_public_key_list(public_key)
        if not public_key_list:
            raise ValueError(
                "public_key must be a non-empty base64 string or list of base64 strings"
            )
        mode = (heartbeat_mode or "").upper()
        if mode not in {"LOCAL", "SERVER"}:
            raise ValueError("heartbeat_mode must be LOCAL or SERVER")
        if heartbeat_interval <= 0:
            raise ValueError("heartbeat_interval must be > 0")

        self.app_id = app_id
        self.app_secret = app_secret
        # `public_key` is the historical public attribute. We now hold the
        # full trust list to support key rotation, but expose the first entry
        # as `public_key` for callers that read it directly.
        self.public_keys: List[str] = public_key_list
        self.public_key = public_key_list[0]
        self.heartbeat_mode = mode
        self.heartbeat_interval = int(heartbeat_interval)
        self.api_base_url = api_base_url.rstrip("/")
        self.on_failure = on_failure
        self.request_timeout = request_timeout
        # None / 0 / negative means "let the server pick its default (24h)".
        # Server clamps to [3600, 604800]; we don't duplicate the clamp here.
        self.ttl_seconds: Optional[int] = (
            int(ttl_seconds) if isinstance(ttl_seconds, int) and ttl_seconds > 0 else None
        )

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
        self._key_id: Optional[str] = None
        self._session_data: Optional[Dict[str, Any]] = None
        self._app_variables: Optional[Dict[str, Any]] = None
        self._license_variables: Optional[Dict[str, Any]] = None
        self._authenticated = False
        self._hwid = self._resolve_hwid(hwid_override)
        self._ed25519_public_keys: List[Ed25519PublicKey] = [
            self._load_public_key(k) for k in public_key_list
        ]

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

    def validate_license(self, license_key: str) -> ValidateLicenseResult:
        """Validate like :meth:`login` (same /auth/validate + signatures) without storing
        session state or starting the heartbeat thread."""
        if not license_key or not isinstance(license_key, str):
            raise ValueError("license_key must be a non-empty string")
        try:
            body: Dict[str, Any] = {
                "appId": self.app_id,
                "appSecret": self.app_secret,
                "licenseKey": license_key,
                "hwid": self._hwid,
                "nonce": self._generate_nonce(),
            }
            if self.ttl_seconds is not None:
                body["ttlSeconds"] = self.ttl_seconds
            response_obj = self._post_json("/auth/validate", body, skip_failure_hook=True)
            expected_nonce = str(body.get("nonce", "")).strip()
            parsed = self._parse_validate_success(response_obj, expected_nonce)
            return {
                "valid": True,
                "session_token": parsed["session_token"],
                "expires_in": parsed["expires_in"],
                "session_data": parsed["session_data"],
                "app_variables": parsed["app_variables"],
                "license_variables": parsed["license_variables"],
                "key_id": parsed["key_id"],
            }
        except Exception as exc:
            return {"valid": False, "code": str(exc), "error": str(exc)}

    def self_ban(
        self,
        *,
        license_key: Optional[str] = None,
        session_token: Optional[str] = None,
        revoke_license: bool = True,
        blacklist_hwid: bool = True,
        blacklist_ip: bool = True,
    ) -> Dict[str, Any]:
        resolved_session = (
            session_token.strip()
            if isinstance(session_token, str) and session_token.strip()
            else None
        )
        with self._lock:
            current_session = self._session_token
            current_license = self._license_key
            hwid = self._hwid
        resolved_session = resolved_session or current_session

        if resolved_session:
            body: Dict[str, Any] = {
                "appId": self.app_id,
                "sessionToken": resolved_session,
                "hwid": hwid,
                "revokeLicense": bool(revoke_license),
                "blacklistHwid": bool(blacklist_hwid),
                "blacklistIp": bool(blacklist_ip),
            }
            response_obj = self._post_json("/auth/selfban", body)
            if not self._is_success_status(response_obj.get("status")):
                raise ValueError(self._extract_server_error(response_obj))
            return response_obj

        resolved_license = (
            license_key.strip()
            if isinstance(license_key, str) and license_key.strip()
            else None
        )
        resolved_license = resolved_license or current_license
        if not resolved_license:
            raise ValueError("missing_license_key")

        body = {
            "appId": self.app_id,
            "appSecret": self.app_secret,
            "licenseKey": resolved_license,
            "hwid": hwid,
            "nonce": self._generate_nonce(),
            # Pre-session self-ban cannot revoke licenses.
            "revokeLicense": False,
            "blacklistHwid": bool(blacklist_hwid),
            "blacklistIp": bool(blacklist_ip),
        }
        response_obj = self._post_json("/auth/selfban", body)
        if not self._is_success_status(response_obj.get("status")):
            raise ValueError(self._extract_server_error(response_obj))
        return response_obj

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
        self._apply_signed_response(
            response_obj,
            expected_nonce=expected_nonce,
            license_key=None,
            context="heartbeat",
        )

    def _local_heartbeat(self) -> None:
        with self._lock:
            raw_payload_b64 = self._raw_payload_b64
            signature = self._signature
            expires_in = self._session_expires_in
        if not raw_payload_b64 or not signature:
            raise RuntimeError("missing_local_verification_state")

        self._verify_signature(raw_payload_b64, signature)

        if expires_in is None:
            raise RuntimeError("missing_session_expiry")

        now = int(time.time())
        if now >= int(expires_in):
            raise RuntimeError("session_expired")

    def _validate_and_store(self, license_key: str) -> None:
        body: Dict[str, Any] = {
            "appId": self.app_id,
            "appSecret": self.app_secret,
            "licenseKey": license_key,
            "hwid": self._hwid,
            "nonce": self._generate_nonce(),
        }
        if self.ttl_seconds is not None:
            body["ttlSeconds"] = self.ttl_seconds
        response_obj = self._post_json("/auth/validate", body)
        expected_nonce = str(body.get("nonce", "")).strip()
        self._apply_signed_response(
            response_obj,
            expected_nonce=expected_nonce,
            license_key=license_key,
            context="validate",
        )

    def _parse_validate_success(
        self, response_obj: Dict[str, Any], expected_nonce: str
    ) -> Dict[str, Any]:
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

        self._verify_signature(raw_payload_b64, signature)

        session_token = str(payload_json.get("sessionToken", "")).strip()
        if not session_token:
            raise ValueError("missing_sessionToken")
        key_id = response_obj.get("keyId")
        if key_id is not None and not isinstance(key_id, str):
            raise ValueError("invalid_keyId")

        expires_from_token = self._extract_expires_in_from_session_token(session_token)
        expires_from_payload = payload_json.get("expiresIn")

        expires_in = expires_from_token
        if expires_in is None and expires_from_payload is not None:
            expires_in = int(expires_from_payload)
        if expires_in is None:
            raise ValueError("missing_expiresIn")

        return {
            "session_token": session_token,
            "expires_in": int(expires_in),
            "session_data": dict(payload_json),
            "app_variables": self._extract_optional_map(payload_json.get("appVariables")),
            "license_variables": self._extract_optional_map(
                payload_json.get("licenseVariables")
            ),
            "key_id": key_id if isinstance(key_id, str) else None,
            "raw_payload_b64": raw_payload_b64,
            "signature": signature,
        }

    def _apply_signed_response(
        self,
        response_obj: Dict[str, Any],
        expected_nonce: str,
        license_key: Optional[str],
        context: str,
    ) -> None:
        parsed = self._parse_validate_success(response_obj, expected_nonce)
        _ = context

        with self._lock:
            if license_key is not None:
                self._license_key = license_key
            self._session_token = parsed["session_token"]
            self._session_expires_in = int(parsed["expires_in"])
            self._last_nonce = expected_nonce
            self._raw_payload_b64 = parsed["raw_payload_b64"]
            self._signature = parsed["signature"]
            self._key_id = parsed["key_id"]
            self._session_data = dict(parsed["session_data"])
            self._app_variables = parsed["app_variables"]
            self._license_variables = parsed["license_variables"]
            self._authenticated = True

    def _post_json(
        self, path: str, data: Dict[str, Any], *, skip_failure_hook: bool = False
    ) -> Dict[str, Any]:
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
                        status_code = int(getattr(response, "status", 200))
                    obj = self._parse_response_object(raw_response)
                    data.clear()
                    data.update(body)
                    break
                except urllib.error.HTTPError as exc:
                    status_code = int(exc.code)
                    try:
                        detail = exc.read().decode("utf-8")
                        obj = self._parse_response_object(detail)
                    except Exception:
                        raise RuntimeError(f"http_error_{status_code}") from exc
                    data.clear()
                    data.update(body)
                    break
                except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
                    if network_attempt == 0:
                        network_attempt += 1
                        time.sleep(NETWORK_RETRY_DELAY)
                        continue
                    if not skip_failure_hook:
                        self._fail("network_error", exc)
                    raise RuntimeError(f"url_error: {exc}") from exc

            is_rate_limited = (
                status_code == 429
                or self._extract_server_error(obj) == "rate_limited"
            )
            if is_rate_limited and rate_attempt < len(RATE_LIMIT_RETRY_DELAYS):
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

    def _resolve_hwid(self, hwid_override: Optional[str]) -> str:
        if isinstance(hwid_override, str):
            trimmed = hwid_override.strip()
            if trimmed:
                return trimmed
        return self._get_hwid()

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
        payload = self._decode_session_token_body(session_token)
        if payload is None:
            return None
        value = payload.get("exp")
        if value is None:
            return None
        return int(value)

    def _decode_session_token_body(self, session_token: str) -> Optional[Dict[str, Any]]:
        parts = session_token.split(".")
        if len(parts) < 2:
            return None
        padded = self._add_base64_padding(parts[0])
        try:
            decoded = base64.urlsafe_b64decode(padded)
            payload = json.loads(decoded.decode("utf-8"))
        except Exception:
            return None
        if not isinstance(payload, dict):
            return None
        return payload

    def _add_base64_padding(self, text: str) -> str:
        remainder = len(text) % 4
        if remainder == 0:
            return text
        return text + ("=" * (4 - remainder))

    def _load_public_key(self, public_key_b64: str) -> Ed25519PublicKey:
        try:
            public_key_bytes = base64.b64decode(
                self._add_base64_padding(public_key_b64), validate=True
            )
        except Exception as exc:
            raise ValueError("invalid_public_key") from exc
        if len(public_key_bytes) != 32:
            raise ValueError("invalid_public_key_length")
        return Ed25519PublicKey.from_public_bytes(public_key_bytes)

    def _verify_signature(self, raw_payload_b64: str, signature: str) -> None:
        try:
            signature_bytes = base64.b64decode(
                self._add_base64_padding(signature), validate=True
            )
        except Exception as exc:
            raise ValueError("invalid_signature_encoding") from exc
        # During a key rotation the SDK may be pinned to the previous key
        # while a new server-side key signs responses (or vice-versa). Trust
        # any key in the configured list.
        payload_bytes = raw_payload_b64.encode("utf-8")
        for key in self._ed25519_public_keys:
            try:
                key.verify(signature_bytes, payload_bytes)
                return
            except InvalidSignature:
                continue
        raise ValueError("signature_mismatch")

    @staticmethod
    def _normalize_public_key_list(value: PublicKeyArg) -> List[str]:
        """Coerce the public_key constructor arg to a list of base64 strings.

        Accepts:
          - "abc..."                     single-key historical contract
          - ["abc...", "def..."]         current first, previous after
          - "abc...,def..."              env-var convenience form
        """
        keys: List[str] = []
        candidates: Iterable[Any]
        if isinstance(value, str):
            candidates = value.split(",") if "," in value else [value]
        elif isinstance(value, Sequence):
            candidates = value
        else:
            return []
        for entry in candidates:
            if not isinstance(entry, str):
                continue
            trimmed = entry.strip()
            if trimmed:
                keys.append(trimmed)
        return keys

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
            self._key_id = None
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
