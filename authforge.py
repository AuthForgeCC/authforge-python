import base64
import hashlib
import json
import os
import platform
import re
import secrets
import subprocess
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
import warnings
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Literal, Optional, Sequence, TypedDict, Union

from typing_extensions import NotRequired
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
    session_expires_at: NotRequired[str]
    license_expires_at: NotRequired[Optional[str]]
    max_hwid_slots: NotRequired[int]
    hwid_count: NotRequired[int]
    license_label: NotRequired[str]


class ValidateLicenseFailure(TypedDict):
    valid: Literal[False]
    code: str
    error: str


ValidateLicenseResult = Union[ValidateLicenseSuccess, ValidateLicenseFailure]


# ---------------------------------------------------------------------------
# Offline license files (`.authforge`)
#
# A cloud-minted, Ed25519-signed document for machines that never phone home.
# This is a SEPARATE mode from the grace period: the grace period continues a
# signed session after one online activation, while an offline file is
# verified locally with only the app public key and the machine HWID. Nothing
# here performs network I/O or starts online check-ins.
# ---------------------------------------------------------------------------

OFFLINE_LICENSE_FILE_VERSION = 1
# How a client authenticated: server session (login) or local file (login_from_file).
SessionKind = Literal["online", "offline"]
_OFFLINE_BEGIN_LICENSE = "-----BEGIN AUTHFORGE LICENSE-----"
_OFFLINE_END_LICENSE = "-----END AUTHFORGE LICENSE-----"
_OFFLINE_BEGIN_SIGNATURE = "-----BEGIN AUTHFORGE SIGNATURE-----"
_OFFLINE_END_SIGNATURE = "-----END AUTHFORGE SIGNATURE-----"
_OFFLINE_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

OFFLINE_LICENSE_ERRORS = (
    "bad_armor",
    "bad_signature",
    "unsupported_version",
    "malformed_payload",
    "wrong_app",
    "expired",
    "hwid_mismatch",
)

# Activation requests (`.authforge-request`): unsigned transport for a HWID.
# Distinct markers from BEGIN AUTHFORGE LICENSE. Not signed; the Checksum
# header is the only integrity check. Keep _SDK_TAG in sync with pyproject.toml.
_ACTIVATION_REQUEST_VERSION = 1
_ACTIVATION_REQUEST_TYP = "authforge-activation-request"
_BEGIN_ACTIVATION_REQUEST = "-----BEGIN AUTHFORGE ACTIVATION REQUEST-----"
_END_ACTIVATION_REQUEST = "-----END AUTHFORGE ACTIVATION REQUEST-----"
_SDK_TAG = "python/1.3.1"
_ARMOR_LINE_WIDTH = 64
_MAX_REQUEST_HWID = 256
_MAX_REQUEST_MACHINE_NAME = 128
_MAX_REQUEST_OS = 64
_MAX_REQUEST_SDK = 64
_MAX_REQUEST_LICENSE_KEY = 64


class OfflineLicense(TypedDict):
    app_id: str
    license_key: str
    jti: str
    key_id: str
    issued_at: str
    expires_at: Optional[str]
    hwid_policy: Dict[str, Any]
    label: NotRequired[str]
    license_expires_at: NotRequired[Optional[str]]
    license_variables: Optional[Dict[str, Any]]
    app_variables: Optional[Dict[str, Any]]
    payload: Dict[str, Any]


class VerifyLicenseFileSuccess(TypedDict):
    ok: Literal[True]
    license: OfflineLicense
    payload_base64: str
    signature_base64: str


class VerifyLicenseFileFailure(TypedDict):
    ok: Literal[False]
    error: str


VerifyLicenseFileResult = Union[VerifyLicenseFileSuccess, VerifyLicenseFileFailure]


class ParsedLicenseFile(TypedDict):
    headers: Dict[str, str]
    payload_base64: str
    signature_base64: str


def _clip_request_field(value: str, max_len: int) -> str:
    return value if len(value) <= max_len else value[:max_len]


def _json_escape_request(value: str) -> str:
    out: List[str] = []
    for ch in value:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20:
            out.append(f"\\u00{code:02x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _wrap_armor_64(value: str) -> str:
    return "\n".join(value[i : i + _ARMOR_LINE_WIDTH] for i in range(0, len(value), _ARMOR_LINE_WIDTH))


def _canonical_activation_request_json(
    *,
    app_id: str,
    hwid: str,
    created_at: str,
    machine_name: Optional[str] = None,
    os_name: Optional[str] = None,
    sdk: Optional[str] = None,
    license_key: Optional[str] = None,
) -> str:
    parts = [
        f'"v":{_ACTIVATION_REQUEST_VERSION}',
        f'"typ":{_json_escape_request(_ACTIVATION_REQUEST_TYP)}',
        f'"appId":{_json_escape_request(app_id)}',
        f'"hwid":{_json_escape_request(_clip_request_field(hwid, _MAX_REQUEST_HWID))}',
        f'"createdAt":{_json_escape_request(created_at)}',
    ]
    if machine_name:
        parts.append(
            f'"machineName":{_json_escape_request(_clip_request_field(machine_name, _MAX_REQUEST_MACHINE_NAME))}'
        )
    if os_name:
        parts.append(f'"os":{_json_escape_request(_clip_request_field(os_name, _MAX_REQUEST_OS))}')
    if sdk:
        parts.append(f'"sdk":{_json_escape_request(_clip_request_field(sdk, _MAX_REQUEST_SDK))}')
    if license_key:
        parts.append(
            f'"licenseKey":{_json_escape_request(_clip_request_field(license_key, _MAX_REQUEST_LICENSE_KEY))}'
        )
    return "{" + ",".join(parts) + "}"


def _utc_iso_ms(value: Optional[datetime] = None) -> str:
    now = value or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(now.microsecond / 1000):03d}Z"


def _detect_os_label() -> str:
    system = platform.system()
    release = platform.release()
    if system == "Darwin":
        mac = platform.mac_ver()[0]
        label = f"macOS {mac or release}"
    elif system == "Windows":
        label = f"Windows {release}"
    elif system == "Linux":
        label = f"Linux {release}"
    else:
        label = f"{system} {release}".strip()
    return _clip_request_field(label, _MAX_REQUEST_OS)


def format_activation_request(
    *,
    app_id: str,
    hwid: str,
    created_at: str,
    machine_name: Optional[str] = None,
    os: Optional[str] = None,
    sdk: Optional[str] = None,
    license_key: Optional[str] = None,
) -> str:
    """Armored ``.authforge-request`` text from explicit fields."""
    json_body = _canonical_activation_request_json(
        app_id=app_id,
        hwid=hwid,
        created_at=created_at,
        machine_name=machine_name,
        os_name=os,
        sdk=sdk,
        license_key=license_key,
    )
    payload_b64 = base64.b64encode(json_body.encode("utf-8")).decode("ascii")
    checksum = hashlib.sha256(payload_b64.encode("utf-8")).hexdigest()[:16]
    clean_app = app_id.replace("\r", " ").replace("\n", " ").strip()
    return "\n".join(
        [
            _BEGIN_ACTIVATION_REQUEST,
            f"Version: {_ACTIVATION_REQUEST_VERSION}",
            f"App-Id: {clean_app}",
            f"Checksum: {checksum}",
            "",
            _wrap_armor_64(payload_b64),
            _END_ACTIVATION_REQUEST,
            "",
        ]
    )


def parse_license_file(text: str) -> Optional[ParsedLicenseFile]:
    """Parse armored ``.authforge`` text.

    Returns ``None`` when the armor is malformed. Tolerates CRLF, a UTF-8 BOM,
    any re-wrapping of the base64 body and text before/after the armor.
    ``payload_base64`` is exactly the string the signature covers.
    """
    if not isinstance(text, str):
        return None
    normalized = text.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")

    def _find(marker: str, start: int) -> int:
        for i in range(start, len(lines)):
            if lines[i].strip() == marker:
                return i
        return -1

    begin_idx = _find(_OFFLINE_BEGIN_LICENSE, 0)
    if begin_idx == -1:
        return None
    end_idx = _find(_OFFLINE_END_LICENSE, begin_idx + 1)
    if end_idx == -1:
        return None
    sig_begin_idx = _find(_OFFLINE_BEGIN_SIGNATURE, end_idx + 1)
    if sig_begin_idx == -1:
        return None
    sig_end_idx = _find(_OFFLINE_END_SIGNATURE, sig_begin_idx + 1)
    if sig_end_idx == -1:
        return None

    block = lines[begin_idx + 1 : end_idx]
    blank_idx = -1
    for i, line in enumerate(block):
        if line.strip() == "":
            blank_idx = i
            break
    if blank_idx == -1:
        return None

    headers: Dict[str, str] = {}
    for raw in block[:blank_idx]:
        line = raw.strip()
        colon = line.find(":")
        if colon <= 0:
            return None
        headers[line[:colon].strip()] = line[colon + 1 :].strip()

    payload_base64 = re.sub(r"\s+", "", "".join(block[blank_idx + 1 :]))
    signature_base64 = re.sub(r"\s+", "", "".join(lines[sig_begin_idx + 1 : sig_end_idx]))
    if not payload_base64 or not _OFFLINE_BASE64_RE.match(payload_base64):
        return None
    if not signature_base64 or not _OFFLINE_BASE64_RE.match(signature_base64):
        return None
    return {
        "headers": headers,
        "payload_base64": payload_base64,
        "signature_base64": signature_base64,
    }


def _parse_iso8601_ms(value: str) -> Optional[float]:
    """ISO-8601 -> epoch milliseconds (UTC). Returns None when unparseable."""
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp() * 1000.0


def _offline_payload_shape_ok(payload: Dict[str, Any]) -> bool:
    if payload.get("typ") != "authforge-license":
        return False
    for field in ("appId", "licenseKey", "jti", "kid", "issuedAt"):
        value = payload.get(field)
        if not isinstance(value, str) or not value:
            return False
    # `expiresAt` must be present: an explicit null means lifetime, absence is
    # a malformed document (never emitted by the cloud minter).
    if "expiresAt" not in payload:
        return False
    expires_at = payload["expiresAt"]
    if expires_at is not None and (not isinstance(expires_at, str) or not expires_at):
        return False
    hwid = payload.get("hwid")
    if not isinstance(hwid, dict):
        return False
    mode = hwid.get("mode")
    if mode == "bound":
        hwids = hwid.get("hwids")
        if not isinstance(hwids, list) or not hwids:
            return False
        if not all(isinstance(h, str) and h for h in hwids):
            return False
    elif mode != "any":
        return False
    return True


def verify_license_file(
    file: str,
    app_id: str,
    public_key: PublicKeyArg,
    hwid: Optional[str] = None,
    *,
    now: Optional[Union[datetime, float, int]] = None,
) -> VerifyLicenseFileResult:
    """Verify an offline ``.authforge`` license file with NO network access.

    Check order (fixed across every SDK): ``bad_armor`` -> ``bad_signature`` ->
    ``unsupported_version`` -> ``malformed_payload`` -> ``wrong_app`` ->
    ``expired`` -> ``hwid_mismatch``. The signature is verified before the
    payload JSON is decoded so a forged file never reaches the parser.

    ``file`` is the armored text. ``public_key`` accepts the same forms as the
    client constructor (single key, list, or comma-separated). ``now`` may be a
    ``datetime`` or epoch seconds (tests).
    """
    parsed = parse_license_file(file)
    if parsed is None:
        return {"ok": False, "error": "bad_armor"}

    keys = AuthForgeClient._normalize_public_key_list(public_key)
    if not _verify_offline_signature(parsed["payload_base64"], parsed["signature_base64"], keys):
        return {"ok": False, "error": "bad_signature"}

    try:
        payload = json.loads(base64.b64decode(parsed["payload_base64"]).decode("utf-8"))
    except Exception:
        return {"ok": False, "error": "malformed_payload"}
    if not isinstance(payload, dict):
        return {"ok": False, "error": "malformed_payload"}
    version = payload.get("v")
    # ``True == 1`` in Python, so the bool check is required for parity with the
    # other SDKs, which all demand a JSON number here.
    if isinstance(version, bool) or version != OFFLINE_LICENSE_FILE_VERSION:
        return {"ok": False, "error": "unsupported_version"}
    if not _offline_payload_shape_ok(payload):
        return {"ok": False, "error": "malformed_payload"}

    if payload["appId"] != app_id:
        return {"ok": False, "error": "wrong_app"}

    if isinstance(now, datetime):
        now_ms = now.timestamp() * 1000.0
    elif isinstance(now, (int, float)):
        now_ms = float(now) * 1000.0
    else:
        now_ms = time.time() * 1000.0
    expires_at = payload["expiresAt"]
    if expires_at is not None:
        exp_ms = _parse_iso8601_ms(expires_at)
        if exp_ms is None or exp_ms <= now_ms:
            return {"ok": False, "error": "expired"}

    hwid_policy = payload["hwid"]
    if hwid_policy["mode"] == "bound":
        local = hwid.strip() if isinstance(hwid, str) else ""
        if not local or local not in hwid_policy["hwids"]:
            return {"ok": False, "error": "hwid_mismatch"}

    license_info: OfflineLicense = {
        "app_id": payload["appId"],
        "license_key": payload["licenseKey"],
        "jti": payload["jti"],
        "key_id": payload["kid"],
        "issued_at": payload["issuedAt"],
        "expires_at": expires_at,
        "hwid_policy": (
            {"mode": "bound", "hwids": list(hwid_policy["hwids"])}
            if hwid_policy["mode"] == "bound"
            else {"mode": "any"}
        ),
        "license_variables": dict(payload["licenseVariables"])
        if isinstance(payload.get("licenseVariables"), dict)
        else None,
        "app_variables": dict(payload["appVariables"])
        if isinstance(payload.get("appVariables"), dict)
        else None,
        "payload": dict(payload),
    }
    if isinstance(payload.get("label"), str):
        license_info["label"] = payload["label"]
    if "licenseExpiresAt" in payload:
        le = payload["licenseExpiresAt"]
        license_info["license_expires_at"] = le if isinstance(le, str) else None
    return {
        "ok": True,
        "license": license_info,
        "payload_base64": parsed["payload_base64"],
        "signature_base64": parsed["signature_base64"],
    }


def _verify_offline_signature(payload_base64: str, signature_base64: str, keys: Sequence[str]) -> bool:
    try:
        signature_bytes = base64.b64decode(signature_base64, validate=True)
    except Exception:
        return False
    if len(signature_bytes) != 64:
        return False
    message = payload_base64.encode("utf-8")
    for key_b64 in keys:
        try:
            raw = base64.b64decode(key_b64, validate=True)
            if len(raw) != 32:
                continue
            Ed25519PublicKey.from_public_bytes(raw).verify(signature_bytes, message)
            return True
        except Exception:
            continue
    return False


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
    "malformed_request",
    "system_error",
}


class AuthForgeClient:
    def __init__(
        self,
        app_id: str,
        app_secret: Optional[str],
        public_key: PublicKeyArg,
        heartbeat_mode: Optional[str] = None,
        heartbeat_interval: int = 900,
        api_base_url: str = DEFAULT_API_BASE_URL,
        on_failure: Optional[Callable[[str, Optional[Exception]], None]] = None,
        request_timeout: int = 15,
        ttl_seconds: Optional[int] = None,
        hwid_override: Optional[str] = None,
        *,
        online_heartbeat: bool = False,
    ) -> None:
        if not app_id or not isinstance(app_id, str):
            raise ValueError("app_id must be a non-empty string")
        # Empty/None is valid for offline-only clients (login_from_file).
        # Online APIs (login, validate_license, self_ban) still require a secret.
        if app_secret is None:
            app_secret = ""
        elif not isinstance(app_secret, str):
            raise ValueError("app_secret must be a string or None")
        public_key_list = self._normalize_public_key_list(public_key)
        if not public_key_list:
            raise ValueError(
                "public_key must be a non-empty base64 string or list of base64 strings"
            )
        # heartbeat_mode is a deprecated shim. By default the client runs on
        # the grace period: after a successful activate/validate, the signed
        # session keeps the app running without contacting AuthForge until
        # the session TTL expires. Online check-ins (periodic
        # /auth/heartbeat calls) are opt-in via online_heartbeat=True.
        mode: Optional[str] = None
        if heartbeat_mode:
            mode = heartbeat_mode.upper()
            if mode not in {"LOCAL", "SERVER"}:
                raise ValueError("heartbeat_mode must be LOCAL or SERVER")
            warnings.warn(
                "heartbeat_mode is deprecated: use online_heartbeat=True for "
                "online check-ins; the default is the grace period behavior",
                DeprecationWarning,
                stacklevel=2,
            )
        if heartbeat_interval < 10:
            raise ValueError("heartbeat_interval must be >= 10")

        self.app_id = app_id
        self.app_secret = app_secret
        # `public_key` is the historical public attribute. We now hold the
        # full trust list to support key rotation, but expose the first entry
        # as `public_key` for callers that read it directly.
        self.public_keys: List[str] = public_key_list
        self.public_key = public_key_list[0]
        # Effective policy: online check-ins are enabled either explicitly or
        # via the legacy heartbeat_mode="SERVER" shim.
        self.online_heartbeat: bool = bool(online_heartbeat) or mode == "SERVER"
        # Back-compat attribute for callers that still read heartbeat_mode.
        self.heartbeat_mode = "SERVER" if self.online_heartbeat else "LOCAL"
        self.heartbeat_interval = int(heartbeat_interval)
        self.api_base_url = api_base_url.rstrip("/")
        self.on_failure = on_failure
        self.request_timeout = request_timeout
        # ttl_seconds is the grace period duration knob: how long the app
        # keeps running on the signed session without contacting AuthForge.
        # None / 0 / negative means "let the server pick its default (24h)".
        # The server clamps requested values to [3600, 604800] (1h to 7d);
        # we don't duplicate the clamp here.
        self.ttl_seconds: Optional[int] = (
            int(ttl_seconds) if isinstance(ttl_seconds, int) and ttl_seconds > 0 else None
        )

        self._lock = threading.Lock()
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._heartbeat_started = False
        self._heartbeat_stop = threading.Event()

        self._license_key: Optional[str] = None
        self._session_token: Optional[str] = None
        # "online" after login()/validate, "offline" after login_from_file(),
        # None when logged out. Drives is_authenticated(), self_ban() and the
        # heartbeat guard so the two modes can never be confused.
        self._session_kind: Optional[SessionKind] = None
        self._session_expires_in: Optional[int] = None
        self._last_nonce: Optional[str] = None
        self._raw_payload_b64: Optional[str] = None
        self._signature: Optional[str] = None
        self._key_id: Optional[str] = None
        self._session_data: Optional[Dict[str, Any]] = None
        self._app_variables: Optional[Dict[str, Any]] = None
        self._license_variables: Optional[Dict[str, Any]] = None
        self._authenticated = False
        self._offline_license: Optional[Dict[str, Any]] = None
        self._hwid = self._resolve_hwid(hwid_override)
        self._ed25519_public_keys: List[Ed25519PublicKey] = [
            self._load_public_key(k) for k in public_key_list
        ]

    def get_hwid(self) -> str:
        """The HWID this client sends to AuthForge (or ``hwid_override``).

        Customers on air-gapped machines report this value to the operator so
        an offline ``.authforge`` file can be bound to it.
        """
        return self._hwid

    def create_activation_request(
        self,
        *,
        include_machine_name: bool = False,
        machine_name: Optional[str] = None,
        os: Optional[str] = None,
        omit_os: bool = False,
        sdk: Optional[str] = None,
        omit_sdk: bool = False,
        license_key: Optional[str] = None,
        created_at: Optional[str] = None,
    ) -> str:
        """Build an activation request (``.authforge-request``) for this machine.

        No network, no session, no app secret. The HWID is the same value
        :meth:`login` / :meth:`login_from_file` use. ``machine_name`` is omitted
        unless ``include_machine_name`` is true (hostnames are often a person's
        name).
        """
        created = created_at if created_at else _utc_iso_ms()
        name: Optional[str] = None
        if include_machine_name:
            name = machine_name or platform.node() or socket.gethostname()
        os_name: Optional[str] = None if omit_os else (os if os is not None else _detect_os_label())
        sdk_tag: Optional[str] = None if omit_sdk else (sdk if sdk is not None else _SDK_TAG)
        key = license_key if license_key is not None else self._license_key
        return format_activation_request(
            app_id=self.app_id,
            hwid=self._hwid,
            created_at=created,
            machine_name=name,
            os=os_name,
            sdk=sdk_tag,
            license_key=key,
        )

    def write_activation_request(self, path: str, **kwargs: Any) -> None:
        """Write an activation request to ``path`` (UTF-8). Same kwargs as
        :meth:`create_activation_request`."""
        text = self.create_activation_request(**kwargs)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)

    def login_from_file(self, path_or_text: str) -> bool:
        """Authorize from a cloud-minted offline license file (``.authforge``)
        with NO network access. Accepts a filesystem path or the armored text.

        On success the client is authenticated (:meth:`is_authenticated`,
        :meth:`get_session_data`, :meth:`get_app_variables`,
        :meth:`get_license_variables` work) and :meth:`get_offline_license`
        describes the file. No grace-period thread and no online check-ins are
        started - the file's own ``expiresAt`` is the only clock. Online
        :meth:`login` is untouched.

        Failures are reported through ``on_failure("offline_login_failed", exc)``
        and return ``False``; unlike :meth:`login` this never calls
        ``os._exit`` - an unreadable file should not kill an air-gapped
        process without a chance to show the user why.
        """
        try:
            text = self._read_license_file_input(path_or_text)
        except Exception as exc:
            self._fail_soft("offline_login_failed", exc)
            return False
        result = verify_license_file(text, self.app_id, self.public_keys, self._hwid)
        if not result["ok"]:
            self._fail_soft("offline_login_failed", ValueError(result["error"]))
            return False
        self._apply_offline_license(result)
        return True

    def verify_license_file(
        self,
        path_or_text: str,
        *,
        now: Optional[Union[datetime, float, int]] = None,
    ) -> VerifyLicenseFileResult:
        """Verify a ``.authforge`` file with this client's app id, public
        key(s) and HWID without touching session state. Never raises for bad
        input."""
        try:
            text = self._read_license_file_input(path_or_text)
        except Exception as exc:
            return {"ok": False, "error": f"read_error: {exc}"}
        return verify_license_file(text, self.app_id, self.public_keys, self._hwid, now=now)

    def get_offline_license(self) -> Optional[Dict[str, Any]]:
        """Details of the offline file the client authenticated with, or ``None``."""
        with self._lock:
            return dict(self._offline_license) if self._offline_license is not None else None

    @staticmethod
    def _read_license_file_input(path_or_text: str) -> str:
        if not isinstance(path_or_text, str) or not path_or_text:
            raise ValueError("license file must be a path or the armored text")
        if _OFFLINE_BEGIN_LICENSE in path_or_text:
            return path_or_text
        with open(path_or_text, "r", encoding="utf-8") as handle:
            return handle.read()

    def _apply_offline_license(self, result: VerifyLicenseFileSuccess) -> None:
        # Stop any online session first so the two modes never overlap.
        self.logout()
        lic = result["license"]
        expires_at = lic["expires_at"]
        expires_ms = _parse_iso8601_ms(expires_at) if isinstance(expires_at, str) else None
        with self._lock:
            self._license_key = lic["license_key"]
            # Offline files carry no server session token. The explicit session
            # kind (not a token sentinel) is what makes is_authenticated() true
            # and keeps self_ban()/heartbeats from ever contacting the server.
            self._session_token = None
            self._session_kind = "offline"
            self._session_expires_in = int(expires_ms / 1000) if expires_ms is not None else None
            self._raw_payload_b64 = result["payload_base64"]
            self._signature = result["signature_base64"]
            self._key_id = lic["key_id"]
            self._session_data = dict(lic["payload"])
            self._app_variables = lic["app_variables"]
            self._license_variables = lic["license_variables"]
            summary: Dict[str, Any] = {
                "license_key": lic["license_key"],
                "jti": lic["jti"],
                "key_id": lic["key_id"],
                "issued_at": lic["issued_at"],
                "expires_at": expires_at,
                "hwid_policy": lic["hwid_policy"],
            }
            if "label" in lic:
                summary["label"] = lic["label"]
            if "license_expires_at" in lic:
                summary["license_expires_at"] = lic["license_expires_at"]
            self._offline_license = summary
            self._authenticated = True

    def _fail_soft(self, reason: str, exc: Optional[Exception]) -> None:
        if self.on_failure is not None:
            try:
                self.on_failure(reason, exc)
            except Exception:
                pass

    def _require_app_secret(self) -> None:
        if not self.app_secret:
            raise ValueError(
                "app_secret is required for online APIs; omit it only when using login_from_file"
            )

    def login(self, license_key: str) -> bool:
        if not license_key or not isinstance(license_key, str):
            raise ValueError("license_key must be a non-empty string")
        self._require_app_secret()

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
        self._require_app_secret()
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
            result: ValidateLicenseSuccess = {
                "valid": True,
                "session_token": parsed["session_token"],
                "expires_in": parsed["expires_in"],
                "session_data": parsed["session_data"],
                "app_variables": parsed["app_variables"],
                "license_variables": parsed["license_variables"],
                "key_id": parsed["key_id"],
            }
            if "session_expires_at" in parsed:
                result["session_expires_at"] = parsed["session_expires_at"]
            if "license_expires_at" in parsed:
                result["license_expires_at"] = parsed["license_expires_at"]
            if "max_hwid_slots" in parsed:
                result["max_hwid_slots"] = parsed["max_hwid_slots"]
            if "hwid_count" in parsed:
                result["hwid_count"] = parsed["hwid_count"]
            if "license_label" in parsed:
                result["license_label"] = parsed["license_label"]
            return result
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
        explicit_license = (
            license_key.strip()
            if isinstance(license_key, str) and license_key.strip()
            else None
        )
        with self._lock:
            current_session = self._session_token
            current_license = self._license_key
            current_kind = self._session_kind
            hwid = self._hwid

        # An offline session has no server session and must never phone home
        # on its own. Callers who pass an explicit license_key/session_token
        # are asking about a *different* credential and get the normal paths.
        if current_kind == "offline" and resolved_session is None and explicit_license is None:
            raise ValueError("offline_session")

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

        resolved_license = explicit_license or current_license
        if not resolved_license:
            raise ValueError("missing_license_key")
        self._require_app_secret()

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
            # Offline sessions have no grace period and no online check-ins:
            # the file's own expires_at is the only clock. Never start a thread.
            if self._heartbeat_started or self._session_kind == "offline":
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
            with self._lock:
                offline = self._session_kind == "offline"
            if offline:
                return
            try:
                if self.online_heartbeat:
                    self._server_heartbeat()
                else:
                    self._grace_period_check()
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

    def _grace_period_check(self) -> None:
        # Grace period enforcement: no network calls. Re-verify the stored
        # signed session payload and fail once the session TTL has expired.
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

        out: Dict[str, Any] = {
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
        se = payload_json.get("sessionExpiresAt")
        if isinstance(se, str) and se != "":
            out["session_expires_at"] = se
        if "licenseExpiresAt" in payload_json:
            le = payload_json["licenseExpiresAt"]
            out["license_expires_at"] = le if isinstance(le, str) else None
        if "maxHwidSlots" in payload_json:
            try:
                out["max_hwid_slots"] = int(payload_json["maxHwidSlots"])
            except (TypeError, ValueError):
                pass
        if "hwidCount" in payload_json:
            try:
                out["hwid_count"] = int(payload_json["hwidCount"])
            except (TypeError, ValueError):
                pass
        ll = payload_json.get("licenseLabel")
        if isinstance(ll, str) and ll != "":
            out["license_label"] = ll
        return out

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
            self._session_kind = "online"
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
            self._session_kind = None
            self._session_expires_in = None
            self._last_nonce = None
            self._raw_payload_b64 = None
            self._signature = None
            self._key_id = None
            self._session_data = None
            self._app_variables = None
            self._license_variables = None
            self._authenticated = False
            self._offline_license = None
            self._heartbeat_started = False
            self._heartbeat_thread = None

    def is_authenticated(self) -> bool:
        """True for an online session (:meth:`login`) or an offline one
        (:meth:`login_from_file`)."""
        with self._lock:
            if not self._authenticated:
                return False
            if self._session_kind == "online":
                return bool(self._session_token)
            return self._session_kind == "offline"

    def get_session_kind(self) -> Optional[SessionKind]:
        """``"online"`` after :meth:`login`, ``"offline"`` after
        :meth:`login_from_file`, ``None`` when logged out."""
        with self._lock:
            return self._session_kind

    def get_session_data(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return dict(self._session_data) if self._session_data is not None else None

    def get_app_variables(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return dict(self._app_variables) if self._app_variables is not None else None

    def get_license_variables(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return dict(self._license_variables) if self._license_variables is not None else None
