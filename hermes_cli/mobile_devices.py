"""Host-approved mobile device enrollment and proof verification.

The mobile listener deliberately keeps this state separate from the dashboard
authentication code.  A device is enrolled with two public P-256 keys: the
background key used for ordinary request proofs and a separate user-presence
key reserved for future step-up operations.  The host owns the enrollment,
approval, profile, and scope decisions; the client never gets to widen them.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import posixpath
import re
import secrets
import sqlite3
import threading
import time
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import jwt

from hermes_constants import get_hermes_home


ENROLLMENT_CODE_TTL_SECONDS = 300
DEVICE_TOKEN_TTL_SECONDS = 300
DPOP_MAX_AGE_SECONDS = 300
DPOP_CLOCK_SKEW_SECONDS = 30
TOKEN_CHALLENGE_TTL_SECONDS = 60
DEVICE_SCOPES = frozenset(
    {
        "chat",
        "groups",
        "attachments",
        "settings:read",
        "settings:write:safe",
        "approvals",
        "routines:control",
    }
)

_PUBLIC_JWK_KEYS = ("crv", "kty", "x", "y")
_PRIVATE_JWK_KEYS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"})
_ALLOWLIST_ITEM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,256}$")
_JTI_RE = re.compile(r"^[\x21-\x7e]{1,256}$")
_DPOP_NONCE_RE = re.compile(r"^[\x21-\x7e]{16,256}$")


class MobileDeviceError(Exception):
    """Base class for fail-closed device trust errors."""


class InvalidEnrollment(MobileDeviceError, ValueError):
    """The enrollment request or code is malformed or unusable."""


class DeviceNotAuthorized(MobileDeviceError, PermissionError):
    """The device is missing, pending, revoked, or outside its allowlist."""


class InvalidDeviceToken(DeviceNotAuthorized):
    """The device token is malformed, expired, or no longer trusted."""


class InvalidDpopProof(MobileDeviceError, ValueError):
    """The DPoP proof is invalid, stale, mismatched, or replayed."""


class DpopReplay(InvalidDpopProof):
    """The DPoP proof's JTI has already been accepted."""


@dataclass(frozen=True)
class EnrollmentChallenge:
    """One short-lived, single-use enrollment code.

    ``code`` is intentionally excluded from ``repr`` and equality because it
    is bearer material.  Callers should deliver it directly to the intended
    device and never log the object wholesale.
    """

    device_id: str
    code: str = field(repr=False, compare=False)
    expires_at: float
    background_jkt: str
    user_jkt: str

    def __str__(self) -> str:
        return "[redacted enrollment code]"


EnrollmentCode = EnrollmentChallenge


@dataclass(frozen=True)
class TokenChallenge:
    device_id: str
    nonce: str = field(repr=False, compare=False)
    expires_at: float

    def __str__(self) -> str:
        return "[redacted token challenge]"


@dataclass(frozen=True)
class DeviceRecord:
    """Public, non-secret view of one enrolled device."""

    device_id: str
    status: str
    background_jwk: dict[str, str]
    user_jwk: dict[str, str]
    background_jkt: str
    user_jkt: str
    profile_allowlist: tuple[str, ...]
    scope_allowlist: tuple[str, ...]
    created_at: float
    approved_at: float | None
    revoked_at: float | None
    device_label: str = ""
    access_subject: str = ""
    access_email: str = ""
    push_handle: str = ""

    @property
    def profiles(self) -> tuple[str, ...]:
        return self.profile_allowlist

    @property
    def scopes(self) -> tuple[str, ...]:
        return self.scope_allowlist

    @property
    def approved(self) -> bool:
        return self.status == "approved"

    @property
    def revoked(self) -> bool:
        return self.status == "revoked"


@dataclass(frozen=True)
class DeviceAuthorization:
    """The result of authenticating one mobile request."""

    device_id: str
    profile: str | None
    scope: str | None
    token_claims: dict[str, Any]
    dpop_claims: dict[str, Any]


def _b64u_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64u_decode(value: Any, *, expected_length: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValueError("invalid public key encoding")
    if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", value):
        raise ValueError("invalid public key encoding")
    if "=" in value[:-2]:
        raise ValueError("invalid public key encoding")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("invalid public key encoding") from exc
    if len(decoded) != expected_length:
        raise ValueError("invalid public key encoding")
    return decoded


def _b64u_decode_variable(value: Any, *, maximum_length: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum_length * 2:
        raise ValueError("invalid signature encoding")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("invalid signature encoding")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("invalid signature encoding") from exc
    if not decoded or len(decoded) > maximum_length:
        raise ValueError("invalid signature encoding")
    return decoded


def token_challenge_message(device_id: str, nonce: str) -> bytes:
    """Canonical bytes the background key signs to mint or refresh a token."""

    if not isinstance(device_id, str) or not _OPAQUE_ID_RE.fullmatch(device_id):
        raise ValueError("invalid device identity")
    if not isinstance(nonce, str) or not 16 <= len(nonce) <= 512:
        raise ValueError("invalid token challenge")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", nonce):
        raise ValueError("invalid token challenge")
    return b"hermes-mobile-token-v1\x00" + device_id.encode("ascii") + b"\x00" + nonce.encode("ascii")


def validate_public_jwk(jwk: Mapping[str, Any]) -> dict[str, str]:
    """Validate and canonicalize a public EC P-256 JWK.

    Private members are rejected rather than silently discarded.  Keeping the
    returned representation to the four RFC 7638 thumbprint members also
    prevents metadata from changing the key identity.
    """

    if not isinstance(jwk, Mapping):
        raise ValueError("public JWK must be an object")
    if any(not isinstance(key, str) for key in jwk):
        raise ValueError("public JWK has invalid members")
    if _PRIVATE_JWK_KEYS.intersection(jwk):
        raise ValueError("private JWK material is not accepted")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("public JWK must be an EC P-256 key")

    x_raw = _b64u_decode(jwk.get("x"), expected_length=32)
    y_raw = _b64u_decode(jwk.get("y"), expected_length=32)
    try:
        ec.EllipticCurvePublicNumbers(
            int.from_bytes(x_raw, "big"),
            int.from_bytes(y_raw, "big"),
            ec.SECP256R1(),
        ).public_key()
    except (ValueError, TypeError) as exc:
        raise ValueError("public JWK point is invalid") from exc

    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64u_encode(x_raw),
        "y": _b64u_encode(y_raw),
    }


def public_jwk_from_key(key: ec.EllipticCurvePublicKey | ec.EllipticCurvePrivateKey) -> dict[str, str]:
    """Return the canonical public JWK for a P-256 key."""

    if isinstance(key, ec.EllipticCurvePrivateKey):
        key = key.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("key must be an EC P-256 public key")
    numbers = key.public_numbers()
    return validate_public_jwk(
        {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64u_encode(numbers.x.to_bytes(32, "big")),
            "y": _b64u_encode(numbers.y.to_bytes(32, "big")),
        }
    )


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """Return an RFC 7638 SHA-256 thumbprint for a public P-256 JWK."""

    canonical = validate_public_jwk(jwk)
    payload = json.dumps(
        {key: canonical[key] for key in _PUBLIC_JWK_KEYS},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _b64u_encode(hashlib.sha256(payload).digest())


def _public_key_from_jwk(jwk: Mapping[str, Any]) -> ec.EllipticCurvePublicKey:
    canonical = validate_public_jwk(jwk)
    x = int.from_bytes(_b64u_decode(canonical["x"], expected_length=32), "big")
    y = int.from_bytes(_b64u_decode(canonical["y"], expected_length=32), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def normalize_dpop_url(url: str) -> str:
    """Normalize an HTTP(S) URL for DPoP's ``htu`` comparison.

    Query strings and fragments are not part of DPoP ``htu``.  Scheme and host
    are case-folded, default ports are removed, and dot segments are removed.
    """

    if not isinstance(url, str) or not url or len(url) > 4096:
        raise ValueError("invalid DPoP URL")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in url):
        raise ValueError("invalid DPoP URL")
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid DPoP URL") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        raise ValueError("invalid DPoP URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("invalid DPoP URL")

    scheme = parsed.scheme.lower()
    try:
        host = hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ValueError("invalid DPoP URL") from exc
    if not host:
        raise ValueError("invalid DPoP URL")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    default_port = 80 if scheme == "http" else 443
    port_part = "" if port is None or port == default_port else f":{port}"

    path = parsed.path or "/"
    path = posixpath.normpath(path)
    if not path.startswith("/"):
        path = "/" + path
    if parsed.path.endswith("/") and not path.endswith("/"):
        path += "/"
    if path == "/.":
        path = "/"
    while path.startswith("//"):
        path = path[1:]
    return f"{scheme}://{host}{port_part}{path}"


normalize_dpop_htu = normalize_dpop_url


def _validate_allowlist(values: Iterable[str] | str | None, *, field_name: str) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        values = (values,)
    if isinstance(values, Mapping):
        raise ValueError(f"{field_name} must be a sequence")
    try:
        items = list(values)
    except TypeError as exc:
        raise ValueError(f"{field_name} must be a sequence") from exc
    result: set[str] = set()
    for item in items:
        if not isinstance(item, str) or not _ALLOWLIST_ITEM_RE.fullmatch(item):
            raise ValueError(f"invalid {field_name} item")
        result.add(item)
    return tuple(sorted(result))


def _safe_claim_string(value: Any, *, field_name: str, max_length: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise ValueError(f"invalid {field_name}")
    if any(ord(char) < 0x21 or ord(char) > 0x7E for char in value):
        raise ValueError(f"invalid {field_name}")
    return value


def _safe_time(value: float | int | None, clock: Callable[[], float]) -> float:
    result = float(clock() if value is None else value)
    if not math.isfinite(result):
        raise ValueError("invalid timestamp")
    return result


def _ttl(value: float | int, *, maximum: int, field_name: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {field_name}") from exc
    if not math.isfinite(result) or result <= 0 or result > maximum:
        raise ValueError(f"invalid {field_name}")
    return result


def _json_allowlist(values: tuple[str, ...]) -> str:
    return json.dumps(list(values), separators=(",", ":"))


def _parse_allowlist(value: Any, *, field_name: str) -> tuple[str, ...]:
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise MobileDeviceError("device record unavailable") from exc
    return _validate_allowlist(parsed, field_name=field_name)


def _coerce_private_signing_key(
    key: ec.EllipticCurvePrivateKey | bytes | None,
) -> ec.EllipticCurvePrivateKey:
    if key is None:
        return ec.generate_private_key(ec.SECP256R1())
    if isinstance(key, bytes):
        try:
            loaded = serialization.load_pem_private_key(key, password=None)
        except (ValueError, TypeError) as exc:
            raise ValueError("invalid device token signing key") from exc
        key = loaded
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("device token signing key must be EC P-256")
    return key


class MobileDeviceStore:
    """SQLite-backed host approval and device-proof store.

    ``db_path`` is injectable for tests and deployments.  If omitted, the
    canonical ``get_hermes_home()`` location is used.  Token signing material
    is intentionally injected (or generated for the process); callers that
    need tokens to survive a process restart must persist and re-inject the
    private key through their deployment's protected secret store.
    """

    def __init__(
        self,
        db_path: str | Path | None = None,
        *,
        path: str | Path | None = None,
        hermes_home: str | Path | None = None,
        token_signing_key: ec.EllipticCurvePrivateKey | bytes | None = None,
        token_issuer: str = "hermes-mobile",
        token_audience: str = "hermes-mobile",
        profile_allowlist: Iterable[str] | str | None = None,
        scope_allowlist: Iterable[str] | str | None = None,
        allowed_profiles: Iterable[str] | str | None = None,
        allowed_scopes: Iterable[str] | str | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if db_path is not None and path is not None:
            raise ValueError("provide only one database path")
        db_path = path if db_path is None else db_path
        if db_path is None:
            root = Path(hermes_home) if hermes_home is not None else Path(get_hermes_home())
            db_path = root / "mobile-devices.sqlite3"
        self.db_path = str(db_path) if str(db_path) == ":memory:" else Path(db_path).expanduser()

        if profile_allowlist is not None and allowed_profiles is not None:
            raise ValueError("provide only one profile allowlist")
        if scope_allowlist is not None and allowed_scopes is not None:
            raise ValueError("provide only one scope allowlist")
        profile_allowlist = profile_allowlist if profile_allowlist is not None else allowed_profiles
        scope_allowlist = scope_allowlist if scope_allowlist is not None else allowed_scopes
        self._profile_allowlist = (
            None
            if profile_allowlist is None
            else frozenset(_validate_allowlist(profile_allowlist, field_name="profile allowlist"))
        )
        self._scope_allowlist = (
            None
            if scope_allowlist is None
            else frozenset(_validate_allowlist(scope_allowlist, field_name="scope allowlist"))
        )
        if self._scope_allowlist is not None and not self._scope_allowlist <= DEVICE_SCOPES:
            raise ValueError("scope allowlist contains an unsupported mobile scope")
        self._clock = clock or time.time
        self._token_issuer = _safe_claim_string(token_issuer, field_name="token issuer")
        self._token_audience = _safe_claim_string(token_audience, field_name="token audience")
        self._token_signing_key = _coerce_private_signing_key(token_signing_key)
        self._lock = threading.RLock()
        self._closed = False

        if isinstance(self.db_path, Path):
            if self.db_path.exists() and self.db_path.is_dir():
                raise ValueError("mobile device database path is a directory")
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            connect_path: str = str(self.db_path)
        else:
            connect_path = self.db_path
        try:
            self._connection = sqlite3.connect(
                connect_path,
                timeout=5.0,
                isolation_level=None,
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._initialize_schema()
        except sqlite3.Error as exc:
            raise MobileDeviceError("mobile device store unavailable") from exc
        if isinstance(self.db_path, Path):
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass

    def _initialize_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS mobile_devices (
                device_id TEXT PRIMARY KEY,
                push_handle TEXT UNIQUE,
                device_label TEXT NOT NULL DEFAULT '',
                access_subject TEXT NOT NULL DEFAULT '',
                access_email TEXT NOT NULL DEFAULT '',
                background_jwk TEXT NOT NULL,
                user_jwk TEXT NOT NULL,
                background_jkt TEXT NOT NULL,
                user_jkt TEXT NOT NULL,
                profile_allowlist TEXT NOT NULL,
                scope_allowlist TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'revoked')),
                created_at REAL NOT NULL,
                approved_at REAL,
                revoked_at REAL
            );
            CREATE TABLE IF NOT EXISTS mobile_enrollment_codes (
                code_hash BLOB PRIMARY KEY,
                device_id TEXT NOT NULL REFERENCES mobile_devices(device_id),
                expires_at REAL NOT NULL,
                consumed_at REAL
            );
            CREATE TABLE IF NOT EXISTS mobile_dpop_replays (
                jti TEXT PRIMARY KEY,
                expires_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS mobile_dpop_replays_expiry
                ON mobile_dpop_replays (expires_at);
            CREATE TABLE IF NOT EXISTS mobile_token_challenges (
                nonce_hash BLOB PRIMARY KEY,
                device_id TEXT NOT NULL REFERENCES mobile_devices(device_id),
                expires_at REAL NOT NULL,
                consumed_at REAL
            );
            CREATE INDEX IF NOT EXISTS mobile_token_challenges_device
                ON mobile_token_challenges (device_id, expires_at);
            """
        )
        columns = {
            str(row["name"])
            for row in self._connection.execute("PRAGMA table_info(mobile_devices)")
        }
        if "device_label" not in columns:
            self._connection.execute(
                "ALTER TABLE mobile_devices ADD COLUMN device_label TEXT NOT NULL DEFAULT ''"
            )
        if "push_handle" not in columns:
            self._connection.execute("ALTER TABLE mobile_devices ADD COLUMN push_handle TEXT")
        rows = self._connection.execute(
            "SELECT device_id FROM mobile_devices WHERE push_handle IS NULL OR push_handle = ''"
        ).fetchall()
        for row in rows:
            self._connection.execute(
                "UPDATE mobile_devices SET push_handle = ? WHERE device_id = ?",
                (self._new_opaque_id(), row["device_id"]),
            )
        self._connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS mobile_devices_push_handle "
            "ON mobile_devices (push_handle)"
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise MobileDeviceError("mobile device store is closed")

    @contextmanager
    def _transaction(self):
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                yield self._connection
            except Exception:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> "MobileDeviceStore":
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()

    @property
    def token_verification_key(self) -> ec.EllipticCurvePublicKey:
        return self._token_signing_key.public_key()

    @property
    def token_signing_public_key(self) -> ec.EllipticCurvePublicKey:
        return self.token_verification_key

    def _now(self, value: float | int | None) -> float:
        return _safe_time(value, self._clock)

    def _resolve_allowlists(
        self,
        profiles: Iterable[str] | str | None,
        scopes: Iterable[str] | str | None,
        profile_allowlist: Iterable[str] | str | None,
        scope_allowlist: Iterable[str] | str | None,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        if profiles is not None and profile_allowlist is not None:
            raise ValueError("provide only one profile allowlist")
        if scopes is not None and scope_allowlist is not None:
            raise ValueError("provide only one scope allowlist")
        profiles = profiles if profiles is not None else profile_allowlist
        scopes = scopes if scopes is not None else scope_allowlist
        if profiles is None:
            profiles = self._profile_allowlist or ()
        if scopes is None:
            scopes = self._scope_allowlist or ()
        profile_values = _validate_allowlist(profiles, field_name="profile allowlist")
        scope_values = _validate_allowlist(scopes, field_name="scope allowlist")
        if self._profile_allowlist is not None and not set(profile_values) <= self._profile_allowlist:
            raise ValueError("profile allowlist exceeds server policy")
        if self._scope_allowlist is not None and not set(scope_values) <= self._scope_allowlist:
            raise ValueError("scope allowlist exceeds server policy")
        return profile_values, scope_values

    @staticmethod
    def _new_opaque_id() -> str:
        return secrets.token_urlsafe(18)

    @staticmethod
    def _new_enrollment_code() -> str:
        return secrets.token_urlsafe(32)

    @staticmethod
    def _code_hash(code: str) -> bytes:
        return hashlib.sha256(code.encode("utf-8")).digest()

    def create_enrollment_code(
        self,
        background_jwk: Mapping[str, Any] | None = None,
        user_jwk: Mapping[str, Any] | None = None,
        *,
        background_public_jwk: Mapping[str, Any] | None = None,
        user_public_jwk: Mapping[str, Any] | None = None,
        approval_jwk: Mapping[str, Any] | None = None,
        profiles: Iterable[str] | str | None = None,
        scopes: Iterable[str] | str | None = None,
        profile_allowlist: Iterable[str] | str | None = None,
        scope_allowlist: Iterable[str] | str | None = None,
        access_subject: str = "",
        access_email: str = "",
        device_label: str = "Mobile device",
        ttl_seconds: float | int = ENROLLMENT_CODE_TTL_SECONDS,
        now: float | int | None = None,
    ) -> EnrollmentChallenge:
        """Create a pending device and return its one-time enrollment code."""

        if background_jwk is None:
            background_jwk = background_public_jwk
        if user_jwk is None:
            user_jwk = user_public_jwk if user_public_jwk is not None else approval_jwk
        if background_jwk is None or user_jwk is None:
            raise InvalidEnrollment("both device public keys are required")
        background = validate_public_jwk(background_jwk)
        user = validate_public_jwk(user_jwk)
        background_jkt = jwk_thumbprint(background)
        user_jkt = jwk_thumbprint(user)
        if background_jkt == user_jkt:
            raise InvalidEnrollment("device keys must be distinct")
        profiles_tuple, scopes_tuple = self._resolve_allowlists(
            profiles, scopes, profile_allowlist, scope_allowlist
        )
        subject = "" if access_subject is None else access_subject
        email = "" if access_email is None else access_email
        label = "" if device_label is None else device_label.strip()
        if not isinstance(device_label, str) or not label or len(label) > 64 or any(ord(c) < 0x20 for c in label):
            raise ValueError("invalid device label")
        if not isinstance(subject, str) or len(subject) > 256 or any(ord(c) < 0x20 for c in subject):
            raise ValueError("invalid access subject")
        if not isinstance(email, str) or len(email) > 320 or any(ord(c) < 0x20 for c in email):
            raise ValueError("invalid access email")
        created_at = self._now(now)
        expires_at = created_at + _ttl(
            ttl_seconds, maximum=ENROLLMENT_CODE_TTL_SECONDS, field_name="enrollment TTL"
        )

        for _attempt in range(5):
            device_id = self._new_opaque_id()
            code = self._new_enrollment_code()
            try:
                with self._transaction() as connection:
                    connection.execute(
                        """
                        INSERT INTO mobile_devices (
                            device_id, push_handle, device_label, access_subject, access_email,
                            background_jwk, user_jwk, background_jkt, user_jkt,
                            profile_allowlist, scope_allowlist, status, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
                        """,
                        (
                            device_id,
                            self._new_opaque_id(),
                            label,
                            subject,
                            email,
                            json.dumps(background, sort_keys=True, separators=(",", ":")),
                            json.dumps(user, sort_keys=True, separators=(",", ":")),
                            background_jkt,
                            user_jkt,
                            _json_allowlist(profiles_tuple),
                            _json_allowlist(scopes_tuple),
                            created_at,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO mobile_enrollment_codes (code_hash, device_id, expires_at)
                        VALUES (?, ?, ?)
                        """,
                        (self._code_hash(code), device_id, expires_at),
                    )
                return EnrollmentChallenge(
                    device_id=device_id,
                    code=code,
                    expires_at=expires_at,
                    background_jkt=background_jkt,
                    user_jkt=user_jkt,
                )
            except sqlite3.IntegrityError:
                continue
        raise MobileDeviceError("could not allocate device enrollment")

    create_enrollment = create_enrollment_code

    def redeem_enrollment_code(
        self,
        code: str | EnrollmentChallenge,
        *,
        now: float | int | None = None,
    ) -> DeviceRecord:
        """Consume a code exactly once and return its still-pending device."""

        code_value = code.code if isinstance(code, EnrollmentChallenge) else code
        if not isinstance(code_value, str) or not 16 <= len(code_value) <= 512:
            raise DeviceNotAuthorized("enrollment code is invalid")
        current = self._now(now)
        code_hash = self._code_hash(code_value)
        try:
            with self._transaction() as connection:
                row = connection.execute(
                    """
                    SELECT d.*, c.expires_at AS code_expires_at, c.consumed_at
                    FROM mobile_enrollment_codes AS c
                    JOIN mobile_devices AS d ON d.device_id = c.device_id
                    WHERE c.code_hash = ?
                    """,
                    (code_hash,),
                ).fetchone()
                if row is None or row["consumed_at"] is not None or current >= float(row["code_expires_at"]):
                    raise DeviceNotAuthorized("enrollment code is invalid")
                changed = connection.execute(
                    """
                    UPDATE mobile_enrollment_codes
                    SET consumed_at = ?
                    WHERE code_hash = ? AND consumed_at IS NULL AND expires_at > ?
                    """,
                    (current, code_hash, current),
                ).rowcount
                if changed != 1:
                    raise DeviceNotAuthorized("enrollment code is invalid")
                return self._record_from_row(row)
        except sqlite3.Error as exc:
            raise MobileDeviceError("mobile device store unavailable") from exc

    redeem_enrollment = redeem_enrollment_code

    def _fetch_row(self, device_id: str) -> sqlite3.Row | None:
        return self._connection.execute(
            "SELECT * FROM mobile_devices WHERE device_id = ?",
            (device_id,),
        ).fetchone()

    def _record_from_row(self, row: sqlite3.Row) -> DeviceRecord:
        try:
            background = json.loads(row["background_jwk"])
            user = json.loads(row["user_jwk"])
            background = validate_public_jwk(background)
            user = validate_public_jwk(user)
            profiles = _parse_allowlist(row["profile_allowlist"], field_name="profile allowlist")
            scopes = _parse_allowlist(row["scope_allowlist"], field_name="scope allowlist")
        except (KeyError, TypeError, ValueError, MobileDeviceError) as exc:
            raise MobileDeviceError("device record unavailable") from exc
        return DeviceRecord(
            device_id=str(row["device_id"]),
            status=str(row["status"]),
            background_jwk=background,
            user_jwk=user,
            background_jkt=str(row["background_jkt"]),
            user_jkt=str(row["user_jkt"]),
            profile_allowlist=profiles,
            scope_allowlist=scopes,
            created_at=float(row["created_at"]),
            approved_at=None if row["approved_at"] is None else float(row["approved_at"]),
            revoked_at=None if row["revoked_at"] is None else float(row["revoked_at"]),
            device_label=str(row["device_label"]),
            access_subject=str(row["access_subject"]),
            access_email=str(row["access_email"]),
            push_handle=str(row["push_handle"]),
        )

    def get_device(self, device_id: str) -> DeviceRecord:
        if not isinstance(device_id, str) or not _OPAQUE_ID_RE.fullmatch(device_id):
            raise DeviceNotAuthorized("device is not authorized")
        with self._lock:
            self._ensure_open()
            row = self._fetch_row(device_id)
        if row is None:
            raise DeviceNotAuthorized("device is not authorized")
        return self._record_from_row(row)

    device = get_device

    def list_devices(self) -> tuple[DeviceRecord, ...]:
        """Return safe device records in deterministic enrollment order."""

        with self._lock:
            self._ensure_open()
            try:
                rows = self._connection.execute(
                    "SELECT * FROM mobile_devices ORDER BY created_at ASC, device_id ASC"
                ).fetchall()
            except sqlite3.Error as exc:
                raise MobileDeviceError("mobile device store unavailable") from exc
        return tuple(self._record_from_row(row) for row in rows)

    def approve_device(
        self,
        device_id: str,
        *,
        profiles: Iterable[str] | str | None = None,
        scopes: Iterable[str] | str | None = None,
        profile_allowlist: Iterable[str] | str | None = None,
        scope_allowlist: Iterable[str] | str | None = None,
        now: float | int | None = None,
    ) -> DeviceRecord:
        """Approve a redeemed device, optionally narrowing its allowlists."""

        if not isinstance(device_id, str) or not _OPAQUE_ID_RE.fullmatch(device_id):
            raise DeviceNotAuthorized("device is not authorized")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM mobile_devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            if row is None or row["status"] == "revoked":
                raise DeviceNotAuthorized("device is not authorized")
            if row["status"] == "approved":
                if profiles is not None or scopes is not None or profile_allowlist is not None or scope_allowlist is not None:
                    current_profiles = _parse_allowlist(row["profile_allowlist"], field_name="profile allowlist")
                    current_scopes = _parse_allowlist(row["scope_allowlist"], field_name="scope allowlist")
                    new_profiles, new_scopes = self._resolve_allowlists(
                        profiles if profiles is not None else current_profiles,
                        scopes if scopes is not None else current_scopes,
                        profile_allowlist,
                        scope_allowlist,
                    )
                    if not set(new_profiles) <= set(current_profiles) or not set(new_scopes) <= set(current_scopes):
                        raise ValueError("approval cannot widen the device policy")
                return self._record_from_row(row)
            consumed = connection.execute(
                "SELECT consumed_at FROM mobile_enrollment_codes WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            if consumed is None or consumed["consumed_at"] is None:
                raise DeviceNotAuthorized("device enrollment is incomplete")
            current_profiles = _parse_allowlist(row["profile_allowlist"], field_name="profile allowlist")
            current_scopes = _parse_allowlist(row["scope_allowlist"], field_name="scope allowlist")
            new_profiles, new_scopes = self._resolve_allowlists(
                profiles if profiles is not None else current_profiles,
                scopes if scopes is not None else current_scopes,
                profile_allowlist,
                scope_allowlist,
            )
            if not set(new_profiles) <= set(current_profiles) or not set(new_scopes) <= set(current_scopes):
                raise ValueError("approval cannot widen the device policy")
            approved_at = self._now(now)
            connection.execute(
                """
                UPDATE mobile_devices
                SET profile_allowlist = ?, scope_allowlist = ?, status = 'approved', approved_at = ?
                WHERE device_id = ? AND status = 'pending'
                """,
                (_json_allowlist(new_profiles), _json_allowlist(new_scopes), approved_at, device_id),
            )
            updated = connection.execute(
                "SELECT * FROM mobile_devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            if updated is None or updated["status"] != "approved":
                raise DeviceNotAuthorized("device approval failed")
            return self._record_from_row(updated)

    approve = approve_device

    def revoke_device(self, device_id: str, *, now: float | int | None = None) -> DeviceRecord:
        """Revoke a device; token verification observes this immediately."""

        if not isinstance(device_id, str) or not _OPAQUE_ID_RE.fullmatch(device_id):
            raise DeviceNotAuthorized("device is not authorized")
        revoked_at = self._now(now)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM mobile_devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            if row is None:
                raise DeviceNotAuthorized("device is not authorized")
            if row["status"] != "revoked":
                connection.execute(
                    "UPDATE mobile_devices SET status = 'revoked', revoked_at = ? WHERE device_id = ?",
                    (revoked_at, device_id),
                )
            updated = connection.execute(
                "SELECT * FROM mobile_devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            if updated is None:
                raise DeviceNotAuthorized("device is not authorized")
            return self._record_from_row(updated)

    revoke = revoke_device

    def create_token_challenge(
        self,
        device_id: str,
        *,
        ttl_seconds: float | int = TOKEN_CHALLENGE_TTL_SECONDS,
        now: float | int | None = None,
    ) -> TokenChallenge:
        """Create a short-lived nonce for the approved device background key."""

        record = self.get_device(device_id)
        if not record.approved:
            raise DeviceNotAuthorized("device is not authorized")
        current = self._now(now)
        expires_at = current + _ttl(
            ttl_seconds,
            maximum=TOKEN_CHALLENGE_TTL_SECONDS,
            field_name="token challenge TTL",
        )
        for _attempt in range(5):
            nonce = secrets.token_urlsafe(32)
            try:
                with self._transaction() as connection:
                    connection.execute(
                        "DELETE FROM mobile_token_challenges WHERE expires_at <= ?",
                        (current,),
                    )
                    connection.execute(
                        """
                        INSERT INTO mobile_token_challenges (nonce_hash, device_id, expires_at)
                        VALUES (?, ?, ?)
                        """,
                        (self._code_hash(nonce), device_id, expires_at),
                    )
                return TokenChallenge(device_id=device_id, nonce=nonce, expires_at=expires_at)
            except sqlite3.IntegrityError:
                continue
        raise MobileDeviceError("could not allocate token challenge")

    def complete_token_challenge(
        self,
        device_id: str,
        *,
        nonce: str,
        signature: str,
        now: float | int | None = None,
    ) -> str:
        """Consume a signed server nonce and issue one five-minute device token."""

        message = token_challenge_message(device_id, nonce)
        try:
            signature_bytes = _b64u_decode_variable(signature, maximum_length=144)
        except ValueError as exc:
            raise DeviceNotAuthorized("token challenge is invalid") from exc
        current = self._now(now)
        nonce_hash = self._code_hash(nonce)
        try:
            with self._transaction() as connection:
                row = connection.execute(
                    """
                    SELECT c.expires_at, c.consumed_at, d.background_jwk, d.status
                    FROM mobile_token_challenges AS c
                    JOIN mobile_devices AS d ON d.device_id = c.device_id
                    WHERE c.nonce_hash = ? AND c.device_id = ?
                    """,
                    (nonce_hash, device_id),
                ).fetchone()
                if (
                    row is None
                    or row["status"] != "approved"
                    or row["consumed_at"] is not None
                    or current >= float(row["expires_at"])
                ):
                    raise DeviceNotAuthorized("token challenge is invalid")
                public_key = _public_key_from_jwk(json.loads(row["background_jwk"]))
                try:
                    public_key.verify(signature_bytes, message, ec.ECDSA(hashes.SHA256()))
                except InvalidSignature as exc:
                    raise DeviceNotAuthorized("token challenge is invalid") from exc
                changed = connection.execute(
                    """
                    UPDATE mobile_token_challenges
                    SET consumed_at = ?
                    WHERE nonce_hash = ? AND device_id = ? AND consumed_at IS NULL AND expires_at > ?
                    """,
                    (current, nonce_hash, device_id, current),
                ).rowcount
                if changed != 1:
                    raise DeviceNotAuthorized("token challenge is invalid")
        except sqlite3.Error as exc:
            raise MobileDeviceError("mobile device store unavailable") from exc
        return self.issue_device_token(device_id, now=current)

    def issue_device_token(
        self,
        device_id: str,
        *,
        profile: str | None = None,
        scope: str | None = None,
        scopes: Iterable[str] | str | None = None,
        ttl_seconds: float | int = DEVICE_TOKEN_TTL_SECONDS,
        now: float | int | None = None,
    ) -> str:
        """Mint a short-lived ES256 token bound to the device background key."""

        record = self.get_device(device_id)
        if not record.approved:
            raise DeviceNotAuthorized("device is not authorized")
        if profile is not None:
            profile = _validate_allowlist(profile, field_name="profile")[0]
            if profile not in record.profile_allowlist:
                raise DeviceNotAuthorized("profile is not authorized")
            token_profiles = (profile,)
        else:
            token_profiles = record.profile_allowlist
        if scope is not None and scopes is not None:
            raise ValueError("provide only one scope")
        if scope is not None:
            token_scopes = _validate_allowlist(scope, field_name="scope")
        elif scopes is not None:
            token_scopes = _validate_allowlist(scopes, field_name="scope")
        else:
            token_scopes = record.scope_allowlist
        if not set(token_scopes) <= set(record.scope_allowlist):
            raise DeviceNotAuthorized("scope is not authorized")
        if not token_scopes or not token_profiles:
            raise DeviceNotAuthorized("device policy is empty")

        issued_at = int(self._now(now))
        ttl = int(_ttl(ttl_seconds, maximum=DEVICE_TOKEN_TTL_SECONDS, field_name="device token TTL"))
        claims = {
            "iss": self._token_issuer,
            "aud": self._token_audience,
            "sub": record.device_id,
            "iat": issued_at,
            "exp": issued_at + ttl,
            "jti": secrets.token_urlsafe(18),
            "cnf": {"jkt": record.background_jkt},
            "profiles": list(token_profiles),
            "scope": " ".join(token_scopes),
        }
        return str(jwt.encode(claims, self._token_signing_key, algorithm="ES256"))

    issue_token = issue_device_token
    mint_device_token = issue_device_token

    def verify_device_token(
        self,
        token: str,
        *,
        now: float | int | None = None,
    ) -> dict[str, Any]:
        """Verify signature, lifetime, key binding, and current approval state."""

        if not isinstance(token, str) or not 32 <= len(token) <= 16384:
            raise InvalidDeviceToken("device token is invalid")
        current = self._now(now)
        try:
            claims = jwt.decode(
                token,
                self.token_verification_key,
                algorithms=["ES256"],
                options={
                    "require": ["iss", "aud", "sub", "iat", "exp", "jti", "cnf", "profiles", "scope"],
                    "verify_aud": False,
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
            if claims.get("iss") != self._token_issuer or claims.get("aud") != self._token_audience:
                raise InvalidDeviceToken("device token is invalid")
            issued_at = claims["iat"]
            expires_at = claims["exp"]
            if (
                isinstance(issued_at, bool)
                or isinstance(expires_at, bool)
                or not isinstance(issued_at, int)
                or not isinstance(expires_at, int)
                or expires_at <= issued_at
                or expires_at - issued_at > DEVICE_TOKEN_TTL_SECONDS
                or issued_at > current + DPOP_CLOCK_SKEW_SECONDS
                or expires_at <= current
            ):
                raise InvalidDeviceToken("device token is invalid")
            device_id = claims["sub"]
            jti = claims["jti"]
            if not isinstance(device_id, str) or not _OPAQUE_ID_RE.fullmatch(device_id):
                raise InvalidDeviceToken("device token is invalid")
            if not isinstance(jti, str) or not _JTI_RE.fullmatch(jti):
                raise InvalidDeviceToken("device token is invalid")
            cnf = claims["cnf"]
            if not isinstance(cnf, Mapping) or not isinstance(cnf.get("jkt"), str):
                raise InvalidDeviceToken("device token is invalid")
            jkt = cnf["jkt"]
            profiles = claims["profiles"]
            if not isinstance(profiles, list):
                raise InvalidDeviceToken("device token is invalid")
            scopes = _validate_allowlist(str(claims["scope"]).split(" "), field_name="scope")
            token_profiles = _validate_allowlist(profiles, field_name="profile")
        except (jwt.PyJWTError, InvalidDeviceToken, TypeError, ValueError, KeyError, OverflowError):
            raise InvalidDeviceToken("device token is invalid") from None

        try:
            record = self.get_device(device_id)
        except DeviceNotAuthorized:
            raise InvalidDeviceToken("device token is invalid") from None
        if not record.approved or record.background_jkt != jkt:
            raise InvalidDeviceToken("device token is invalid")
        if not set(token_profiles) <= set(record.profile_allowlist) or not set(scopes) <= set(record.scope_allowlist):
            raise InvalidDeviceToken("device token is invalid")
        return dict(claims)

    verify_token = verify_device_token

    def _remember_dpop_jti(self, jti: str, *, now: float) -> None:
        expires_at = now + DPOP_MAX_AGE_SECONDS + DPOP_CLOCK_SKEW_SECONDS
        try:
            with self._transaction() as connection:
                connection.execute(
                    "DELETE FROM mobile_dpop_replays WHERE expires_at <= ?",
                    (now,),
                )
                connection.execute(
                    "INSERT INTO mobile_dpop_replays (jti, expires_at) VALUES (?, ?)",
                    (jti, expires_at),
                )
        except sqlite3.IntegrityError:
            raise DpopReplay("DPoP proof replayed") from None
        except sqlite3.Error as exc:
            raise InvalidDpopProof("DPoP replay storage unavailable") from exc

    def verify_dpop_proof(
        self,
        proof: str,
        *,
        method: str,
        url: str,
        access_token: str | None = None,
        expected_jkt: str | None = None,
        now: float | int | None = None,
        max_age_seconds: float | int = DPOP_MAX_AGE_SECONDS,
    ) -> dict[str, Any]:
        """Verify an ES256 DPoP proof and atomically consume its JTI."""

        if not isinstance(proof, str) or not 32 <= len(proof) <= 16384:
            raise InvalidDpopProof("DPoP proof is invalid")
        if not isinstance(method, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]{0,31}", method):
            raise InvalidDpopProof("DPoP proof is invalid")
        try:
            expected_url = normalize_dpop_url(url)
            max_age = _ttl(max_age_seconds, maximum=DPOP_MAX_AGE_SECONDS, field_name="DPoP age")
            current = self._now(now)
            header = jwt.get_unverified_header(proof)
            if not isinstance(header, Mapping) or header.get("alg") != "ES256":
                raise InvalidDpopProof("DPoP proof is invalid")
            if str(header.get("typ", "")).lower() != "dpop+jwt":
                raise InvalidDpopProof("DPoP proof is invalid")
            jwk = header.get("jwk")
            if not isinstance(jwk, Mapping):
                raise InvalidDpopProof("DPoP proof is invalid")
            canonical_jwk = validate_public_jwk(jwk)
            proof_jkt = jwk_thumbprint(canonical_jwk)
            if expected_jkt is not None and not secrets.compare_digest(proof_jkt, expected_jkt):
                raise InvalidDpopProof("DPoP proof is invalid")
            claims = jwt.decode(
                proof,
                _public_key_from_jwk(canonical_jwk),
                algorithms=["ES256"],
                options={
                    # ``nonce`` is a per-proof client nonce and ``request_id`` is
                    # the explicit API request identity.  Requiring the latter to
                    # equal the standard DPoP ``jti`` keeps the existing durable
                    # replay table as the single source of truth.
                    "require": ["htm", "htu", "iat", "jti", "nonce", "request_id"],
                    "verify_aud": False,
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
            proof_method = claims.get("htm")
            proof_url = claims.get("htu")
            issued_at = claims.get("iat")
            jti = claims.get("jti")
            nonce = claims.get("nonce")
            request_id = claims.get("request_id")
            if (
                not isinstance(proof_method, str)
                or proof_method.upper() != method.upper()
                or not isinstance(proof_url, str)
                or normalize_dpop_url(proof_url) != expected_url
                or isinstance(issued_at, bool)
                or not isinstance(issued_at, int)
                or issued_at > current + DPOP_CLOCK_SKEW_SECONDS
                or issued_at < current - max_age
                or not isinstance(jti, str)
                or not _JTI_RE.fullmatch(jti)
                or not isinstance(nonce, str)
                or not _DPOP_NONCE_RE.fullmatch(nonce)
                or not isinstance(request_id, str)
                or request_id != jti
            ):
                raise InvalidDpopProof("DPoP proof is invalid")
            if access_token is not None:
                if not isinstance(access_token, str) or not isinstance(claims.get("ath"), str):
                    raise InvalidDpopProof("DPoP proof is invalid")
                try:
                    expected_ath = _b64u_encode(hashlib.sha256(access_token.encode("ascii")).digest())
                except UnicodeEncodeError as exc:
                    raise InvalidDpopProof("DPoP proof is invalid") from exc
                if not secrets.compare_digest(claims["ath"], expected_ath):
                    raise InvalidDpopProof("DPoP proof is invalid")
            elif "ath" in claims:
                raise InvalidDpopProof("DPoP proof is invalid")
        except DpopReplay:
            raise
        except InvalidDpopProof:
            raise
        except (jwt.PyJWTError, TypeError, ValueError, KeyError, OverflowError):
            raise InvalidDpopProof("DPoP proof is invalid") from None

        self._remember_dpop_jti(jti, now=current)
        return dict(claims)

    verify_dpop = verify_dpop_proof

    def authorize_request(
        self,
        device_token: str,
        dpop_proof: str,
        *,
        method: str,
        url: str,
        profile: str | None = None,
        scope: str | None = None,
        now: float | int | None = None,
    ) -> DeviceAuthorization:
        """Authorize a request with token, DPoP proof, and host policy."""

        claims = self.verify_device_token(device_token, now=now)
        device_id = claims["sub"]
        token_profiles = set(_validate_allowlist(claims["profiles"], field_name="profile"))
        token_scopes = set(_validate_allowlist(str(claims["scope"]).split(" "), field_name="scope"))
        if profile is not None:
            profile = _validate_allowlist(profile, field_name="profile")[0]
            if profile not in token_profiles:
                raise DeviceNotAuthorized("profile is not authorized")
        if scope is not None:
            scope = _validate_allowlist(scope, field_name="scope")[0]
            if scope not in token_scopes:
                raise DeviceNotAuthorized("scope is not authorized")
        dpop_claims = self.verify_dpop_proof(
            dpop_proof,
            method=method,
            url=url,
            access_token=device_token,
            expected_jkt=claims["cnf"]["jkt"],
            now=now,
        )
        return DeviceAuthorization(
            device_id=device_id,
            profile=profile,
            scope=scope,
            token_claims=claims,
            dpop_claims=dpop_claims,
        )

    authorize = authorize_request


MobileDeviceRegistry = MobileDeviceStore
MobileDeviceTrustStore = MobileDeviceStore


def verify_dpop_proof(
    proof: str,
    *,
    method: str,
    url: str,
    replay_store: MobileDeviceStore | None = None,
    access_token: str | None = None,
    expected_jkt: str | None = None,
    now: float | int | None = None,
) -> dict[str, Any]:
    """Module-level convenience wrapper requiring explicit replay storage."""

    if replay_store is None:
        raise InvalidDpopProof("DPoP replay storage unavailable")
    return replay_store.verify_dpop_proof(
        proof,
        method=method,
        url=url,
        access_token=access_token,
        expected_jkt=expected_jkt,
        now=now,
    )


validate_device_jwk = validate_public_jwk
device_jwk_thumbprint = jwk_thumbprint
