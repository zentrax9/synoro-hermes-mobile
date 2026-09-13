"""Cloud Run relay that maps opaque event enums to fixed FCM notifications."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import Any, Callable, Mapping, Protocol

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field


_OPAQUE_RE = re.compile(r"^[A-Za-z0-9_-]{16,256}$")
_DEDUP_TTL_SECONDS = 86_400
_DELIVERY_LEASE_SECONDS = 60


class PushEventType(StrEnum):
    APPROVAL_REQUIRED = "approval_required"
    QUESTION_REQUIRED = "question_required"
    RUN_COMPLETED = "run_completed"
    RUN_FAILED = "run_failed"


_STATIC_MESSAGES = {
    PushEventType.APPROVAL_REQUIRED: ("Hermes needs attention", "Open Hermes to review a request."),
    PushEventType.QUESTION_REQUIRED: ("Hermes has a question", "Open Hermes to continue."),
    PushEventType.RUN_COMPLETED: ("Hermes finished", "Open Hermes to view the result."),
    PushEventType.RUN_FAILED: ("Hermes needs attention", "Open Hermes to review a failed run."),
}


class PushRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: PushEventType
    event_id: str = Field(min_length=16, max_length=256, pattern=_OPAQUE_RE.pattern)
    device_handle: str = Field(min_length=16, max_length=256, pattern=_OPAQUE_RE.pattern)
    expires_at: int = Field(gt=0)


class PushResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    accepted: bool
    duplicate: bool = False


class DeviceRegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fcm_token: str = Field(min_length=32, max_length=4096)


@dataclass(frozen=True)
class FcmMessage:
    token: str
    title: str
    body: str
    event_type: str
    event_id: str
    ttl_seconds: int
    high_priority: bool
    collapse_key: str | None


class FcmSender(Protocol):
    def send(self, message: FcmMessage) -> None: ...


def _hash_secret(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def _is_opaque(value: object) -> bool:
    return isinstance(value, str) and _OPAQUE_RE.fullmatch(value) is not None


def _delivery_key(event_id: str, device_handle: str) -> str:
    """Return an internal key that scopes idempotency to one device."""

    return f"{event_id}\x00{device_handle}"


class RelayRegistry:
    """Stores only authentication hashes, opaque handles, and FCM routing tokens."""

    def __init__(self, path: str | Path, *, clock=time.time) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS relay_instances (
                    instance_id TEXT PRIMARY KEY,
                    credential_hash BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS relay_devices (
                    device_handle TEXT PRIMARY KEY,
                    instance_id TEXT NOT NULL REFERENCES relay_instances(instance_id),
                    fcm_token TEXT NOT NULL,
                    revoked_at REAL
                );
                CREATE TABLE IF NOT EXISTS relay_events (
                    instance_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    device_handle TEXT NOT NULL,
                    accepted_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    delivery_state TEXT NOT NULL DEFAULT 'sent',
                    lease_until REAL NOT NULL DEFAULT 0,
                    PRIMARY KEY (instance_id, event_id)
                );
                CREATE TABLE IF NOT EXISTS relay_rate_limits (
                    instance_id TEXT NOT NULL,
                    device_handle TEXT NOT NULL,
                    window_start INTEGER NOT NULL,
                    request_count INTEGER NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (instance_id, device_handle, window_start)
                );
                """
            )
            event_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(relay_events)").fetchall()
            }
            if "expires_at" not in event_columns:
                connection.execute(
                    "ALTER TABLE relay_events ADD COLUMN expires_at REAL NOT NULL DEFAULT 0"
                )
            if "delivery_state" not in event_columns:
                connection.execute(
                    "ALTER TABLE relay_events ADD COLUMN delivery_state TEXT NOT NULL DEFAULT 'sent'"
                )
            if "lease_until" not in event_columns:
                connection.execute(
                    "ALTER TABLE relay_events ADD COLUMN lease_until REAL NOT NULL DEFAULT 0"
                )
            rate_limit_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(relay_rate_limits)").fetchall()
            }
            if "expires_at" not in rate_limit_columns:
                connection.execute(
                    "ALTER TABLE relay_rate_limits ADD COLUMN expires_at REAL NOT NULL DEFAULT 0"
                )

    def _connect(self):
        connection = sqlite3.connect(self.path, isolation_level=None, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def provision_instance(self, instance_id: str, credential: str | None = None) -> str:
        if not _is_opaque(instance_id):
            raise ValueError("instance ID must be opaque")
        credential = credential or secrets.token_urlsafe(32)
        if not isinstance(credential, str) or len(credential) < 32:
            raise ValueError("relay credential is too short")
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO relay_instances (instance_id, credential_hash) VALUES (?, ?)",
                (instance_id, _hash_secret(credential)),
            )
        return credential

    def register_device(
        self,
        instance_id: str,
        device_handle: str,
        fcm_token: str,
        *,
        maximum_devices: int = 100,
    ) -> None:
        if (
            not _is_opaque(instance_id)
            or not _is_opaque(device_handle)
            or not isinstance(fcm_token, str)
            or not 32 <= len(fcm_token) <= 4096
            or not isinstance(maximum_devices, int)
            or isinstance(maximum_devices, bool)
            or maximum_devices <= 0
        ):
            raise ValueError("invalid relay device registration")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            instance = connection.execute(
                "SELECT 1 FROM relay_instances WHERE instance_id = ?",
                (instance_id,),
            ).fetchone()
            if instance is None:
                connection.rollback()
                raise KeyError("unknown relay instance")
            owner = connection.execute(
                "SELECT instance_id FROM relay_devices WHERE device_handle = ?",
                (device_handle,),
            ).fetchone()
            if owner is not None and owner["instance_id"] != instance_id:
                connection.rollback()
                raise PermissionError("relay device handle belongs to another instance")
            count = connection.execute(
                "SELECT COUNT(*) FROM relay_devices WHERE instance_id = ? AND revoked_at IS NULL",
                (instance_id,),
            ).fetchone()[0]
            if owner is None and int(count) >= maximum_devices:
                connection.rollback()
                raise OverflowError("relay device limit exceeded")
            connection.execute(
                "INSERT INTO relay_devices (device_handle, instance_id, fcm_token) VALUES (?, ?, ?) "
                "ON CONFLICT(device_handle) DO UPDATE SET fcm_token = excluded.fcm_token, "
                "revoked_at = NULL",
                (device_handle, instance_id, fcm_token),
            )
            connection.commit()

    def revoke_device(self, instance_id: str, device_handle: str) -> None:
        if not _is_opaque(instance_id) or not _is_opaque(device_handle):
            raise ValueError("invalid relay device handle")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            owner = connection.execute(
                "SELECT instance_id, revoked_at FROM relay_devices WHERE device_handle = ?",
                (device_handle,),
            ).fetchone()
            if owner is None or owner["instance_id"] != instance_id:
                connection.rollback()
                raise PermissionError("relay device handle is not owned by this instance")
            if owner["revoked_at"] is None:
                connection.execute(
                    "UPDATE relay_devices SET revoked_at = ? WHERE instance_id = ? AND device_handle = ?",
                    (float(self._clock()), instance_id, device_handle),
                )
            connection.commit()

    def authenticate(self, authorization: str) -> str:
        prefix = "Bearer "
        if not isinstance(authorization, str) or not authorization.startswith(prefix):
            raise PermissionError("relay authentication required")
        presented = _hash_secret(authorization[len(prefix) :])
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT instance_id, credential_hash FROM relay_instances"
            ).fetchall()
        for row in rows:
            if hmac.compare_digest(bytes(row["credential_hash"]), presented):
                return str(row["instance_id"])
        raise PermissionError("relay authentication required")

    def reserve_delivery(
        self,
        *,
        instance_id: str,
        event_id: str,
        device_handle: str,
        limit_per_minute: int = 60,
    ) -> tuple[str, bool]:
        if (
            not _is_opaque(instance_id)
            or not _is_opaque(event_id)
            or not _is_opaque(device_handle)
        ):
            raise ValueError("invalid relay delivery identifiers")
        if not isinstance(limit_per_minute, int) or isinstance(limit_per_minute, bool) or limit_per_minute <= 0:
            raise OverflowError("relay rate exceeded")
        now = float(self._clock())
        window = int(now // 60) * 60
        event_key = _delivery_key(event_id, device_handle)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT fcm_token FROM relay_devices WHERE instance_id = ? "
                "AND device_handle = ? AND revoked_at IS NULL",
                (instance_id, device_handle),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise KeyError("unknown relay device")
            duplicate = connection.execute(
                "SELECT expires_at, delivery_state, lease_until FROM relay_events "
                "WHERE instance_id = ? AND event_id = ?",
                (instance_id, event_key),
            ).fetchone()
            if duplicate is not None and float(duplicate["expires_at"]) > now:
                state = str(duplicate["delivery_state"] or "sent")
                lease_until = float(duplicate["lease_until"] or 0)
                if state == "sent" or lease_until > now:
                    connection.rollback()
                    return str(row["fcm_token"]), True
            if duplicate is not None and float(duplicate["expires_at"]) <= now:
                connection.execute(
                    "DELETE FROM relay_events WHERE instance_id = ? AND event_id = ?",
                    (instance_id, event_key),
                )
            connection.execute(
                "DELETE FROM relay_rate_limits WHERE expires_at <= ?",
                (now,),
            )
            count = connection.execute(
                "SELECT request_count, expires_at FROM relay_rate_limits WHERE instance_id = ? "
                "AND device_handle = ? AND window_start = ?",
                (instance_id, device_handle, window),
            ).fetchone()
            if count is not None:
                if float(count["expires_at"]) <= now:
                    connection.execute(
                        "DELETE FROM relay_rate_limits WHERE instance_id = ? "
                        "AND device_handle = ? AND window_start = ?",
                        (instance_id, device_handle, window),
                    )
                elif int(count["request_count"]) >= limit_per_minute:
                    connection.rollback()
                    raise OverflowError("relay rate exceeded")
            values = (
                instance_id,
                event_key,
                device_handle,
                now,
                now + _DEDUP_TTL_SECONDS,
                "pending",
                now + _DELIVERY_LEASE_SECONDS,
            )
            if duplicate is None or float(duplicate["expires_at"]) <= now:
                connection.execute(
                    "INSERT INTO relay_events (instance_id, event_id, device_handle, accepted_at, "
                    "expires_at, delivery_state, lease_until) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    values,
                )
            else:
                connection.execute(
                    "UPDATE relay_events SET device_handle = ?, accepted_at = ?, expires_at = ?, "
                    "delivery_state = ?, lease_until = ? WHERE instance_id = ? AND event_id = ?",
                    (
                        device_handle,
                        now,
                        now + _DEDUP_TTL_SECONDS,
                        "pending",
                        now + _DELIVERY_LEASE_SECONDS,
                        instance_id,
                        event_key,
                    ),
                )
            connection.execute(
                "INSERT INTO relay_rate_limits "
                "(instance_id, device_handle, window_start, request_count, expires_at) "
                "VALUES (?, ?, ?, 1, ?) "
                "ON CONFLICT(instance_id, device_handle, window_start) "
                "DO UPDATE SET request_count = request_count + 1, expires_at = excluded.expires_at",
                (instance_id, device_handle, window, float(window + 120)),
            )
            connection.commit()
            return str(row["fcm_token"]), False

    def complete_delivery(self, *, instance_id: str, event_id: str, device_handle: str) -> None:
        if not _is_opaque(instance_id) or not _is_opaque(event_id) or not _is_opaque(device_handle):
            raise ValueError("invalid relay delivery identifiers")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE relay_events SET delivery_state = 'sent', lease_until = 0 "
                "WHERE instance_id = ? AND event_id = ? AND device_handle = ? "
                "AND delivery_state = 'pending'",
                (instance_id, _delivery_key(event_id, device_handle), device_handle),
            )
            connection.commit()

    def release_delivery(self, *, instance_id: str, event_id: str, device_handle: str) -> None:
        """Release a failed reservation so a caller can retry the wake hint."""

        if not _is_opaque(instance_id) or not _is_opaque(event_id) or not _is_opaque(device_handle):
            raise ValueError("invalid relay delivery identifiers")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM relay_events WHERE instance_id = ? AND event_id = ? "
                "AND device_handle = ? AND delivery_state = 'pending'",
                (instance_id, _delivery_key(event_id, device_handle), device_handle),
            )
            connection.commit()

    def delivery_pending(self, *, instance_id: str, event_id: str, device_handle: str) -> bool:
        if not _is_opaque(instance_id) or not _is_opaque(event_id) or not _is_opaque(device_handle):
            raise ValueError("invalid relay delivery identifiers")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT delivery_state, lease_until, expires_at FROM relay_events "
                "WHERE instance_id = ? AND event_id = ? AND device_handle = ?",
                (instance_id, _delivery_key(event_id, device_handle), device_handle),
            ).fetchone()
        now = float(self._clock())
        return bool(
            row is not None
            and str(row["delivery_state"] or "sent") == "pending"
            and float(row["lease_until"] or 0) > now
            and float(row["expires_at"]) > now
        )


class FirestoreRelayRegistry:
    """Durable relay state backed by Firestore transactions and TTL fields.

    The constructor performs ADC setup when no client is injected.  Production callers
    therefore fail during startup if Workload Identity/ADC or the Firestore dependency is
    unavailable rather than silently falling back to an ephemeral local database.
    """

    _FIRESTORE_SCOPES = ("https://www.googleapis.com/auth/datastore",)

    def __init__(
        self,
        project_id: str | None = None,
        *,
        client: Any | None = None,
        transaction_runner: Callable[[Callable[[Any], Any]], Any] | None = None,
        clock=time.time,
        dedup_ttl_seconds: int = 86_400,
    ) -> None:
        if not isinstance(dedup_ttl_seconds, int) or dedup_ttl_seconds <= 0:
            raise ValueError("dedup_ttl_seconds must be positive")
        self._clock = clock
        self.dedup_ttl_seconds = dedup_ttl_seconds
        self._transaction_runner = transaction_runner
        self._transactional = None
        if client is None:
            try:
                import google.auth
                from google.cloud import firestore
                from google.cloud.firestore_v1.transaction import transactional

                credentials, discovered_project = google.auth.default(scopes=self._FIRESTORE_SCOPES)
                project = project_id or discovered_project
                if not project:
                    raise RuntimeError("Google Cloud project is not configured")
                client = firestore.Client(project=project, credentials=credentials)
                self._transactional = transactional
                self.project_id = str(project)
            except Exception as exc:
                raise RuntimeError("Firestore ADC setup failed") from exc
        else:
            self.project_id = project_id
            if self._transaction_runner is None:
                try:
                    from google.cloud.firestore_v1.transaction import transactional

                    self._transactional = transactional
                except Exception as exc:
                    raise RuntimeError("Firestore transaction support is unavailable") from exc
        self._client = client
        self._instances = client.collection("relay_instances")
        self._devices = client.collection("relay_devices")
        self._events = client.collection("relay_events")
        self._rate_limits = client.collection("relay_rate_limits")

    @staticmethod
    def _utc_timestamp(value: float) -> datetime:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)

    @staticmethod
    def _epoch(value: Any) -> float:
        if isinstance(value, datetime):
            return value.timestamp()
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
        return 0.0

    def _now(self) -> float:
        value = self._clock()
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise RuntimeError("relay clock is invalid")
        return float(value)

    def _run_transaction(self, callback: Callable[[Any], Any]) -> Any:
        if self._transaction_runner is not None:
            return self._transaction_runner(callback)
        if self._transactional is None:
            raise RuntimeError("Firestore transactions are unavailable")
        transaction = self._client.transaction()
        return self._transactional(callback)(transaction)

    @staticmethod
    def _doc_id(instance_id: str, value: str) -> str:
        return hashlib.sha256(f"{instance_id}\x00{value}".encode("utf-8")).hexdigest()

    @staticmethod
    def _snapshot_values(snapshot: Any) -> dict[str, Any]:
        values = snapshot.to_dict() if snapshot.exists else None
        return {} if values is None else dict(values)

    def provision_instance(self, instance_id: str, credential: str | None = None) -> str:
        if not _is_opaque(instance_id):
            raise ValueError("instance ID must be opaque")
        credential = credential or secrets.token_urlsafe(32)
        if not isinstance(credential, str) or len(credential) < 32:
            raise ValueError("relay credential is too short")
        reference = self._instances.document(instance_id)

        def operation(transaction: Any) -> str:
            if transaction.get(reference).exists:
                raise ValueError("relay instance already exists")
            values = {
                "credential_hash": _hash_secret(credential).hex(),
                "active_device_count": 0,
                "created_at": self._utc_timestamp(self._now()),
            }
            transaction.create(reference, values)
            return credential

        return self._run_transaction(operation)

    def register_device(
        self,
        instance_id: str,
        device_handle: str,
        fcm_token: str,
        *,
        maximum_devices: int = 100,
    ) -> None:
        if (
            not _is_opaque(instance_id)
            or not _is_opaque(device_handle)
            or not isinstance(fcm_token, str)
            or not 32 <= len(fcm_token) <= 4096
            or not isinstance(maximum_devices, int)
            or isinstance(maximum_devices, bool)
            or maximum_devices <= 0
        ):
            raise ValueError("invalid relay device registration")
        instance_reference = self._instances.document(instance_id)
        device_reference = self._devices.document(device_handle)

        def operation(transaction: Any) -> None:
            instance_snapshot = transaction.get(instance_reference)
            if not instance_snapshot.exists:
                raise KeyError("unknown relay instance")
            instance = self._snapshot_values(instance_snapshot)
            device_snapshot = transaction.get(device_reference)
            device = self._snapshot_values(device_snapshot)
            if device_snapshot.exists and device.get("instance_id") != instance_id:
                raise PermissionError("relay device handle belongs to another instance")
            was_active = device_snapshot.exists and device.get("revoked_at") is None
            active_count = int(instance.get("active_device_count", 0))
            if not was_active:
                if active_count >= maximum_devices:
                    raise OverflowError("relay device limit exceeded")
                active_count += 1
            timestamp = self._utc_timestamp(self._now())
            transaction.set(
                device_reference,
                {
                    "instance_id": instance_id,
                    "fcm_token": fcm_token,
                    "revoked_at": None,
                    "updated_at": timestamp,
                },
            )
            transaction.set(
                instance_reference,
                {"active_device_count": active_count},
                merge=True,
            )

        self._run_transaction(operation)

    rotate_device_token = register_device

    def revoke_device(self, instance_id: str, device_handle: str) -> None:
        if not _is_opaque(instance_id) or not _is_opaque(device_handle):
            raise ValueError("invalid relay device handle")
        instance_reference = self._instances.document(instance_id)
        device_reference = self._devices.document(device_handle)

        def operation(transaction: Any) -> None:
            instance_snapshot = transaction.get(instance_reference)
            device_snapshot = transaction.get(device_reference)
            if not instance_snapshot.exists or not device_snapshot.exists:
                raise PermissionError("relay device handle is not owned by this instance")
            instance = self._snapshot_values(instance_snapshot)
            device = self._snapshot_values(device_snapshot)
            if device.get("instance_id") != instance_id:
                raise PermissionError("relay device handle is not owned by this instance")
            if device.get("revoked_at") is not None:
                return
            transaction.set(
                device_reference,
                {"revoked_at": self._utc_timestamp(self._now())},
                merge=True,
            )
            transaction.set(
                instance_reference,
                {"active_device_count": max(0, int(instance.get("active_device_count", 0)) - 1)},
                merge=True,
            )

        self._run_transaction(operation)

    def authenticate(self, authorization: str) -> str:
        prefix = "Bearer "
        if not isinstance(authorization, str) or not authorization.startswith(prefix):
            raise PermissionError("relay authentication required")
        presented = _hash_secret(authorization[len(prefix) :]).hex()
        query = self._instances.where("credential_hash", "==", presented)
        for snapshot in query.stream():
            values = self._snapshot_values(snapshot)
            stored = values.get("credential_hash")
            if isinstance(stored, str) and hmac.compare_digest(stored, presented):
                instance_id = str(snapshot.reference.id)
                if _is_opaque(instance_id):
                    return instance_id
        raise PermissionError("relay authentication required")

    def reserve_delivery(
        self,
        *,
        instance_id: str,
        event_id: str,
        device_handle: str,
        limit_per_minute: int = 60,
    ) -> tuple[str, bool]:
        if (
            not _is_opaque(instance_id)
            or not _is_opaque(event_id)
            or not _is_opaque(device_handle)
        ):
            raise ValueError("invalid relay delivery identifiers")
        if not isinstance(limit_per_minute, int) or limit_per_minute <= 0:
            raise OverflowError("relay rate exceeded")
        now = self._now()
        window = int(now // 60) * 60
        instance_reference = self._instances.document(instance_id)
        device_reference = self._devices.document(device_handle)
        event_reference = self._events.document(
            self._doc_id(instance_id, _delivery_key(event_id, device_handle))
        )
        rate_reference = self._rate_limits.document(
            self._doc_id(f"{instance_id}:{device_handle}", str(window))
        )

        def operation(transaction: Any) -> tuple[str, bool]:
            if not transaction.get(instance_reference).exists:
                raise KeyError("unknown relay instance")
            device_snapshot = transaction.get(device_reference)
            if not device_snapshot.exists:
                raise KeyError("unknown relay device")
            device = self._snapshot_values(device_snapshot)
            if device.get("instance_id") != instance_id or device.get("revoked_at") is not None:
                raise KeyError("unknown relay device")
            token = device.get("fcm_token")
            if not isinstance(token, str):
                raise KeyError("unknown relay device")
            event_snapshot = transaction.get(event_reference)
            if event_snapshot.exists:
                event = self._snapshot_values(event_snapshot)
                if self._epoch(event.get("expires_at")) > now:
                    state = str(event.get("delivery_state") or "sent")
                    lease_until = self._epoch(event.get("lease_until"))
                    if state == "sent" or lease_until > now:
                        return token, True

            rate_snapshot = transaction.get(rate_reference)
            rate = self._snapshot_values(rate_snapshot)
            count = int(rate.get("request_count", 0))
            if count >= limit_per_minute:
                raise OverflowError("relay rate exceeded")
            transaction.set(
                event_reference,
                {
                    "device_handle": device_handle,
                    "accepted_at": self._utc_timestamp(now),
                    "expires_at": self._utc_timestamp(now + self.dedup_ttl_seconds),
                    "delivery_state": "pending",
                    "lease_until": self._utc_timestamp(now + _DELIVERY_LEASE_SECONDS),
                },
            )
            transaction.set(
                rate_reference,
                {
                    "request_count": count + 1,
                    "window_start": self._utc_timestamp(window),
                    "expires_at": self._utc_timestamp(window + 120),
                },
            )
            return token, False

        return self._run_transaction(operation)

    def complete_delivery(self, *, instance_id: str, event_id: str, device_handle: str) -> None:
        if not _is_opaque(instance_id) or not _is_opaque(event_id) or not _is_opaque(device_handle):
            raise ValueError("invalid relay delivery identifiers")
        event_reference = self._events.document(
            self._doc_id(instance_id, _delivery_key(event_id, device_handle))
        )

        def operation(transaction: Any) -> None:
            snapshot = transaction.get(event_reference)
            values = self._snapshot_values(snapshot)
            if (
                snapshot.exists
                and values.get("device_handle") == device_handle
                and values.get("delivery_state", "sent") == "pending"
            ):
                transaction.set(
                    event_reference,
                    {
                        "delivery_state": "sent",
                        "lease_until": self._utc_timestamp(0),
                    },
                    merge=True,
                )

        self._run_transaction(operation)

    def release_delivery(self, *, instance_id: str, event_id: str, device_handle: str) -> None:
        """Release a failed reservation so a caller can retry the wake hint."""

        if not _is_opaque(instance_id) or not _is_opaque(event_id) or not _is_opaque(device_handle):
            raise ValueError("invalid relay delivery identifiers")
        event_reference = self._events.document(
            self._doc_id(instance_id, _delivery_key(event_id, device_handle))
        )

        def operation(transaction: Any) -> None:
            snapshot = transaction.get(event_reference)
            values = self._snapshot_values(snapshot)
            if (
                snapshot.exists
                and values.get("device_handle") == device_handle
                and values.get("delivery_state", "sent") == "pending"
            ):
                transaction.delete(event_reference)

        self._run_transaction(operation)

    def delivery_pending(self, *, instance_id: str, event_id: str, device_handle: str) -> bool:
        if not _is_opaque(instance_id) or not _is_opaque(event_id) or not _is_opaque(device_handle):
            raise ValueError("invalid relay delivery identifiers")
        now = self._now()
        event_reference = self._events.document(
            self._doc_id(instance_id, _delivery_key(event_id, device_handle))
        )

        def operation(transaction: Any) -> bool:
            snapshot = transaction.get(event_reference)
            values = self._snapshot_values(snapshot)
            return bool(
                snapshot.exists
                and values.get("device_handle") == device_handle
                and values.get("delivery_state", "sent") == "pending"
                and self._epoch(values.get("lease_until")) > now
                and self._epoch(values.get("expires_at")) > now
            )

        return bool(self._run_transaction(operation))


SQLiteRelayRegistry = RelayRegistry


def create_registry_from_environment(
    environment: Mapping[str, str] | None = None,
) -> RelayRegistry | FirestoreRelayRegistry:
    """Select durable production state and an explicit SQLite local/test backend."""

    values = dict(os.environ if environment is None else environment)
    backend = values.get("RELAY_BACKEND", "").strip().lower()
    production = bool(values.get("K_SERVICE")) or values.get("RELAY_ENV", "").lower() in {
        "prod",
        "production",
        "cloud_run",
    }
    if production and backend not in {"", "firestore"}:
        raise RuntimeError("production relay state must use Firestore")
    if backend == "firestore" or production:
        return FirestoreRelayRegistry(project_id=values.get("GOOGLE_CLOUD_PROJECT"))
    if backend not in {"", "sqlite"}:
        raise RuntimeError("unsupported relay backend")
    # The standalone relay must not assume Hermes' profile home.  Production always uses
    # Firestore; this cwd-local default is only a predictable convenience for explicit local
    # development, while callers that need persistence should set RELAY_DB_PATH.
    path = values.get("RELAY_DB_PATH") or str(Path.cwd() / "mobile-push-relay.sqlite3")
    return RelayRegistry(path)


def create_app(*, registry: RelayRegistry, sender: FcmSender, clock=time.time) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def authenticate(authorization: str) -> str:
        try:
            return registry.authenticate(authorization)
        except PermissionError as exc:
            raise HTTPException(status_code=401, detail="relay authentication required") from exc

    @app.put("/v1/devices/{device_handle}", status_code=204)
    def register_device(
        device_handle: str,
        request: DeviceRegistrationRequest,
        authorization: str = Header(default=""),
    ) -> None:
        if not _OPAQUE_RE.fullmatch(device_handle):
            raise HTTPException(status_code=404, detail="relay device not found")
        instance_id = authenticate(authorization)
        try:
            registry.register_device(instance_id, device_handle, request.fcm_token)
        except PermissionError as exc:
            raise HTTPException(status_code=404, detail="relay device not found") from exc
        except OverflowError as exc:
            raise HTTPException(status_code=429, detail="relay device limit exceeded") from exc

    @app.delete("/v1/devices/{device_handle}", status_code=204)
    def revoke_device(
        device_handle: str,
        authorization: str = Header(default=""),
    ) -> None:
        if not _OPAQUE_RE.fullmatch(device_handle):
            raise HTTPException(status_code=404, detail="relay device not found")
        instance_id = authenticate(authorization)
        try:
            registry.revoke_device(instance_id, device_handle)
        except PermissionError as exc:
            raise HTTPException(status_code=404, detail="relay device not found") from exc

    @app.post("/v1/push", response_model=PushResponse)
    def push(
        request: PushRequest,
        authorization: str = Header(default=""),
    ) -> PushResponse:
        instance_id = authenticate(authorization)
        now = int(clock())
        if request.expires_at <= now or request.expires_at > now + 86_400:
            raise HTTPException(status_code=400, detail="invalid push expiry")
        try:
            token, duplicate = registry.reserve_delivery(
                instance_id=instance_id,
                event_id=request.event_id,
                device_handle=request.device_handle,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="relay device not found") from exc
        except OverflowError as exc:
            raise HTTPException(status_code=429, detail="relay request rate exceeded") from exc
        if duplicate:
            try:
                pending = registry.delivery_pending(
                    instance_id=instance_id,
                    event_id=request.event_id,
                    device_handle=request.device_handle,
                )
            except Exception:
                raise HTTPException(status_code=503, detail="push delivery unavailable") from None
            if pending:
                raise HTTPException(status_code=503, detail="push delivery in progress")
            return PushResponse(accepted=True, duplicate=True)
        title, body = _STATIC_MESSAGES[request.event_type]
        urgent = request.event_type in {
            PushEventType.APPROVAL_REQUIRED,
            PushEventType.QUESTION_REQUIRED,
        }
        try:
            sender.send(
                FcmMessage(
                    token=token,
                    title=title,
                    body=body,
                    event_type=request.event_type.value,
                    event_id=request.event_id,
                    ttl_seconds=request.expires_at - now,
                    high_priority=urgent,
                    collapse_key=None if urgent else f"hermes-{request.event_type.value}",
                )
            )
        except Exception:
            # A failed provider call must not leave the idempotency record marked as
            # delivered.  Release is best effort; a durable pending lease still
            # expires and can be reclaimed by a later retry.
            try:
                registry.release_delivery(
                    instance_id=instance_id,
                    event_id=request.event_id,
                    device_handle=request.device_handle,
                )
            except Exception:
                pass
            raise HTTPException(status_code=503, detail="push delivery unavailable") from None
        try:
            registry.complete_delivery(
                instance_id=instance_id,
                event_id=request.event_id,
                device_handle=request.device_handle,
            )
        except Exception:
            # FCM already accepted the wake hint.  Returning success avoids causing
            # a caller retry that could duplicate the provider delivery; the lease
            # remains bounded if durable completion was temporarily unavailable.
            pass
        return PushResponse(accepted=True)

    return app


class GoogleFcmSender:
    """FCM HTTP v1 sender using Application Default Credentials/Workload Identity."""

    def __init__(self, project_id: str) -> None:
        if not project_id:
            raise ValueError("FCM project ID is required")
        self._project_id = project_id

    def send(self, message: FcmMessage) -> None:
        import google.auth
        from google.auth.transport.requests import AuthorizedSession

        credentials, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/firebase.messaging"]
        )
        response = AuthorizedSession(credentials).post(
            f"https://fcm.googleapis.com/v1/projects/{self._project_id}/messages:send",
            json={
                "message": {
                    "token": message.token,
                    "notification": {"title": message.title, "body": message.body},
                    # The notification payload is intentionally generic.  This marker is copied
                    # into the launch intent by FCM so MainActivity can perform an authenticated
                    # cursor refresh when a background notification is opened; it is not an
                    # authorization or profile-selection input.
                    "data": {
                        "hermes_sync_wake": "1",
                        "event_type": message.event_type,
                        "event_id": message.event_id,
                    },
                    "android": {
                        "priority": "high" if message.high_priority else "normal",
                        "ttl": f"{message.ttl_seconds}s",
                        **(
                            {}
                            if message.collapse_key is None
                            else {"collapse_key": message.collapse_key}
                        ),
                    },
                }
            },
            timeout=10,
        )
        response.raise_for_status()


def app_from_environment() -> FastAPI:
    registry = create_registry_from_environment()
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT") or getattr(registry, "project_id", None)
    if not project_id:
        raise RuntimeError("GOOGLE_CLOUD_PROJECT is required for the FCM sender")
    sender = GoogleFcmSender(project_id)
    return create_app(registry=registry, sender=sender)
