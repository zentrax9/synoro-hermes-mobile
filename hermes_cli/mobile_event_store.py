"""Durable semantic events and idempotent mutation state for Hermes Mobile.

The mobile listener is allowed to lose transient token deltas, but it must not
lose the semantic state needed to reconcile a phone after a restart.  This
module deliberately has no FastAPI, agent, or dashboard dependencies.  A
profile-scoped service owns this store and supplies server-side actor/action
values; request data is persisted only as JSON data and is never interpolated
into SQL.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterator


_PROCESS_TOKEN = uuid.uuid4().hex
_SCHEMA_VERSION = "1"
_DEFAULT_RETENTION_SECONDS = 30 * 24 * 60 * 60
_MAX_EVENT_TYPE_LENGTH = 128
_MAX_IDENTIFIER_LENGTH = 512
_MAX_IDEMPOTENCY_KEY_LENGTH = 255
_MAX_EVENT_PAYLOAD_BYTES = 1_048_576
_MAX_MUTATION_BODY_BYTES = 1_048_576
_MAX_RESULT_BODY_BYTES = 1_048_576
_MAX_BACKLOG_LIMIT = 1_000
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class MobileEventStoreError(RuntimeError):
    """Base class for errors safe for a mobile service to classify."""

    code = "mobile_event_store_error"


class CursorExpired(MobileEventStoreError):
    """The requested cursor predates the retained semantic event window."""

    code = "cursor_expired"

    def __init__(self, after_cursor: int, retained_floor: int, latest_cursor: int) -> None:
        self.after_cursor = after_cursor
        self.retained_floor = retained_floor
        self.latest_cursor = latest_cursor
        super().__init__(
            f"cursor {after_cursor} expired; resume from a complete snapshot "
            f"(retained floor {retained_floor}, latest {latest_cursor})"
        )


class IdempotencyConflict(MobileEventStoreError):
    """A key was reused for the same actor/action with a different body."""

    code = "idempotency_conflict"

    def __init__(self, actor_id: str, action: str, key: str) -> None:
        self.actor_id = actor_id
        self.action = action
        self.key = key
        super().__init__("idempotency key was reused with a different request body")


class MutationStateError(MobileEventStoreError):
    """A mutation cannot make the requested state transition."""

    code = "mutation_state_error"


class InstanceIdentityError(MobileEventStoreError):
    """A database was opened by a caller claiming a different installation."""

    code = "instance_identity_mismatch"


class DuplicateEventError(MobileEventStoreError, ValueError):
    """A caller supplied an event ID already present in the store."""

    code = "duplicate_event"


class MutationStatus(str, Enum):
    """Durable lifecycle states for an idempotent side-effecting request."""

    NEW = "new"
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True, slots=True)
class EventInput:
    """A semantic event to append atomically with a mutation, if requested."""

    event_type: str
    aggregate_type: str
    aggregate_id: str
    payload: Mapping[str, Any]
    tombstone: bool = False
    event_id: str | None = None
    created_at: float | None = None


@dataclass(frozen=True, slots=True)
class MobileEvent:
    """A persisted semantic event with its instance-local monotonic cursor."""

    cursor: int
    event_id: str
    event_type: str
    aggregate_type: str
    aggregate_id: str
    payload: Mapping[str, Any]
    created_at: float
    tombstone: bool = False


@dataclass(frozen=True, slots=True)
class EventBacklog:
    """A bounded cursor page returned by :meth:`MobileEventStore.events_since`."""

    after_cursor: int
    events: tuple[MobileEvent, ...]
    latest_cursor: int
    retained_floor: int
    has_more: bool

    @property
    def next_cursor(self) -> int:
        """The cursor a client should use for the next page."""

        if self.events:
            return self.events[-1].cursor
        return self.after_cursor


@dataclass(frozen=True, slots=True)
class MutationResult:
    """The exact JSON response that can be replayed for an idempotent request."""

    status_code: int
    body: Any


@dataclass(frozen=True, slots=True)
class MutationClaim:
    """The result of reserving an actor/action/idempotency-key tuple."""

    mutation_id: str
    actor_id: str
    action: str
    key: str
    body_digest: str
    status: MutationStatus
    result: MutationResult | None = None

    @property
    def is_new(self) -> bool:
        """Whether the caller owns a fresh reservation and may execute once."""

        return self.status is MutationStatus.NEW


def canonical_body_digest(body: Any) -> str:
    """Return a stable SHA-256 digest for a JSON request body or exact bytes.

    HTTP adapters that already possess the raw body may pass bytes to preserve
    the exact wire digest.  Parsed JSON values are canonicalized before hashing
    so retries with equivalent object-key ordering bind to the same mutation.
    """

    if isinstance(body, bytes):
        encoded = body
    elif isinstance(body, str):
        encoded = _canonical_json(body, field="body").encode("utf-8")
    else:
        encoded = _canonical_json(body, field="body").encode("utf-8")
    if len(encoded) > _MAX_MUTATION_BODY_BYTES:
        raise ValueError("body is too large")
    return hashlib.sha256(encoded).hexdigest()


class MobileEventStore:
    """SQLite/WAL store for durable mobile events and mutation idempotency.

    A connection is opened per operation, while every write uses an explicit
    ``BEGIN IMMEDIATE`` transaction.  This keeps the public surface small and
    makes the event cursor and mutation state transition atomic across multiple
    listener workers.
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        instance_id: str | None = None,
        retention_seconds: float = _DEFAULT_RETENTION_SECONDS,
        clock: Callable[[], float] = time.time,
        timeout_seconds: float = 30.0,
    ) -> None:
        if not isinstance(retention_seconds, (int, float)) or not math.isfinite(retention_seconds):
            raise ValueError("retention_seconds must be a finite number")
        if retention_seconds < 0:
            raise ValueError("retention_seconds must be non-negative")
        if not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds):
            raise ValueError("timeout_seconds must be a finite number")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

        self._db_path = Path(db_path)
        self._retention_seconds = float(retention_seconds)
        self._clock = clock
        self._timeout_seconds = float(timeout_seconds)
        self._requested_instance_id = (
            _validate_identifier(instance_id, "instance_id") if instance_id is not None else None
        )
        self._instance_id = ""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @property
    def db_path(self) -> Path:
        return self._db_path

    @property
    def instance_id(self) -> str:
        """The stable installation identity stored with this database."""

        return self._instance_id

    def append_event(self, event: EventInput) -> MobileEvent:
        """Append one semantic event and return its instance cursor."""

        _validate_event_input(event)
        with self._write_transaction() as connection:
            self._prune_locked(connection)
            return self._insert_event_locked(connection, event)

    def append_events(self, events: Sequence[EventInput]) -> tuple[MobileEvent, ...]:
        """Append a non-empty batch atomically and return events in cursor order."""

        if not isinstance(events, Sequence) or isinstance(events, (str, bytes)):
            raise ValueError("events must be a sequence of EventInput values")
        if not events:
            return ()
        for event in events:
            _validate_event_input(event)
        with self._write_transaction() as connection:
            self._prune_locked(connection)
            return tuple(self._insert_event_locked(connection, event) for event in events)

    def events_since(self, *, after_cursor: int = 0, limit: int = 100) -> EventBacklog:
        """Return retained semantic events after a cursor.

        The cursor is instance-local.  A cursor below the retained floor is
        deliberately not silently truncated: callers must perform a complete
        snapshot sync after receiving :class:`CursorExpired`.
        """

        return self._events_since(after_cursor=after_cursor, limit=limit, allow_expired=False)

    def snapshot_events_since(self, *, after_cursor: int = 0, limit: int = 100) -> EventBacklog:
        """Return the retained event window for a complete snapshot replay.

        Snapshot callers intentionally start below the retained floor after a
        ``cursor_expired`` response.  The result is still bounded and ordered;
        the caller replaces its local projection before applying it.  Canonical
        object/history stores remain the source for data older than the semantic
        event retention window.
        """

        return self._events_since(after_cursor=after_cursor, limit=limit, allow_expired=True)

    def events_for_aggregate(
        self,
        *,
        aggregate_type: str,
        aggregate_id: str,
        limit: int = 100,
    ) -> tuple[MobileEvent, ...]:
        """Return retained events for one aggregate without cursor-floor semantics.

        Aggregate readers are used for detail views such as a single direct-chat
        run. They must not scan a bounded global page: unrelated high-volume
        activity can otherwise hide the target aggregate. They also intentionally
        do not reject an old aggregate when the global retention floor advances;
        callers receive whatever events for that aggregate are still retained.
        """

        aggregate_type = _validate_action(aggregate_type, "aggregate_type")
        aggregate_id = _validate_identifier(aggregate_id, "aggregate_id")
        limit = _validate_limit(limit)
        with self._connection() as connection:
            connection.execute("BEGIN")
            try:
                rows = connection.execute(
                    """
                    SELECT cursor, event_id, event_type, aggregate_type, aggregate_id,
                           payload_json, created_at, tombstone
                    FROM mobile_events
                    WHERE aggregate_type = ? AND aggregate_id = ?
                    ORDER BY cursor ASC
                    LIMIT ?
                    """,
                    (aggregate_type, aggregate_id, limit),
                ).fetchall()
                events = tuple(_event_from_row(row) for row in rows)
                connection.execute("COMMIT")
                return events
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def _events_since(
        self,
        *,
        after_cursor: int,
        limit: int,
        allow_expired: bool,
    ) -> EventBacklog:
        """Read one event page, optionally allowing a snapshot floor reset."""

        after_cursor = _validate_cursor(after_cursor, "after_cursor")
        limit = _validate_limit(limit)
        with self._connection() as connection:
            connection.execute("BEGIN")
            try:
                retained_floor = self._metadata_int(connection, "retained_floor")
                latest_cursor = self._metadata_int(connection, "latest_cursor")
                if after_cursor < retained_floor and not allow_expired:
                    raise CursorExpired(after_cursor, retained_floor, latest_cursor)

                rows = connection.execute(
                    """
                    SELECT cursor, event_id, event_type, aggregate_type, aggregate_id,
                           payload_json, created_at, tombstone
                    FROM mobile_events
                    WHERE cursor > ?
                    ORDER BY cursor ASC
                    LIMIT ?
                    """,
                    (after_cursor, limit + 1),
                ).fetchall()
                has_more = len(rows) > limit
                if has_more:
                    rows = rows[:limit]
                events = tuple(_event_from_row(row) for row in rows)
                connection.execute("COMMIT")
                return EventBacklog(
                    after_cursor=after_cursor,
                    events=events,
                    latest_cursor=latest_cursor,
                    retained_floor=retained_floor,
                    has_more=has_more,
                )
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def reserve_mutation(
        self,
        *,
        actor_id: str,
        action: str,
        key: str,
        body: Any,
    ) -> MutationClaim:
        """Reserve a mutation or return its prior durable decision.

        Only a returned ``MutationClaim`` with ``is_new`` true may be executed.
        Pending and indeterminate claims are intentionally returned without any
        automatic retry; the caller must surface the state or request an
        explicit, separately authorized retry with a new key.
        """

        actor_id = _validate_identifier(actor_id, "actor_id")
        action = _validate_action(action, "action")
        key = _validate_key(key)
        digest = canonical_body_digest(body)
        with self._write_transaction() as connection:
            row = connection.execute(
                """
                SELECT mutation_id, actor_id, action, idempotency_key, body_digest,
                       status, status_code, result_json
                FROM mobile_idempotency
                WHERE actor_id = ? AND action = ? AND idempotency_key = ?
                """,
                (actor_id, action, key),
            ).fetchone()
            if row is not None:
                if row["body_digest"] != digest:
                    raise IdempotencyConflict(actor_id, action, key)
                return _claim_from_row(row)

            mutation_id = uuid.uuid4().hex
            now = _validated_timestamp(self._clock())
            connection.execute(
                """
                INSERT INTO mobile_idempotency (
                    mutation_id, actor_id, action, idempotency_key, body_digest,
                    status, status_code, result_json, owner_pid, owner_token,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?)
                """,
                (
                    mutation_id,
                    actor_id,
                    action,
                    key,
                    digest,
                    MutationStatus.PENDING.value,
                    os.getpid(),
                    _PROCESS_TOKEN,
                    now,
                    now,
                ),
            )
            return MutationClaim(
                mutation_id=mutation_id,
                actor_id=actor_id,
                action=action,
                key=key,
                body_digest=digest,
                status=MutationStatus.NEW,
            )

    def lookup_mutation(
        self,
        *,
        actor_id: str,
        action: str,
        key: str,
    ) -> MutationClaim | None:
        """Read an actor/action/idempotency-key claim without changing state.

        This is intentionally separate from :meth:`reserve_mutation`: a
        recovery/status request must not reserve a new mutation, prune events,
        or fence a pending reservation.  A durable pending row is returned as
        ``MutationStatus.PENDING`` so callers can report what is known without
        attempting execution.
        """

        actor_id = _validate_identifier(actor_id, "actor_id")
        action = _validate_action(action, "action")
        key = _validate_key(key)
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT mutation_id, actor_id, action, idempotency_key, body_digest,
                       status, status_code, result_json
                FROM mobile_idempotency
                WHERE actor_id = ? AND action = ? AND idempotency_key = ?
                """,
                (actor_id, action, key),
            ).fetchone()
            return None if row is None else _claim_from_row(row)

    def complete_mutation(
        self,
        mutation_id: str,
        *,
        result: MutationResult,
        events: Sequence[EventInput] = (),
    ) -> MutationClaim:
        """Commit a successful mutation result and its semantic events atomically."""

        return self._finish_mutation(
            mutation_id,
            result=result,
            events=events,
            final_status=MutationStatus.SUCCEEDED,
        )

    def fail_mutation(
        self,
        mutation_id: str,
        *,
        result: MutationResult,
        events: Sequence[EventInput] = (),
    ) -> MutationClaim:
        """Commit a deterministic failed result and its semantic events atomically."""

        return self._finish_mutation(
            mutation_id,
            result=result,
            events=events,
            final_status=MutationStatus.FAILED,
        )

    def mark_indeterminate(
        self,
        mutation_id: str,
        *,
        reason: str = "uncertain",
        event: EventInput | None = None,
    ) -> MutationClaim:
        """Fence an uncertain mutation so it can never be auto-resubmitted."""

        mutation_id = _validate_identifier(mutation_id, "mutation_id")
        reason = _validate_action(reason, "reason")
        with self._write_transaction() as connection:
            row = self._mutation_row_locked(connection, mutation_id)
            if row is None:
                raise MutationStateError("mutation does not exist")
            status = MutationStatus(row["status"])
            if status is MutationStatus.PENDING:
                indeterminate_event = event or EventInput(
                    event_type="mutation.indeterminate",
                    aggregate_type="mutation",
                    aggregate_id=mutation_id,
                    payload={
                        "mutation_id": mutation_id,
                        "action": row["action"],
                        "reason": reason,
                    },
                )
                _validate_event_input(indeterminate_event)
                self._insert_event_locked(connection, indeterminate_event)
                now = _validated_timestamp(self._clock())
                connection.execute(
                    """
                    UPDATE mobile_idempotency
                    SET status = ?, updated_at = ?
                    WHERE mutation_id = ? AND status = ?
                    """,
                    (
                        MutationStatus.INDETERMINATE.value,
                        now,
                        mutation_id,
                        MutationStatus.PENDING.value,
                    ),
                )
                row = self._mutation_row_locked(connection, mutation_id)
            return _claim_from_row(row)

    def recover_pending_mutations(self) -> int:
        """Mark every pending mutation indeterminate during explicit startup recovery."""

        with self._write_transaction() as connection:
            return self._recover_pending_locked(connection, force=True)

    def prune(self) -> int:
        """Delete semantic events older than the configured retention window."""

        with self._write_transaction() as connection:
            return self._prune_locked(connection)

    def _finish_mutation(
        self,
        mutation_id: str,
        *,
        result: MutationResult,
        events: Sequence[EventInput],
        final_status: MutationStatus,
    ) -> MutationClaim:
        mutation_id = _validate_identifier(mutation_id, "mutation_id")
        _validate_result(result)
        if not isinstance(events, Sequence) or isinstance(events, (str, bytes)):
            raise ValueError("events must be a sequence of EventInput values")
        for event in events:
            _validate_event_input(event)
        result_json = _canonical_json(result.body, field="result.body")
        if len(result_json.encode("utf-8")) > _MAX_RESULT_BODY_BYTES:
            raise ValueError("result.body is too large")

        with self._write_transaction() as connection:
            row = self._mutation_row_locked(connection, mutation_id)
            if row is None:
                raise MutationStateError("mutation does not exist")
            current_status = MutationStatus(row["status"])
            if current_status in {MutationStatus.SUCCEEDED, MutationStatus.FAILED}:
                existing = _result_from_row(row)
                if existing != result or current_status is not final_status:
                    raise MutationStateError("mutation already has a different final result")
                return _claim_from_row(row)
            if current_status is not MutationStatus.PENDING:
                raise MutationStateError(
                    f"cannot complete a mutation in {current_status.value} state"
                )
            if row["owner_pid"] != os.getpid() or row["owner_token"] != _PROCESS_TOKEN:
                raise MutationStateError("mutation reservation belongs to another process")

            self._prune_locked(connection)
            for event in events:
                self._insert_event_locked(connection, event)
            now = _validated_timestamp(self._clock())
            connection.execute(
                """
                UPDATE mobile_idempotency
                SET status = ?, status_code = ?, result_json = ?, updated_at = ?
                WHERE mutation_id = ? AND status = ?
                """,
                (
                    final_status.value,
                    result.status_code,
                    result_json,
                    now,
                    mutation_id,
                    MutationStatus.PENDING.value,
                ),
            )
            row = self._mutation_row_locked(connection, mutation_id)
            return _claim_from_row(row)

    def _initialize(self) -> None:
        with self._write_transaction() as connection:
            for statement in (
                """
                CREATE TABLE IF NOT EXISTS mobile_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS mobile_events (
                    cursor INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    aggregate_type TEXT NOT NULL,
                    aggregate_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    tombstone INTEGER NOT NULL CHECK (tombstone IN (0, 1))
                )
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_mobile_events_aggregate
                    ON mobile_events (aggregate_type, aggregate_id, cursor)
                """,
                """
                CREATE TABLE IF NOT EXISTS mobile_idempotency (
                    mutation_id TEXT PRIMARY KEY,
                    actor_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    body_digest TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('pending', 'succeeded', 'failed', 'indeterminate')
                    ),
                    status_code INTEGER,
                    result_json TEXT,
                    owner_pid INTEGER NOT NULL,
                    owner_token TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    UNIQUE (actor_id, action, idempotency_key)
                )
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_mobile_idempotency_updated
                    ON mobile_idempotency (updated_at)
                """,
            ):
                connection.execute(statement)
            self._ensure_metadata_locked(connection)
            stored_instance_id = self._metadata_text(connection, "instance_id")
            if stored_instance_id is None:
                self._instance_id = self._requested_instance_id or uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO mobile_meta (key, value) VALUES (?, ?)",
                    ("instance_id", self._instance_id),
                )
            else:
                if self._requested_instance_id is not None and stored_instance_id != self._requested_instance_id:
                    raise InstanceIdentityError(
                        "mobile event database belongs to a different instance"
                    )
                self._instance_id = stored_instance_id
            self._recover_pending_locked(connection, force=False)

    def _ensure_metadata_locked(self, connection: sqlite3.Connection) -> None:
        defaults = {
            "schema_version": _SCHEMA_VERSION,
            "retained_floor": "0",
            "latest_cursor": "0",
        }
        for key, value in defaults.items():
            connection.execute(
                "INSERT OR IGNORE INTO mobile_meta (key, value) VALUES (?, ?)",
                (key, value),
            )
        version = self._metadata_text(connection, "schema_version")
        if version != _SCHEMA_VERSION:
            raise MobileEventStoreError(f"unsupported mobile event schema version {version!r}")

    def _recover_pending_locked(self, connection: sqlite3.Connection, *, force: bool) -> int:
        if force:
            rows = connection.execute(
                """
                SELECT mutation_id, action
                FROM mobile_idempotency
                WHERE status = ?
                ORDER BY created_at ASC
                """,
                (MutationStatus.PENDING.value,),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT mutation_id, action
                FROM mobile_idempotency
                WHERE status = ? AND (owner_pid <> ? OR owner_token <> ?)
                ORDER BY created_at ASC
                """,
                (MutationStatus.PENDING.value, os.getpid(), _PROCESS_TOKEN),
            ).fetchall()
        count = 0
        now = _validated_timestamp(self._clock())
        for row in rows:
            mutation_id = row["mutation_id"]
            connection.execute(
                """
                UPDATE mobile_idempotency
                SET status = ?, updated_at = ?
                WHERE mutation_id = ? AND status = ?
                """,
                (
                    MutationStatus.INDETERMINATE.value,
                    now,
                    mutation_id,
                    MutationStatus.PENDING.value,
                ),
            )
            self._insert_event_locked(
                connection,
                EventInput(
                    event_type="mutation.indeterminate",
                    aggregate_type="mutation",
                    aggregate_id=mutation_id,
                    payload={
                        "mutation_id": mutation_id,
                        "action": row["action"],
                        "reason": "process_restart",
                    },
                ),
            )
            count += 1
        return count

    def _prune_locked(self, connection: sqlite3.Connection) -> int:
        cutoff = _validated_timestamp(self._clock()) - self._retention_seconds
        row = connection.execute(
            "SELECT MAX(cursor) AS max_cursor FROM mobile_events WHERE created_at < ?",
            (cutoff,),
        ).fetchone()
        max_cursor = row["max_cursor"] if row is not None else None
        if max_cursor is None:
            return 0
        deleted = connection.execute(
            "DELETE FROM mobile_events WHERE created_at < ?",
            (cutoff,),
        ).rowcount
        floor = self._metadata_int(connection, "retained_floor")
        if max_cursor > floor:
            connection.execute(
                "UPDATE mobile_meta SET value = ? WHERE key = 'retained_floor'",
                (str(max_cursor),),
            )
        return int(deleted)

    def _insert_event_locked(
        self,
        connection: sqlite3.Connection,
        event: EventInput,
    ) -> MobileEvent:
        event_id = event.event_id or uuid.uuid4().hex
        if event.event_id is not None:
            _validate_identifier(event.event_id, "event_id")
        payload_json = _canonical_json(event.payload, field="event.payload")
        if len(payload_json.encode("utf-8")) > _MAX_EVENT_PAYLOAD_BYTES:
            raise ValueError("event.payload is too large")
        created_at = _validated_timestamp(event.created_at if event.created_at is not None else self._clock())
        try:
            cursor = connection.execute(
                """
                INSERT INTO mobile_events (
                    event_id, event_type, aggregate_type, aggregate_id,
                    payload_json, created_at, tombstone
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    event.event_type,
                    event.aggregate_type,
                    event.aggregate_id,
                    payload_json,
                    created_at,
                    int(event.tombstone),
                ),
            ).lastrowid
        except sqlite3.IntegrityError as exc:
            if "event_id" in str(exc).lower() or "unique" in str(exc).lower():
                raise DuplicateEventError("event_id already exists") from exc
            raise
        if cursor is None:
            raise MobileEventStoreError("SQLite did not return an event cursor")
        connection.execute(
            "UPDATE mobile_meta SET value = ? WHERE key = 'latest_cursor'",
            (str(cursor),),
        )
        return MobileEvent(
            cursor=int(cursor),
            event_id=event_id,
            event_type=event.event_type,
            aggregate_type=event.aggregate_type,
            aggregate_id=event.aggregate_id,
            payload=json.loads(payload_json),
            created_at=created_at,
            tombstone=bool(event.tombstone),
        )

    def _mutation_row_locked(
        self,
        connection: sqlite3.Connection,
        mutation_id: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT mutation_id, actor_id, action, idempotency_key, body_digest,
                   status, status_code, result_json, owner_pid, owner_token
            FROM mobile_idempotency
            WHERE mutation_id = ?
            """,
            (mutation_id,),
        ).fetchone()

    def _metadata_text(self, connection: sqlite3.Connection, key: str) -> str | None:
        row = connection.execute(
            "SELECT value FROM mobile_meta WHERE key = ?",
            (key,),
        ).fetchone()
        return None if row is None else str(row["value"])

    def _metadata_int(self, connection: sqlite3.Connection, key: str) -> int:
        value = self._metadata_text(connection, key)
        if value is None:
            raise MobileEventStoreError(f"missing mobile metadata {key!r}")
        try:
            return int(value)
        except ValueError as exc:
            raise MobileEventStoreError(f"invalid mobile metadata {key!r}") from exc

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            self._db_path,
            timeout=self._timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute(f"PRAGMA busy_timeout = {max(1, int(self._timeout_seconds * 1000))}")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _write_transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise


def _event_from_row(row: sqlite3.Row) -> MobileEvent:
    return MobileEvent(
        cursor=int(row["cursor"]),
        event_id=str(row["event_id"]),
        event_type=str(row["event_type"]),
        aggregate_type=str(row["aggregate_type"]),
        aggregate_id=str(row["aggregate_id"]),
        payload=json.loads(str(row["payload_json"])),
        created_at=float(row["created_at"]),
        tombstone=bool(row["tombstone"]),
    )


def _result_from_row(row: sqlite3.Row) -> MutationResult | None:
    if row["status_code"] is None or row["result_json"] is None:
        return None
    return MutationResult(
        status_code=int(row["status_code"]),
        body=json.loads(str(row["result_json"])),
    )


def _claim_from_row(row: sqlite3.Row) -> MutationClaim:
    status = MutationStatus(row["status"])
    return MutationClaim(
        mutation_id=str(row["mutation_id"]),
        actor_id=str(row["actor_id"]),
        action=str(row["action"]),
        key=str(row["idempotency_key"]),
        body_digest=str(row["body_digest"]),
        status=status,
        result=_result_from_row(row),
    )


def _validate_event_input(event: EventInput) -> None:
    if not isinstance(event, EventInput):
        raise ValueError("event must be an EventInput")
    _validate_action(event.event_type, "event_type")
    _validate_action(event.aggregate_type, "aggregate_type")
    _validate_identifier(event.aggregate_id, "aggregate_id")
    if not isinstance(event.payload, Mapping):
        raise ValueError("event.payload must be a JSON object")
    if event.event_id is not None:
        _validate_identifier(event.event_id, "event_id")
    if event.created_at is not None:
        _validated_timestamp(event.created_at)


def _validate_result(result: MutationResult) -> None:
    if not isinstance(result, MutationResult):
        raise ValueError("result must be a MutationResult")
    if not isinstance(result.status_code, int) or isinstance(result.status_code, bool):
        raise ValueError("result.status_code must be an integer")
    if not 100 <= result.status_code <= 599:
        raise ValueError("result.status_code must be between 100 and 599")


def _validate_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_IDENTIFIER_LENGTH:
        raise ValueError(f"{field} must be a non-empty string of at most {_MAX_IDENTIFIER_LENGTH} characters")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ValueError(f"{field} contains a control character")
    return value


def _validate_action(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _TOKEN_RE.fullmatch(value):
        raise ValueError(f"{field} must be an ASCII token")
    return value


def _validate_key(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_IDEMPOTENCY_KEY_LENGTH:
        raise ValueError(
            f"key must be a non-empty string of at most {_MAX_IDEMPOTENCY_KEY_LENGTH} characters"
        )
    if any(ord(char) < 0x21 or ord(char) > 0x7E for char in value):
        raise ValueError("key must contain printable ASCII characters only")
    return value


def _validate_cursor(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _validate_limit(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= _MAX_BACKLOG_LIMIT:
        raise ValueError(f"limit must be an integer between 1 and {_MAX_BACKLOG_LIMIT}")
    return value


def _validated_timestamp(value: Any) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        raise ValueError("timestamp must be a finite number")
    return float(value)


def _canonical_json(value: Any, *, field: str) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be valid JSON") from exc
    return encoded
