"""Durable control plane for existing Hermes routines.

Mobile may inspect, pause, resume, and explicitly run a host-owned routine.
The service never accepts a routine definition from the phone and never
persists the routine's command/tool internals.  A run is a fenced reservation;
execution is performed by a host worker that later calls ``complete`` or
``fail`` with the returned claim.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import time
from typing import Any, Literal
from uuid import UUID, uuid4


_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$")
_STATUSES = frozenset({"pending", "completed", "failed", "indeterminate", "cancelled"})
_MAX_RESULT_BYTES = 256_000


class RoutineError(RuntimeError):
    """Base class for mobile routine control errors."""


class RoutineNotFound(RoutineError, LookupError):
    """The routine or run is outside the caller's profile scope."""


class RoutineConflict(RoutineError):
    """The routine revision, idempotency body, or execution fence is stale."""


class RoutineForbidden(RoutineError, PermissionError):
    """The host policy does not permit the requested routine operation."""


class RoutineStepUpRequired(RoutineForbidden):
    """A run lacks the required user-presence proof."""


class RoutineAlreadyRunning(RoutineError):
    """An identical side effect is already reserved and cannot be replayed."""


class RoutineIndeterminate(RoutineError):
    """The prior side effect may have happened; no automatic resubmission occurs."""


class RoutineLeaseExpired(RoutineError):
    """The worker's execution lease has expired."""


@dataclass(frozen=True, slots=True)
class RoutineDefinition:
    routine_id: str
    profile_id: str
    label: str
    summary: str

    def __post_init__(self) -> None:
        try:
            UUID(self.routine_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("routine_id must be an opaque UUID") from exc
        if not _TOKEN.fullmatch(self.profile_id):
            raise ValueError("invalid routine profile")
        if not isinstance(self.label, str) or not self.label or len(self.label) > 160:
            raise ValueError("invalid routine label")
        if not isinstance(self.summary, str) or len(self.summary) > 512:
            raise ValueError("invalid routine summary")


@dataclass(frozen=True, slots=True)
class RoutineSnapshot:
    routine_id: str
    profile_id: str
    label: str
    summary: str
    paused: bool
    revision: int
    etag: str


@dataclass(frozen=True, slots=True)
class RoutineRun:
    run_id: str
    routine_id: str
    profile_id: str
    actor_id: str
    idempotency_key: str
    body_digest: str
    status: Literal["pending", "completed", "failed", "indeterminate", "cancelled"]
    execution_generation: int
    fence_token: str
    lease_expires_at: float
    result: Any | None = None
    # Set atomically when the host worker is about to cross the external
    # executor boundary.  Cancellation before this marker is a deterministic
    # cancel; cancellation after it must become indeterminate.
    started_at: float | None = None


def _canonical(value: Any) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("routine request must be JSON data") from exc
    if len(encoded.encode("utf-8")) > _MAX_RESULT_BYTES:
        raise ValueError("routine request or result is too large")
    return encoded


def body_digest(body: Any) -> str:
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


def run_context(
    *, instance_id: str, profile_id: str, routine_id: str, idempotency_key: str, body: Any
) -> dict[str, Any]:
    return {
        "action": "routines.run",
        "instance_id": instance_id,
        "profile_id": profile_id,
        "routine_id": routine_id,
        "idempotency_key": idempotency_key,
        "body_digest": body_digest(body),
    }


class MobileRoutineService:
    """Server-owned routine registry and durable run state machine."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        instance_id: str,
        profile_allowlist: Iterable[str],
        routines: Iterable[RoutineDefinition],
        step_up: Any | None = None,
        clock=time.time,
        lease_seconds: float = 120.0,
        recover_on_start: bool = False,
    ) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._instance_id = self._token(instance_id, "instance identifier")
        self._profiles = frozenset(self._token(value, "profile identifier") for value in profile_allowlist)
        if not isinstance(lease_seconds, (int, float)) or not 1 <= lease_seconds <= 3_600:
            raise ValueError("lease_seconds is invalid")
        self._lease_seconds = float(lease_seconds)
        self._step_up = step_up
        self._clock = clock
        definitions = tuple(routines)
        if any(not isinstance(item, RoutineDefinition) for item in definitions):
            raise TypeError("routines must contain RoutineDefinition values")
        if any(item.profile_id not in self._profiles for item in definitions):
            raise RoutineNotFound("routine profile is outside the mobile scope")
        ids = [item.routine_id for item in definitions]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate routine identifier")
        self._definitions = {item.routine_id: item for item in definitions}
        self._initialize()
        self._ensure_definitions(definitions)
        if recover_on_start:
            self.recover_uncertain()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, isolation_level=None, timeout=10, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS mobile_routine_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS mobile_routine_state (
                    routine_id TEXT PRIMARY KEY,
                    profile_id TEXT NOT NULL,
                    label TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    paused INTEGER NOT NULL CHECK (paused IN (0, 1)),
                    revision INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS mobile_routine_runs (
                    run_id TEXT PRIMARY KEY,
                    routine_id TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    body_digest TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('pending','completed','failed','indeterminate','cancelled')),
                    execution_generation INTEGER NOT NULL,
                    fence_token TEXT NOT NULL,
                    lease_expires_at REAL NOT NULL,
                    result_json TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    started_at REAL,
                    UNIQUE (routine_id, actor_id, idempotency_key)
                );
                CREATE TABLE IF NOT EXISTS mobile_routine_audit (
                    audit_id TEXT PRIMARY KEY,
                    routine_id TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    run_id TEXT,
                    body_digest TEXT,
                    created_at REAL NOT NULL
                );
                """
            )
            # Databases created by the first mobile-routines implementation do
            # not have the worker-boundary marker.  Add it in place so an
            # upgrade cannot silently retain the cancellation race.
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(mobile_routine_runs)")
            }
            if "started_at" not in columns:
                connection.execute("ALTER TABLE mobile_routine_runs ADD COLUMN started_at REAL")
            row = connection.execute(
                "SELECT value FROM mobile_routine_meta WHERE key = 'instance_id'"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO mobile_routine_meta VALUES ('instance_id', ?)", (self._instance_id,)
                )
            elif row[0] != self._instance_id:
                raise RoutineConflict("routine database belongs to another Hermes instance")

    def _ensure_definitions(self, definitions: tuple[RoutineDefinition, ...]) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for definition in definitions:
                row = connection.execute(
                    "SELECT profile_id, label, summary FROM mobile_routine_state WHERE routine_id = ?",
                    (definition.routine_id,),
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO mobile_routine_state VALUES (?, ?, ?, ?, 0, 1)",
                        (
                            definition.routine_id,
                            definition.profile_id,
                            definition.label,
                            definition.summary,
                        ),
                    )
                elif (
                    row["profile_id"] != definition.profile_id
                    or row["label"] != definition.label
                    or row["summary"] != definition.summary
                ):
                    connection.rollback()
                    raise RoutineConflict("routine definition changed outside the host registry")
            connection.commit()

    def get(self, profile_id: str, routine_id: str) -> RoutineSnapshot:
        profile_id = self._require_profile(profile_id)
        routine_id = self._opaque_id(routine_id)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM mobile_routine_state WHERE routine_id = ? AND profile_id = ?",
                (routine_id, profile_id),
            ).fetchone()
        if row is None:
            raise RoutineNotFound("routine not found")
        return self._snapshot(row)

    def routines(self, profile_id: str) -> tuple[RoutineDefinition, ...]:
        profile_id = self._require_profile(profile_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT routine_id, profile_id, label, summary FROM mobile_routine_state "
                "WHERE profile_id = ? ORDER BY routine_id",
                (profile_id,),
            ).fetchall()
        return tuple(RoutineDefinition(row[0], row[1], row[2], row[3]) for row in rows)

    def definition(self, profile_id: str, routine_id: str) -> RoutineDefinition:
        """Return the host-owned definition for one authorized routine.

        The definition is intentionally limited to server-controlled metadata.  Mobile input is
        never folded into it and callers must provide their own trusted executor when a run is
        dispatched.
        """

        profile_id = self._require_profile(profile_id)
        routine_id = self._opaque_id(routine_id)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT routine_id, profile_id, label, summary FROM mobile_routine_state "
                "WHERE routine_id = ? AND profile_id = ?",
                (routine_id, profile_id),
            ).fetchone()
        if row is None:
            raise RoutineNotFound("routine not found")
        return RoutineDefinition(row[0], row[1], row[2], row[3])

    @property
    def lease_seconds(self) -> float:
        """The configured reservation lease used by a host worker."""

        return self._lease_seconds

    def run_context(self, profile_id: str, routine_id: str, idempotency_key: str, *, body: Any) -> dict[str, Any]:
        profile_id = self._require_profile(profile_id)
        routine_id = self._opaque_id(routine_id)
        self.get(profile_id, routine_id)
        idempotency_key = self._key(idempotency_key)
        return run_context(
            instance_id=self._instance_id,
            profile_id=profile_id,
            routine_id=routine_id,
            idempotency_key=idempotency_key,
            body=body,
        )

    def run(
        self,
        profile_id: str,
        routine_id: str,
        *,
        actor_id: str,
        idempotency_key: str,
        body: Any,
        challenge: Any,
        signature: str,
        context: Mapping[str, Any],
    ) -> RoutineRun:
        profile_id = self._require_profile(profile_id)
        routine_id = self._opaque_id(routine_id)
        actor_id = self._token(actor_id, "actor identifier")
        idempotency_key = self._key(idempotency_key)
        snapshot = self.get(profile_id, routine_id)
        if snapshot.paused:
            raise RoutineForbidden("routine is paused")
        digest = body_digest(body)
        expected = run_context(
            instance_id=self._instance_id,
            profile_id=profile_id,
            routine_id=routine_id,
            idempotency_key=idempotency_key,
            body=body,
        )
        if dict(context) != expected:
            raise RoutineStepUpRequired("run step-up context does not match")
        self._verify_step_up(challenge, signature, expected)
        now = float(self._clock())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM mobile_routine_runs WHERE routine_id = ? AND actor_id = ? "
                "AND idempotency_key = ?",
                (routine_id, actor_id, idempotency_key),
            ).fetchone()
            if row is not None:
                if row["body_digest"] != digest:
                    connection.rollback()
                    raise RoutineConflict("idempotency key conflicts with another body")
                status = row["status"]
                connection.rollback()
                if status == "pending":
                    raise RoutineAlreadyRunning("routine execution is already reserved")
                if status == "indeterminate":
                    raise RoutineIndeterminate("routine execution is indeterminate")
                return self._run_from_row(row)
            generation_row = connection.execute(
                "SELECT COALESCE(MAX(execution_generation), 0) + 1 FROM mobile_routine_runs "
                "WHERE routine_id = ?",
                (routine_id,),
            ).fetchone()
            generation = int(generation_row[0])
            run_id = str(uuid4())
            fence_token = str(uuid4())
            lease_expires = now + self._lease_seconds
            connection.execute(
                "INSERT INTO mobile_routine_runs "
                "(run_id, routine_id, profile_id, actor_id, idempotency_key, body_digest, "
                "status, execution_generation, fence_token, lease_expires_at, result_json, "
                "created_at, updated_at, started_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, NULL, ?, ?, NULL)",
                (
                    run_id,
                    routine_id,
                    profile_id,
                    actor_id,
                    idempotency_key,
                    digest,
                    generation,
                    fence_token,
                    lease_expires,
                    now,
                    now,
                ),
            )
            self._audit_locked(
                connection,
                routine_id=routine_id,
                profile_id=profile_id,
                actor_id=actor_id,
                action="routine.run.reserved",
                run_id=run_id,
                body_digest=digest,
                now=now,
            )
            row = connection.execute(
                "SELECT * FROM mobile_routine_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            connection.commit()
        return self._run_from_row(row)

    def begin_execution(
        self,
        run_id: str,
        *,
        actor_id: str,
        execution_generation: int,
        fence_token: str,
    ) -> RoutineRun:
        """Claim the external-executor boundary for one reserved run.

        The reservation itself is not enough to distinguish a queued run from
        a worker that may already have caused an external side effect.  This
        durable marker lets cancellation make that distinction atomically:
        before ``started_at`` a run may be cancelled; after it, cancellation
        fences the run as indeterminate.
        """

        run_id = self._opaque_id(run_id)
        actor_id = self._token(actor_id, "actor identifier")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._run_row(connection, run_id)
            self._check_fence(row, actor_id, execution_generation, fence_token)
            if row["status"] != "pending":
                connection.rollback()
                raise RoutineConflict("routine run is no longer pending")
            if row["started_at"] is not None:
                connection.rollback()
                raise RoutineConflict("routine run execution was already claimed")
            now = float(self._clock())
            connection.execute(
                "UPDATE mobile_routine_runs SET started_at = ?, lease_expires_at = ?, updated_at = ? "
                "WHERE run_id = ? AND status = 'pending' AND started_at IS NULL",
                (now, now + self._lease_seconds, now, run_id),
            )
            self._audit_locked(
                connection,
                routine_id=row["routine_id"],
                profile_id=row["profile_id"],
                actor_id=actor_id,
                action="routine.run.started",
                run_id=run_id,
                body_digest=row["body_digest"],
                now=now,
            )
            row = self._run_row(connection, run_id)
            connection.commit()
        return self._run_from_row(row)

    def complete(
        self,
        run_id: str,
        *,
        actor_id: str,
        result: Any,
        execution_generation: int | None = None,
        fence_token: str | None = None,
    ) -> RoutineRun:
        return self._finish(
            run_id,
            actor_id=actor_id,
            result=result,
            status="completed",
            execution_generation=execution_generation,
            fence_token=fence_token,
        )

    def fail(
        self,
        run_id: str,
        *,
        actor_id: str,
        result: Any,
        execution_generation: int | None = None,
        fence_token: str | None = None,
    ) -> RoutineRun:
        return self._finish(
            run_id,
            actor_id=actor_id,
            result=result,
            status="failed",
            execution_generation=execution_generation,
            fence_token=fence_token,
        )

    def cancel(self, run_id: str, *, actor_id: str) -> RoutineRun:
        actor_id = self._token(actor_id, "actor identifier")
        run_id = self._opaque_id(run_id)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._run_row(connection, run_id)
            if row is None or row["actor_id"] != actor_id:
                connection.rollback()
                raise RoutineNotFound("routine run not found")
            if row["status"] != "pending":
                connection.rollback()
                raise RoutineConflict("routine run is no longer pending")
            now = float(self._clock())
            if row["started_at"] is not None:
                # The worker may already be inside the host executor.  Do not
                # report a clean cancellation when that side effect's outcome
                # is unknown; fence it and require explicit reconciliation.
                connection.execute(
                    "UPDATE mobile_routine_runs SET status = 'indeterminate', updated_at = ? "
                    "WHERE run_id = ? AND status = 'pending'",
                    (now, run_id),
                )
                self._audit_locked(
                    connection,
                    routine_id=row["routine_id"],
                    profile_id=row["profile_id"],
                    actor_id=actor_id,
                    action="routine.run.indeterminate.cancel_race",
                    run_id=run_id,
                    body_digest=row["body_digest"],
                    now=now,
                )
                row = self._run_row(connection, run_id)
                connection.commit()
                return self._run_from_row(row)
            connection.execute(
                "UPDATE mobile_routine_runs SET status = 'cancelled', updated_at = ? "
                "WHERE run_id = ? AND status = 'pending'",
                (now, run_id),
            )
            self._audit_locked(
                connection,
                routine_id=row["routine_id"],
                profile_id=row["profile_id"],
                actor_id=actor_id,
                action="routine.run.cancelled",
                run_id=run_id,
                body_digest=row["body_digest"],
                now=now,
            )
            row = self._run_row(connection, run_id)
            connection.commit()
        return self._run_from_row(row)

    def get_run(self, run_id: str) -> RoutineRun:
        run_id = self._opaque_id(run_id)
        with self._connect() as connection:
            row = self._run_row(connection, run_id)
        if row is None or row["profile_id"] not in self._profiles:
            raise RoutineNotFound("routine run not found")
        return self._run_from_row(row)

    def renew(
        self,
        run_id: str,
        *,
        actor_id: str,
        execution_generation: int,
        fence_token: str,
    ) -> RoutineRun:
        run_id = self._opaque_id(run_id)
        actor_id = self._token(actor_id, "actor identifier")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._run_row(connection, run_id)
            self._check_fence(row, actor_id, execution_generation, fence_token)
            now = float(self._clock())
            if row["lease_expires_at"] <= now:
                connection.rollback()
                raise RoutineLeaseExpired("routine execution lease expired")
            connection.execute(
                "UPDATE mobile_routine_runs SET lease_expires_at = ?, updated_at = ? WHERE run_id = ?",
                (now + self._lease_seconds, now, run_id),
            )
            row = self._run_row(connection, run_id)
            connection.commit()
        return self._run_from_row(row)

    def mark_indeterminate(self, run_id: str, *, reason: str = "uncertain") -> RoutineRun:
        run_id = self._opaque_id(run_id)
        if not isinstance(reason, str) or not _TOKEN.fullmatch(reason):
            raise ValueError("invalid indeterminate reason")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._run_row(connection, run_id)
            if row is None or row["profile_id"] not in self._profiles:
                connection.rollback()
                raise RoutineNotFound("routine run not found")
            if row["status"] == "pending":
                now = float(self._clock())
                connection.execute(
                    "UPDATE mobile_routine_runs SET status = 'indeterminate', updated_at = ? "
                    "WHERE run_id = ? AND status = 'pending'",
                    (now, run_id),
                )
                self._audit_locked(
                    connection,
                    routine_id=row["routine_id"],
                    profile_id=row["profile_id"],
                    actor_id=row["actor_id"],
                    action=f"routine.run.indeterminate.{reason}",
                    run_id=run_id,
                    body_digest=row["body_digest"],
                    now=now,
                )
                row = self._run_row(connection, run_id)
            connection.commit()
        return self._run_from_row(row)

    def recover_uncertain(self) -> int:
        """Fence every pending run after a process restart; never retry it."""

        count = 0
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT * FROM mobile_routine_runs WHERE status = 'pending'"
            ).fetchall()
            now = float(self._clock())
            for row in rows:
                connection.execute(
                    "UPDATE mobile_routine_runs SET status = 'indeterminate', updated_at = ? "
                    "WHERE run_id = ? AND status = 'pending'",
                    (now, row["run_id"]),
                )
                self._audit_locked(
                    connection,
                    routine_id=row["routine_id"],
                    profile_id=row["profile_id"],
                    actor_id=row["actor_id"],
                    action="routine.run.indeterminate.restart",
                    run_id=row["run_id"],
                    body_digest=row["body_digest"],
                    now=now,
                )
                count += 1
            connection.commit()
        return count

    def pause(self, profile_id: str, routine_id: str, *, actor_id: str, if_match: str) -> RoutineSnapshot:
        return self._set_paused(profile_id, routine_id, actor_id=actor_id, if_match=if_match, paused=True)

    def resume(self, profile_id: str, routine_id: str, *, actor_id: str, if_match: str) -> RoutineSnapshot:
        return self._set_paused(profile_id, routine_id, actor_id=actor_id, if_match=if_match, paused=False)

    def _set_paused(
        self, profile_id: str, routine_id: str, *, actor_id: str, if_match: str, paused: bool
    ) -> RoutineSnapshot:
        profile_id = self._require_profile(profile_id)
        routine_id = self._opaque_id(routine_id)
        actor_id = self._token(actor_id, "actor identifier")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM mobile_routine_state WHERE routine_id = ? AND profile_id = ?",
                (routine_id, profile_id),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise RoutineNotFound("routine not found")
            expected = self._etag(row["revision"])
            if if_match != expected:
                connection.rollback()
                raise RoutineConflict("If-Match does not identify the current routine revision")
            if bool(row["paused"]) == paused:
                connection.rollback()
                return self._snapshot(row)
            revision = int(row["revision"]) + 1
            now = float(self._clock())
            connection.execute(
                "UPDATE mobile_routine_state SET paused = ?, revision = ? WHERE routine_id = ?",
                (int(paused), revision, routine_id),
            )
            self._audit_locked(
                connection,
                routine_id=routine_id,
                profile_id=profile_id,
                actor_id=actor_id,
                action="routine.paused" if paused else "routine.resumed",
                run_id=None,
                body_digest=None,
                now=now,
            )
            row = connection.execute(
                "SELECT * FROM mobile_routine_state WHERE routine_id = ?", (routine_id,)
            ).fetchone()
            connection.commit()
        return self._snapshot(row)

    def _finish(
        self,
        run_id: str,
        *,
        actor_id: str,
        result: Any,
        status: Literal["completed", "failed"],
        execution_generation: int | None,
        fence_token: str | None,
    ) -> RoutineRun:
        run_id = self._opaque_id(run_id)
        actor_id = self._token(actor_id, "actor identifier")
        encoded = _canonical(result)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._run_row(connection, run_id)
            self._check_fence(row, actor_id, execution_generation, fence_token)
            if row["status"] != "pending":
                connection.rollback()
                if row["status"] == "indeterminate":
                    raise RoutineIndeterminate("routine execution is indeterminate")
                raise RoutineConflict("routine run is no longer pending")
            now = float(self._clock())
            if row["lease_expires_at"] <= now:
                connection.rollback()
                raise RoutineLeaseExpired("routine execution lease expired")
            connection.execute(
                "UPDATE mobile_routine_runs SET status = ?, result_json = ?, updated_at = ? "
                "WHERE run_id = ? AND status = 'pending'",
                (status, encoded, now, run_id),
            )
            self._audit_locked(
                connection,
                routine_id=row["routine_id"],
                profile_id=row["profile_id"],
                actor_id=actor_id,
                action=f"routine.run.{status}",
                run_id=run_id,
                body_digest=row["body_digest"],
                now=now,
            )
            row = self._run_row(connection, run_id)
            connection.commit()
        return self._run_from_row(row)

    def _verify_step_up(self, challenge: Any, signature: str, expected: Mapping[str, Any]) -> None:
        if self._step_up is None or challenge is None or not isinstance(signature, str):
            raise RoutineStepUpRequired("routine runs require user presence")
        challenge_context = getattr(challenge, "context", None)
        if challenge_context is not None and dict(challenge_context) != dict(expected):
            raise RoutineStepUpRequired("routine run step-up context is invalid")
        try:
            self._step_up.verify(challenge, context=expected, signature=signature, now=float(self._clock()))
        except Exception as exc:
            raise RoutineStepUpRequired("routine run step-up is invalid") from exc

    @staticmethod
    def _run_row(connection: sqlite3.Connection, run_id: str) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM mobile_routine_runs WHERE run_id = ?", (run_id,)
        ).fetchone()

    @staticmethod
    def _check_fence(
        row: sqlite3.Row | None,
        actor_id: str,
        execution_generation: int | None,
        fence_token: str | None,
    ) -> None:
        if row is None or row["actor_id"] != actor_id:
            raise RoutineNotFound("routine run not found")
        if row["status"] != "pending":
            raise RoutineConflict("routine run is no longer executable")
        if execution_generation is not None and execution_generation != row["execution_generation"]:
            raise RoutineConflict("execution generation fence was lost")
        if fence_token is not None and fence_token != row["fence_token"]:
            raise RoutineConflict("execution fence was lost")

    @staticmethod
    def _snapshot(row: sqlite3.Row) -> RoutineSnapshot:
        return RoutineSnapshot(
            row["routine_id"],
            row["profile_id"],
            row["label"],
            row["summary"],
            bool(row["paused"]),
            row["revision"],
            f'"routine-{row["revision"]}"',
        )

    @staticmethod
    def _run_from_row(row: sqlite3.Row) -> RoutineRun:
        return RoutineRun(
            run_id=row["run_id"],
            routine_id=row["routine_id"],
            profile_id=row["profile_id"],
            actor_id=row["actor_id"],
            idempotency_key=row["idempotency_key"],
            body_digest=row["body_digest"],
            status=row["status"],
            execution_generation=row["execution_generation"],
            fence_token=row["fence_token"],
            lease_expires_at=row["lease_expires_at"],
            result=None if row["result_json"] is None else json.loads(row["result_json"]),
            started_at=row["started_at"],
        )

    def _audit_locked(
        self,
        connection: sqlite3.Connection,
        *,
        routine_id: str,
        profile_id: str,
        actor_id: str,
        action: str,
        run_id: str | None,
        body_digest: str | None,
        now: float,
    ) -> None:
        connection.execute(
            "INSERT INTO mobile_routine_audit VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid4()), routine_id, profile_id, actor_id, action, run_id, body_digest, now),
        )

    def _require_profile(self, value: str) -> str:
        value = self._token(value, "profile identifier")
        if value not in self._profiles:
            raise RoutineNotFound("routine not found")
        return value

    @staticmethod
    def _opaque_id(value: str) -> str:
        try:
            UUID(value)
        except (TypeError, ValueError) as exc:
            raise RoutineNotFound("routine not found") from exc
        return value

    @staticmethod
    def _token(value: str, field: str) -> str:
        if not isinstance(value, str) or not _TOKEN.fullmatch(value):
            raise ValueError(f"invalid {field}")
        return value

    @staticmethod
    def _key(value: str) -> str:
        if not isinstance(value, str) or not _KEY.fullmatch(value):
            raise ValueError("invalid idempotency key")
        return value

    @staticmethod
    def _etag(revision: int) -> str:
        return f'"routine-{revision}"'
