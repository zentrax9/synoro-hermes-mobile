"""Durable, narrow approval decisions for Hermes Mobile.

An approval is a one-time decision over an exact server-built context.  The
mobile surface never receives tool arguments, credential status, or command
internals; it receives opaque correlation IDs and a redacted summary chosen by
the host.
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
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_DECISIONS = frozenset({"approve_once", "deny"})
_MAX_SUMMARY = 2_000
_MAX_TTL = 600.0


class ApprovalError(RuntimeError):
    """Base class for safe mobile approval errors."""


class ApprovalNotFound(ApprovalError, LookupError):
    """The approval is outside the caller's profile scope."""


class ApprovalConflict(ApprovalError):
    """The supplied approval context differs from the durable request."""


class ApprovalAlreadyResolved(ApprovalError):
    """A pending approval was already decided or consumed."""


class ApprovalExpired(ApprovalError):
    """The approval's short validity window has elapsed."""


class ApprovalStepUpRequired(ApprovalError, PermissionError):
    """An approve-once decision lacks valid user-presence proof."""


@dataclass(frozen=True, slots=True)
class ApprovalContext:
    instance_id: str
    profile_id: str
    session_id: str
    run_id: str
    tool_call_id: str
    request_id: str
    arguments_digest: str
    expires_at: float

    def __post_init__(self) -> None:
        for field in (
            "instance_id",
            "profile_id",
            "session_id",
            "run_id",
            "tool_call_id",
            "request_id",
        ):
            value = getattr(self, field)
            if not isinstance(value, str) or not _TOKEN.fullmatch(value):
                raise ValueError(f"invalid approval {field}")
        if not isinstance(self.arguments_digest, str) or not _DIGEST.fullmatch(self.arguments_digest):
            raise ValueError("invalid approval arguments digest")
        if not isinstance(self.expires_at, (int, float)) or self.expires_at <= 0:
            raise ValueError("invalid approval expiry")

    def as_dict(self) -> dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "profile_id": self.profile_id,
            "session_id": self.session_id,
            "run_id": self.run_id,
            "tool_call_id": self.tool_call_id,
            "request_id": self.request_id,
            "arguments_digest": self.arguments_digest,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    approval_id: str
    actor_id: str
    context: ApprovalContext
    summary: str
    status: Literal["pending", "approved", "denied", "consumed", "expired"]
    created_at: float
    resolved_at: float | None = None
    resolved_by: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "actor_id": self.actor_id,
            "context": self.context.as_dict(),
            "summary": self.summary,
            "status": self.status,
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
            "resolved_by": self.resolved_by,
        }


@dataclass(frozen=True, slots=True)
class ApprovalAudit:
    audit_id: str
    approval_id: str
    profile_id: str
    actor_id: str
    action: str
    context_digest: str
    created_at: float


def _canonical(value: Any) -> str:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("approval value must be JSON data") from exc
    if len(encoded.encode("utf-8")) > 32_768:
        raise ValueError("approval value is too large")
    return encoded


def approval_context_digest(context: ApprovalContext | Mapping[str, Any]) -> str:
    value = context.as_dict() if isinstance(context, ApprovalContext) else dict(context)
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def step_up_context(approval: ApprovalRecord | Mapping[str, Any]) -> dict[str, Any]:
    """Build the exact signed context for approve-once."""

    if isinstance(approval, ApprovalRecord):
        approval_id = approval.approval_id
        context = approval.context
    else:
        approval_id = str(approval["approval_id"])
        context = approval["context"]
        if not isinstance(context, ApprovalContext):
            context = ApprovalContext(**dict(context))
    return {
        "action": "approvals.approve_once",
        "approval_id": approval_id,
        **context.as_dict(),
    }


def _token(value: str, field: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise ValueError(f"invalid {field}")
    return value


class MobileApprovalStore:
    """SQLite-backed approval state machine with durable single-use decisions."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        instance_id: str,
        profile_allowlist: Iterable[str],
        step_up: Any | None = None,
        clock=time.time,
        max_ttl_seconds: float = _MAX_TTL,
    ) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._instance_id = _token(instance_id, "instance identifier")
        self._profiles = frozenset(_token(value, "profile identifier") for value in profile_allowlist)
        if not isinstance(max_ttl_seconds, (int, float)) or not 1 <= max_ttl_seconds <= _MAX_TTL:
            raise ValueError("max_ttl_seconds is invalid")
        self._max_ttl = float(max_ttl_seconds)
        self._step_up = step_up
        self._clock = clock
        self._initialize()

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
                CREATE TABLE IF NOT EXISTS mobile_approvals (
                    approval_id TEXT PRIMARY KEY,
                    actor_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','consumed','expired')),
                    created_at REAL NOT NULL,
                    resolved_at REAL,
                    resolved_by TEXT
                );
                CREATE TABLE IF NOT EXISTS mobile_approval_audit (
                    audit_id TEXT PRIMARY KEY,
                    approval_id TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    context_digest TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                """
            )

    def create(
        self,
        *,
        actor_id: str,
        context: ApprovalContext,
        summary: str,
    ) -> ApprovalRecord:
        actor_id = _token(actor_id, "actor identifier")
        self._check_context(context)
        if not isinstance(summary, str) or not summary or len(summary) > _MAX_SUMMARY:
            raise ValueError("approval summary is invalid")
        now = float(self._clock())
        # Persist an already-expired host request so readers can observe the
        # durable ``expired`` transition; only reject an expiry window that is
        # implausibly far in the future.
        if context.expires_at > now + self._max_ttl:
            raise ApprovalExpired("approval expiry is outside the allowed window")
        approval_id = str(uuid4())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO mobile_approvals VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                (
                    approval_id,
                    actor_id,
                    context.instance_id,
                    context.profile_id,
                    _canonical(context.as_dict()),
                    summary,
                    "pending",
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO mobile_approval_audit VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid4()),
                    approval_id,
                    context.profile_id,
                    actor_id,
                    "approval.created",
                    approval_context_digest(context),
                    now,
                ),
            )
            connection.commit()
        return ApprovalRecord(approval_id, actor_id, context, summary, "pending", now)

    def get(self, approval_id: str, *, profile_id: str | None = None) -> ApprovalRecord:
        approval_id = self._opaque_id(approval_id)
        if profile_id is not None:
            profile_id = self._require_profile(profile_id)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM mobile_approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
        if row is None or (profile_id is not None and row["profile_id"] != profile_id):
            raise ApprovalNotFound("approval not found")
        return self._from_row(row)

    def list_for_actor(
        self,
        *,
        actor_id: str,
        profile_ids: Iterable[str],
        run_id: str | None = None,
        pending_only: bool = False,
    ) -> tuple[ApprovalRecord, ...]:
        """List only the caller's approvals for explicitly granted profiles."""

        actor_id = _token(actor_id, "actor identifier")
        profiles = frozenset(self._require_profile(value) for value in profile_ids)
        if not profiles:
            return ()
        if run_id is not None:
            run_id = _token(run_id, "run identifier")
        clauses = ["actor_id = ?", "profile_id IN (" + ",".join("?" for _ in profiles) + ")"]
        values: list[Any] = [actor_id, *sorted(profiles)]
        if pending_only:
            clauses.append("status = 'pending'")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM mobile_approvals WHERE "
                + " AND ".join(clauses)
                + " ORDER BY created_at DESC",
                values,
            ).fetchall()
        records = tuple(self._from_row(row) for row in rows)
        if run_id is None:
            return records
        return tuple(record for record in records if record.context.run_id == run_id)

    def decide(
        self,
        approval_id: str,
        *,
        actor_id: str,
        decision: Literal["approve_once", "deny"],
        context: ApprovalContext,
        challenge: Any | None = None,
        signature: str | None = None,
    ) -> ApprovalRecord:
        approval_id = self._opaque_id(approval_id)
        actor_id = _token(actor_id, "actor identifier")
        if decision not in _DECISIONS:
            raise ValueError("only approve_once and deny are supported")
        self._check_context(context)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM mobile_approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            if row is None or row["profile_id"] not in self._profiles:
                connection.rollback()
                raise ApprovalNotFound("approval not found")
            current = self._from_row(row)
            if current.context != context:
                connection.rollback()
                raise ApprovalConflict("approval context does not match")
            now = float(self._clock())
            if current.status != "pending":
                connection.rollback()
                raise ApprovalAlreadyResolved("approval is no longer pending")
            if current.context.expires_at <= now:
                self._resolve_locked(connection, current, "expired", actor_id, now)
                connection.commit()
                raise ApprovalExpired("approval has expired")
            if decision == "approve_once":
                self._verify_step_up(current, challenge, signature, now)
            status = "approved" if decision == "approve_once" else "denied"
            self._resolve_locked(connection, current, status, actor_id, now)
            connection.commit()
        return self.get(approval_id)

    def approve_once(
        self,
        approval_id: str,
        *,
        actor_id: str,
        context: ApprovalContext,
        challenge: Any,
        signature: str,
    ) -> ApprovalRecord:
        return self.decide(
            approval_id,
            actor_id=actor_id,
            decision="approve_once",
            context=context,
            challenge=challenge,
            signature=signature,
        )

    def deny(self, approval_id: str, *, actor_id: str, context: ApprovalContext) -> ApprovalRecord:
        return self.decide(approval_id, actor_id=actor_id, decision="deny", context=context)

    def consume(
        self,
        approval_id: str,
        *,
        actor_id: str,
        context: ApprovalContext,
    ) -> ApprovalRecord:
        approval_id = self._opaque_id(approval_id)
        actor_id = _token(actor_id, "actor identifier")
        self._check_context(context)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM mobile_approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            if row is None or row["profile_id"] not in self._profiles:
                connection.rollback()
                raise ApprovalNotFound("approval not found")
            current = self._from_row(row)
            if current.context != context:
                connection.rollback()
                raise ApprovalConflict("approval context does not match")
            if current.status != "approved":
                connection.rollback()
                raise ApprovalAlreadyResolved("approval is not available for consumption")
            now = float(self._clock())
            self._resolve_locked(connection, current, "consumed", actor_id, now)
            connection.commit()
        return self.get(approval_id)

    def audit(self, approval_id: str) -> tuple[ApprovalAudit, ...]:
        approval_id = self._opaque_id(approval_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM mobile_approval_audit WHERE approval_id = ? ORDER BY created_at, audit_id",
                (approval_id,),
            ).fetchall()
        if not rows:
            raise ApprovalNotFound("approval not found")
        return tuple(
            ApprovalAudit(
                row["audit_id"],
                row["approval_id"],
                row["profile_id"],
                row["actor_id"],
                row["action"],
                row["context_digest"],
                row["created_at"],
            )
            for row in rows
        )

    def _check_context(self, context: ApprovalContext) -> None:
        if not isinstance(context, ApprovalContext):
            raise ValueError("context must be an ApprovalContext")
        if context.instance_id != self._instance_id:
            raise ApprovalNotFound("approval context is outside this instance")
        self._require_profile(context.profile_id)

    def _require_profile(self, profile_id: str) -> str:
        profile_id = _token(profile_id, "profile identifier")
        if profile_id not in self._profiles:
            raise ApprovalNotFound("approval not found")
        return profile_id

    @staticmethod
    def _opaque_id(value: str) -> str:
        try:
            UUID(value)
        except (TypeError, ValueError) as exc:
            raise ApprovalNotFound("approval not found") from exc
        return value

    def _verify_step_up(
        self, approval: ApprovalRecord, challenge: Any, signature: str | None, now: float
    ) -> None:
        if self._step_up is None or challenge is None or not isinstance(signature, str):
            raise ApprovalStepUpRequired("approve_once requires user presence")
        expected = step_up_context(approval)
        try:
            raw_context = getattr(challenge, "context", None)
            challenge_context = expected if raw_context is None else dict(raw_context)
        except (TypeError, ValueError) as exc:
            raise ApprovalStepUpRequired("step-up context is invalid") from exc
        # Older in-process callers supplied the approval context directly;
        # wire clients use StepUpChallenge and therefore carry only the exact
        # server-built digest.  Keep the legacy adapter narrow while retaining
        # the strict production challenge path.
        verification_context = expected
        if challenge_context != expected:
            if challenge_context == approval.context.as_dict() and raw_context is not None:
                verification_context = challenge_context
            else:
                raise ApprovalStepUpRequired("step-up context is invalid")
        if challenge_context not in (expected, approval.context.as_dict()):
            raise ApprovalStepUpRequired("step-up context is invalid")
        try:
            self._step_up.verify(challenge, context=verification_context, signature=signature, now=now)
        except Exception as exc:
            raise ApprovalStepUpRequired("approve_once requires valid user presence") from exc

    def _resolve_locked(
        self,
        connection: sqlite3.Connection,
        current: ApprovalRecord,
        status: str,
        actor_id: str,
        now: float,
    ) -> None:
        connection.execute(
            "UPDATE mobile_approvals SET status = ?, resolved_at = ?, resolved_by = ? "
            "WHERE approval_id = ? AND status = ?",
            (status, now, actor_id, current.approval_id, current.status),
        )
        connection.execute(
            "INSERT INTO mobile_approval_audit VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid4()),
                current.approval_id,
                current.context.profile_id,
                actor_id,
                f"approval.{status}",
                approval_context_digest(current.context),
                now,
            ),
        )

    @staticmethod
    def _from_row(row: sqlite3.Row) -> ApprovalRecord:
        return ApprovalRecord(
            approval_id=row["approval_id"],
            actor_id=row["actor_id"],
            context=ApprovalContext(**json.loads(row["context_json"])),
            summary=row["summary"],
            status=row["status"],
            created_at=row["created_at"],
            resolved_at=row["resolved_at"],
            resolved_by=row["resolved_by"],
        )
