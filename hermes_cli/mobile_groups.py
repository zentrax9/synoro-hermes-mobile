"""Durable same-instance group coordination for Hermes Mobile.

This module owns coordination state only.  It never chooses tools, providers,
credentials, working directories, or agent prompts.  A higher service layer
resolves server-owned profiles to :class:`BotSelection` values and supplies
the resulting untrusted content to this state machine.
"""

from __future__ import annotations

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
_DEFAULT_LEASE_SECONDS = 30.0
_MIN_BOTS = 2
_MAX_BOTS = 6
_MAX_ROUNDS = 3
_MAX_RESPONSES = 10
_MAX_CONTENT_BYTES = 1_048_576
_MAX_IDENTIFIER_LENGTH = 512
_MAX_DISPLAY_NAME_LENGTH = 256
_MAX_EVENT_TYPE_LENGTH = 128
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class MobileGroupError(RuntimeError):
    """Base error with a stable code/status mapping for an HTTP adapter."""

    code = "mobile_group_error"
    status_code = 409


class CrossInstanceGroupUnsupported(MobileGroupError):
    code = "cross_instance_group_unsupported"
    status_code = 422


class GroupBusy(MobileGroupError):
    code = "group_busy"
    status_code = 409


class GroupRevisionConflict(MobileGroupError):
    code = "group_revision_conflict"
    status_code = 409


class GroupStopped(MobileGroupError):
    code = "group_stopped"
    status_code = 409


class TurnIndeterminate(GroupStopped):
    code = "turn_indeterminate"


class GroupNotFound(MobileGroupError):
    code = "group_not_found"
    status_code = 404


class MemberNotFound(MobileGroupError):
    code = "member_not_found"
    status_code = 404


class TurnNotFound(MobileGroupError):
    code = "turn_not_found"
    status_code = 404


class TurnStateError(MobileGroupError):
    code = "turn_state_error"


class ExecutionFenceLost(MobileGroupError):
    code = "execution_fence_lost"


class LeaseExpired(MobileGroupError):
    code = "lease_expired"


class ExecutionBusy(GroupBusy):
    code = "execution_busy"


class GroupCapExceeded(MobileGroupError):
    code = "group_cap_exceeded"
    status_code = 422


class RoundLimitExceeded(GroupCapExceeded):
    code = "round_limit_exceeded"


class InstanceIdentityError(MobileGroupError):
    code = "instance_identity_mismatch"
    status_code = 422


class GroupState(str, Enum):
    ACTIVE = "active"
    STOPPED = "stopped"


class TurnState(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    INDETERMINATE = "indeterminate"


class ContentProvenance(str, Enum):
    """Origin label preserved with content; it is never routing authority."""

    USER = "user"
    BOT = "bot"
    DOCUMENT = "document"
    OCR = "ocr"
    TRANSCRIPT = "transcript"
    WEB = "web"
    SYSTEM = "system"


@dataclass(frozen=True, slots=True)
class BotId:
    """Server-resolved bot identity; display names are intentionally absent."""

    instance_id: str
    profile_id: str


@dataclass(frozen=True, slots=True)
class BotSelection:
    """A server-resolved bot selection used when creating a group."""

    instance_id: str
    profile_id: str
    display_name: str

    @property
    def bot_id(self) -> BotId:
        return BotId(self.instance_id, self.profile_id)


@dataclass(frozen=True, slots=True)
class GroupMember:
    member_id: str
    bot_id: BotId
    display_name: str
    ordinal: int


@dataclass(frozen=True, slots=True)
class GroupSnapshot:
    group_id: str
    instance_id: str
    owner_id: str
    device_id: str
    members: tuple[GroupMember, ...]
    coordinator_member_id: str
    state: GroupState
    authority_epoch: int
    active_turn_id: str | None


@dataclass(frozen=True, slots=True)
class GroupListPage:
    """A bounded, keyset-paginated owner/device group snapshot page."""

    groups: tuple[GroupSnapshot, ...]
    has_more: bool
    next_created_at: float | None = None
    next_group_id: str | None = None

    def __post_init__(self) -> None:
        if self.has_more != (self.next_created_at is not None and self.next_group_id is not None):
            raise ValueError("group page cursor state is inconsistent")
        if not self.has_more and (self.next_created_at is not None or self.next_group_id is not None):
            raise ValueError("complete group page must not expose a cursor")


@dataclass(frozen=True, slots=True)
class TurnSnapshot:
    turn_id: str
    group_id: str
    user_event_id: str
    state: TurnState
    authority_epoch: int
    execution_generation: int
    current_round: int
    response_count: int
    active_member_id: str | None
    lease_until: float | None
    cancel_requested: bool
    completed_side_effects_not_undone: bool


@dataclass(frozen=True, slots=True)
class ExecutionClaim:
    """All fencing values required to commit one bot response."""

    turn_id: str
    group_id: str
    member_id: str
    authority_epoch: int
    execution_generation: int
    lease_token: str
    lease_until: float


@dataclass(frozen=True, slots=True)
class GroupEvent:
    sequence: int
    event_id: str
    group_id: str
    turn_id: str | None
    event_type: str
    payload: Mapping[str, Any]
    provenance: ContentProvenance
    created_at: float


class MobileGroupCoordinator:
    """SQLite-backed state machine for one Hermes installation."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        instance_id: str,
        lease_seconds: float = _DEFAULT_LEASE_SECONDS,
        clock: Callable[[], float] = time.time,
        timeout_seconds: float = 30.0,
    ) -> None:
        self._db_path = Path(db_path)
        self._instance_id = _validate_identifier(instance_id, "instance_id")
        self._lease_seconds = _validate_positive_seconds(lease_seconds, "lease_seconds")
        self._clock = clock
        self._timeout_seconds = _validate_positive_seconds(timeout_seconds, "timeout_seconds")
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @property
    def db_path(self) -> Path:
        return self._db_path

    @property
    def instance_id(self) -> str:
        return self._instance_id

    @staticmethod
    def _etag(authority_epoch: int) -> str:
        return f'"group-{authority_epoch}"'

    def create_group(
        self,
        selections: Sequence[BotSelection],
        *,
        owner_id: str = "",
        device_id: str = "",
    ) -> GroupSnapshot:
        """Create a 2–6 member group; the first selection coordinates by default."""

        if not isinstance(selections, Sequence) or isinstance(selections, (str, bytes)):
            raise ValueError("selections must be a sequence of BotSelection values")
        if not _MIN_BOTS <= len(selections) <= _MAX_BOTS:
            raise GroupCapExceeded("groups must contain between 2 and 6 bots")
        if owner_id:
            owner_id = _validate_identifier(owner_id, "owner_id")
        if device_id:
            device_id = _validate_identifier(device_id, "device_id")

        checked: list[BotSelection] = []
        profile_ids: set[str] = set()
        for selection in selections:
            if not isinstance(selection, BotSelection):
                raise ValueError("selections must contain BotSelection values")
            _validate_identifier(selection.instance_id, "selection.instance_id")
            profile_id = _validate_profile_id(selection.profile_id)
            display_name = _validate_display_name(selection.display_name)
            if selection.instance_id != self._instance_id:
                raise CrossInstanceGroupUnsupported(
                    "group members must belong to this Hermes instance"
                )
            if profile_id in profile_ids:
                raise ValueError("a profile may appear only once in a group")
            profile_ids.add(profile_id)
            checked.append(BotSelection(selection.instance_id, profile_id, display_name))

        group_id = _new_uuid()
        now = self._now()
        members = tuple(
            GroupMember(
                member_id=_new_uuid(),
                bot_id=selection.bot_id,
                display_name=selection.display_name,
                ordinal=ordinal,
            )
            for ordinal, selection in enumerate(checked)
        )
        with self._write_transaction() as connection:
            connection.execute(
                """
                INSERT INTO mobile_groups (
                    group_id, instance_id, owner_id, device_id, state, authority_epoch,
                    coordinator_member_id, active_turn_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 1, ?, NULL, ?, ?)
                """,
                (
                    group_id,
                    self._instance_id,
                    owner_id,
                    device_id,
                    GroupState.ACTIVE.value,
                    members[0].member_id,
                    now,
                    now,
                ),
            )
            for member in members:
                connection.execute(
                    """
                    INSERT INTO mobile_group_members (
                        member_id, group_id, instance_id, profile_id,
                        display_name, ordinal
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        member.member_id,
                        group_id,
                        member.bot_id.instance_id,
                        member.bot_id.profile_id,
                        member.display_name,
                        member.ordinal,
                    ),
                )
            self._insert_event_locked(
                connection,
                group_id=group_id,
                turn_id=None,
                event_type="group.created",
                payload={
                    "group_id": group_id,
                    "member_ids": [member.member_id for member in members],
                    "coordinator_member_id": members[0].member_id,
                },
                provenance=ContentProvenance.SYSTEM,
                created_at=now,
            )
        return GroupSnapshot(
            group_id=group_id,
            instance_id=self._instance_id,
            owner_id=owner_id,
            device_id=device_id,
            members=members,
            coordinator_member_id=members[0].member_id,
            state=GroupState.ACTIVE,
            authority_epoch=1,
            active_turn_id=None,
        )

    def get_group(
        self,
        group_id: str,
        *,
        owner_id: str | None = None,
        device_id: str | None = None,
    ) -> GroupSnapshot:
        group_id = _validate_uuid(group_id, "group_id")
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT group_id, instance_id, owner_id, device_id, state, authority_epoch,
                       coordinator_member_id, active_turn_id
                FROM mobile_groups
                WHERE group_id = ? AND instance_id = ?
                """,
                (group_id, self._instance_id),
            ).fetchone()
            if row is None:
                raise GroupNotFound("group does not exist")
            if (owner_id is not None and row["owner_id"] != owner_id) or (
                device_id is not None and row["device_id"] != device_id
            ):
                raise GroupNotFound("group does not exist")
            return self._group_from_row(connection, row)

    def list_groups(
        self,
        *,
        owner_id: str,
        device_id: str,
        limit: int = 100,
    ) -> tuple[GroupSnapshot, ...]:
        """List groups owned by one authenticated device on this installation.

        Group IDs are intentionally not accepted as a client-side filter here.  The owner and
        device coordinates come from the authenticated request, while the instance predicate is
        applied by the coordinator's connection.  Callers still perform member/profile
        authorization before serializing each snapshot so a revoked profile removes the whole
        group from the result rather than leaking a partial membership view.
        """

        if not isinstance(owner_id, str) or not owner_id or len(owner_id) > _MAX_IDENTIFIER_LENGTH:
            raise ValueError("owner_id must be a non-empty bounded string")
        if not isinstance(device_id, str) or not device_id or len(device_id) > _MAX_IDENTIFIER_LENGTH:
            raise ValueError("device_id must be a non-empty bounded string")
        return self.list_groups_page(
            owner_id=owner_id,
            device_id=device_id,
            limit=limit,
        ).groups

    def list_groups_page(
        self,
        *,
        owner_id: str,
        device_id: str,
        after_created_at: float | None = None,
        after_group_id: str | None = None,
        limit: int = 100,
    ) -> GroupListPage:
        """Return one stable keyset page for an authenticated owner/device pair.

        ``created_at DESC, group_id ASC`` is the durable ordering.  Creation time never changes
        when a group is stopped or its membership is revised, so a cursor remains stable while
        the installation is active.  The caller supplies the last row's timestamp and opaque ID
        for the next page; the instance, owner, and device predicates remain server-owned on every
        query so a cursor can never widen authorization.
        """

        if not isinstance(owner_id, str) or not owner_id or len(owner_id) > _MAX_IDENTIFIER_LENGTH:
            raise ValueError("owner_id must be a non-empty bounded string")
        if not isinstance(device_id, str) or not device_id or len(device_id) > _MAX_IDENTIFIER_LENGTH:
            raise ValueError("device_id must be a non-empty bounded string")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        if (after_created_at is None) != (after_group_id is None):
            raise ValueError("group page cursor is incomplete")
        if after_created_at is not None:
            if (
                isinstance(after_created_at, bool)
                or not isinstance(after_created_at, (int, float))
                or not math.isfinite(float(after_created_at))
            ):
                raise ValueError("group page cursor timestamp is invalid")
            after_created_at = float(after_created_at)
            after_group_id = _validate_uuid(after_group_id, "after_group_id")
        with self._connection() as connection:
            query = """
                SELECT group_id, instance_id, owner_id, device_id, state,
                       authority_epoch, coordinator_member_id, active_turn_id, created_at
                FROM mobile_groups
                WHERE instance_id = ? AND owner_id = ? AND device_id = ?
            """
            parameters: list[Any] = [self._instance_id, owner_id, device_id]
            if after_created_at is not None and after_group_id is not None:
                query += " AND (created_at < ? OR (created_at = ? AND group_id > ?))\n"
                parameters.extend([after_created_at, after_created_at, after_group_id])
            query += " ORDER BY created_at DESC, group_id ASC LIMIT ?"
            parameters.append(limit + 1)
            rows = connection.execute(
                query,
                tuple(parameters),
            ).fetchall()
            page_rows = rows[:limit]
            has_more = len(rows) > limit
            last = page_rows[-1] if has_more else None
            return GroupListPage(
                groups=tuple(self._group_from_row(connection, row) for row in page_rows),
                has_more=has_more,
                next_created_at=None if last is None else float(last["created_at"]),
                next_group_id=None if last is None else str(last["group_id"]),
            )

    def resolve_member(self, group_id: str, member_id: str) -> GroupMember:
        """Resolve only an opaque member UUID; display names never route."""

        group_id = _validate_uuid(group_id, "group_id")
        member_id = _validate_uuid(member_id, "member_id")
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT member_id, group_id, instance_id, profile_id, display_name, ordinal
                FROM mobile_group_members
                WHERE group_id = ? AND member_id = ?
                """,
                (group_id, member_id),
            ).fetchone()
            if row is None:
                raise MemberNotFound("member does not exist in this group")
            return _member_from_row(row)

    def add_member(
        self,
        group_id: str,
        selection: BotSelection,
        *,
        if_match: str | None = None,
    ) -> GroupSnapshot:
        group_id = _validate_uuid(group_id, "group_id")
        self._validate_selection(selection)
        with self._write_transaction() as connection:
            group = self._mutable_group_row_locked(connection, group_id)
            if if_match is not None and if_match != self._etag(int(group["authority_epoch"])):
                raise GroupRevisionConflict("group membership revision is stale")
            count = connection.execute(
                "SELECT COUNT(*) AS count FROM mobile_group_members WHERE group_id = ?",
                (group_id,),
            ).fetchone()["count"]
            if count >= _MAX_BOTS:
                raise GroupCapExceeded("a group cannot contain more than 6 bots")
            duplicate = connection.execute(
                """
                SELECT 1 FROM mobile_group_members
                WHERE group_id = ? AND profile_id = ?
                """,
                (group_id, selection.profile_id),
            ).fetchone()
            if duplicate is not None:
                raise ValueError("a profile may appear only once in a group")
            max_ordinal = connection.execute(
                "SELECT COALESCE(MAX(ordinal), -1) AS ordinal FROM mobile_group_members WHERE group_id = ?",
                (group_id,),
            ).fetchone()["ordinal"]
            member = GroupMember(
                member_id=_new_uuid(),
                bot_id=selection.bot_id,
                display_name=selection.display_name,
                ordinal=int(max_ordinal) + 1,
            )
            connection.execute(
                """
                INSERT INTO mobile_group_members (
                    member_id, group_id, instance_id, profile_id, display_name, ordinal
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    member.member_id,
                    group_id,
                    member.bot_id.instance_id,
                    member.bot_id.profile_id,
                    member.display_name,
                    member.ordinal,
                ),
            )
            epoch = int(group["authority_epoch"]) + 1
            now = self._now()
            self._update_group_epoch_locked(connection, group_id, epoch, now)
            self._insert_event_locked(
                connection,
                group_id=group_id,
                turn_id=None,
                event_type="group.member_added",
                payload={"member_id": member.member_id, "profile_id": member.bot_id.profile_id},
                provenance=ContentProvenance.SYSTEM,
                created_at=now,
            )
            row = self._group_row_locked(connection, group_id)
            return self._group_from_row(connection, row)

    def remove_member(
        self,
        group_id: str,
        member_id: str,
        *,
        if_match: str | None = None,
    ) -> GroupSnapshot:
        group_id = _validate_uuid(group_id, "group_id")
        member_id = _validate_uuid(member_id, "member_id")
        with self._write_transaction() as connection:
            group = self._mutable_group_row_locked(connection, group_id)
            if if_match is not None and if_match != self._etag(int(group["authority_epoch"])):
                raise GroupRevisionConflict("group membership revision is stale")
            count = connection.execute(
                "SELECT COUNT(*) AS count FROM mobile_group_members WHERE group_id = ?",
                (group_id,),
            ).fetchone()["count"]
            if count <= _MIN_BOTS:
                raise GroupCapExceeded("a group must retain at least 2 bots")
            member = connection.execute(
                """
                SELECT member_id, group_id, instance_id, profile_id, display_name, ordinal
                FROM mobile_group_members
                WHERE group_id = ? AND member_id = ?
                """,
                (group_id, member_id),
            ).fetchone()
            if member is None:
                raise MemberNotFound("member does not exist in this group")
            connection.execute(
                "DELETE FROM mobile_group_members WHERE group_id = ? AND member_id = ?",
                (group_id, member_id),
            )
            remaining = connection.execute(
                """
                SELECT member_id FROM mobile_group_members
                WHERE group_id = ? ORDER BY ordinal ASC
                """,
                (group_id,),
            ).fetchall()
            coordinator_member_id = (
                remaining[0]["member_id"]
                if member_id == group["coordinator_member_id"]
                else group["coordinator_member_id"]
            )
            epoch = int(group["authority_epoch"]) + 1
            now = self._now()
            connection.execute(
                """
                UPDATE mobile_groups
                SET authority_epoch = ?, coordinator_member_id = ?, updated_at = ?
                WHERE group_id = ?
                """,
                (epoch, coordinator_member_id, now, group_id),
            )
            self._insert_event_locked(
                connection,
                group_id=group_id,
                turn_id=None,
                event_type="group.member_removed",
                payload={
                    "member_id": member_id,
                    "coordinator_member_id": coordinator_member_id,
                },
                provenance=ContentProvenance.SYSTEM,
                created_at=now,
            )
            row = self._group_row_locked(connection, group_id)
            return self._group_from_row(connection, row)

    def start_turn(self, group_id: str, *, content: Any) -> TurnSnapshot:
        group_id = _validate_uuid(group_id, "group_id")
        content_json = _content_json(content, "content")
        now = self._now()
        turn_id = _new_uuid()
        user_event_id = _new_uuid()
        with self._write_transaction() as connection:
            group = self._active_group_row_locked(connection, group_id)
            if group["active_turn_id"] is not None:
                raise GroupBusy("a group has one active turn at a time")
            connection.execute(
                """
                INSERT INTO mobile_group_turns (
                    turn_id, group_id, user_event_id, state, authority_epoch,
                    execution_generation, current_round, round_closed,
                    response_count, active_member_id, lease_token,
                    lease_owner_pid, lease_owner_token, lease_until,
                    cancel_requested, completed_side_effects_not_undone,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 0, 1, 0, 0, NULL, NULL, ?, ?, NULL, 0, 0, ?, ?)
                """,
                (
                    turn_id,
                    group_id,
                    user_event_id,
                    TurnState.ACTIVE.value,
                    int(group["authority_epoch"]),
                    os.getpid(),
                    _PROCESS_TOKEN,
                    now,
                    now,
                ),
            )
            connection.execute(
                """
                UPDATE mobile_groups
                SET active_turn_id = ?, updated_at = ?
                WHERE group_id = ? AND active_turn_id IS NULL
                """,
                (turn_id, now, group_id),
            )
            self._insert_event_locked(
                connection,
                group_id=group_id,
                turn_id=turn_id,
                event_type="turn.user_message",
                payload={"user_event_id": user_event_id, "content": json.loads(content_json)},
                provenance=ContentProvenance.USER,
                created_at=now,
            )
            row = self._turn_row_locked(connection, turn_id)
            return _turn_from_row(row)

    def get_turn(self, turn_id: str) -> TurnSnapshot:
        turn_id = _validate_uuid(turn_id, "turn_id")
        with self._connection() as connection:
            row = self._turn_row_locked(connection, turn_id)
            if row is None:
                raise TurnNotFound("turn does not exist")
            return _turn_from_row(row)

    def claim_response(
        self,
        turn_id: str,
        member_id: str | None = None,
        *,
        lease_seconds: float | None = None,
        reclaim_expired: bool = False,
    ) -> ExecutionClaim:
        """Claim one serial bot response using an authority/generation fence."""

        turn_id = _validate_uuid(turn_id, "turn_id")
        if member_id is not None:
            member_id = _validate_uuid(member_id, "member_id")
        lease_seconds = (
            self._lease_seconds
            if lease_seconds is None
            else _validate_positive_seconds(lease_seconds, "lease_seconds")
        )
        now = self._now()
        with self._write_transaction() as connection:
            row = self._turn_with_group_locked(connection, turn_id)
            if row is None:
                raise TurnNotFound("turn does not exist")
            self._assert_claimable_turn(row)
            if int(row["response_count"]) >= _MAX_RESPONSES:
                raise GroupCapExceeded("a turn cannot execute more than 10 bot responses")
            if int(row["round_closed"]):
                raise RoundLimitExceeded("a turn cannot execute more than 3 serial rounds")

            active_member = row["active_member_id"]
            if active_member is not None:
                lease_until = row["lease_until"]
                if lease_until is not None and float(lease_until) > now:
                    raise ExecutionBusy("another bot response currently owns the lease")
                if not reclaim_expired:
                    raise LeaseExpired("response lease expired; explicit reclaim is required")
                self._mark_execution_indeterminate_locked(
                    connection,
                    row,
                    reason="lease_expired",
                    created_at=now,
                )
                row = self._turn_with_group_locked(connection, turn_id)
                if row is None:
                    raise TurnNotFound("turn does not exist")
                self._assert_claimable_turn(row)

            if member_id is None:
                if int(row["response_count"]) != 0:
                    raise ValueError("member_id is required after the coordinator's first response")
                member_id = str(row["coordinator_member_id"])
            self._assert_member_locked(connection, row["group_id"], member_id)

            generation = int(row["execution_generation"]) + 1
            authority_epoch = int(row["authority_epoch"])
            lease_token = _new_uuid()
            lease_until = now + lease_seconds
            connection.execute(
                """
                UPDATE mobile_group_turns
                SET execution_generation = ?, active_member_id = ?,
                    lease_token = ?, lease_owner_pid = ?, lease_owner_token = ?,
                    lease_until = ?, updated_at = ?
                WHERE turn_id = ? AND state = ? AND active_member_id IS NULL
                """,
                (
                    generation,
                    member_id,
                    lease_token,
                    os.getpid(),
                    _PROCESS_TOKEN,
                    lease_until,
                    now,
                    turn_id,
                    TurnState.ACTIVE.value,
                ),
            )
            self._insert_event_locked(
                connection,
                group_id=row["group_id"],
                turn_id=turn_id,
                event_type="execution.claimed",
                payload={
                    "member_id": member_id,
                    "authority_epoch": authority_epoch,
                    "execution_generation": generation,
                },
                provenance=ContentProvenance.SYSTEM,
                created_at=now,
            )
            return ExecutionClaim(
                turn_id=turn_id,
                group_id=row["group_id"],
                member_id=member_id,
                authority_epoch=authority_epoch,
                execution_generation=generation,
                lease_token=lease_token,
                lease_until=lease_until,
            )

    def renew_response_lease(
        self,
        claim: ExecutionClaim,
        *,
        lease_seconds: float | None = None,
    ) -> ExecutionClaim:
        lease_seconds = (
            self._lease_seconds
            if lease_seconds is None
            else _validate_positive_seconds(lease_seconds, "lease_seconds")
        )
        now = self._now()
        with self._write_transaction() as connection:
            row = self._turn_with_group_locked(connection, _validate_uuid(claim.turn_id, "turn_id"))
            self._assert_fence(row, claim, now)
            lease_until = now + lease_seconds
            connection.execute(
                "UPDATE mobile_group_turns SET lease_until = ?, updated_at = ? WHERE turn_id = ?",
                (lease_until, now, claim.turn_id),
            )
            return ExecutionClaim(
                turn_id=claim.turn_id,
                group_id=claim.group_id,
                member_id=claim.member_id,
                authority_epoch=claim.authority_epoch,
                execution_generation=claim.execution_generation,
                lease_token=claim.lease_token,
                lease_until=lease_until,
            )

    def complete_response(
        self,
        claim: ExecutionClaim,
        *,
        content: Any,
        provenance: ContentProvenance,
        round_complete: bool = False,
    ) -> TurnSnapshot:
        """Commit one bot response only when every fence value still matches."""

        content_json = _content_json(content, "content")
        provenance = _validate_provenance(provenance)
        now = self._now()
        with self._write_transaction() as connection:
            row = self._turn_with_group_locked(connection, _validate_uuid(claim.turn_id, "turn_id"))
            self._assert_fence(row, claim, now)
            response_count = int(row["response_count"]) + 1
            current_round = int(row["current_round"])
            round_closed = int(row["round_closed"])
            if response_count > _MAX_RESPONSES:
                raise GroupCapExceeded("a turn cannot execute more than 10 bot responses")
            if round_complete:
                if current_round >= _MAX_ROUNDS:
                    round_closed = 1
                else:
                    current_round += 1
            connection.execute(
                """
                UPDATE mobile_group_turns
                SET current_round = ?, round_closed = ?, response_count = ?,
                    active_member_id = NULL, lease_token = NULL,
                    lease_owner_pid = ?, lease_owner_token = ?,
                    lease_until = NULL, updated_at = ?
                WHERE turn_id = ?
                """,
                (
                    current_round,
                    round_closed,
                    response_count,
                    os.getpid(),
                    _PROCESS_TOKEN,
                    now,
                    claim.turn_id,
                ),
            )
            self._insert_event_locked(
                connection,
                group_id=row["group_id"],
                turn_id=claim.turn_id,
                event_type="bot.response",
                payload={
                    "member_id": claim.member_id,
                    "response_number": response_count,
                    "content": json.loads(content_json),
                },
                provenance=provenance,
                created_at=now,
            )
            refreshed = self._turn_row_locked(connection, claim.turn_id)
            return _turn_from_row(refreshed)

    def finish_turn(self, turn_id: str) -> TurnSnapshot:
        turn_id = _validate_uuid(turn_id, "turn_id")
        now = self._now()
        with self._write_transaction() as connection:
            row = self._turn_with_group_locked(connection, turn_id)
            if row is None:
                raise TurnNotFound("turn does not exist")
            if TurnState(row["state"]) is not TurnState.ACTIVE:
                return _turn_from_row(row)
            if row["active_member_id"] is not None:
                raise GroupBusy("finish requires no active member execution")
            connection.execute(
                """
                UPDATE mobile_group_turns
                SET state = ?, updated_at = ?
                WHERE turn_id = ? AND state = ? AND active_member_id IS NULL
                """,
                (TurnState.COMPLETED.value, now, turn_id, TurnState.ACTIVE.value),
            )
            connection.execute(
                """
                UPDATE mobile_groups
                SET active_turn_id = NULL, updated_at = ?
                WHERE group_id = ? AND active_turn_id = ?
                """,
                (now, row["group_id"], turn_id),
            )
            self._insert_event_locked(
                connection,
                group_id=row["group_id"],
                turn_id=turn_id,
                event_type="turn.completed",
                payload={"response_count": int(row["response_count"])},
                provenance=ContentProvenance.SYSTEM,
                created_at=now,
            )
            return _turn_from_row(self._turn_row_locked(connection, turn_id))

    def cancel_turn(self, turn_id: str, *, reason: str = "user_stop") -> TurnSnapshot:
        turn_id = _validate_uuid(turn_id, "turn_id")
        reason = _validate_token(reason, "reason")
        now = self._now()
        with self._write_transaction() as connection:
            row = self._turn_with_group_locked(connection, turn_id)
            if row is None:
                raise TurnNotFound("turn does not exist")
            state = TurnState(row["state"])
            if state is not TurnState.ACTIVE:
                return _turn_from_row(row)
            connection.execute(
                """
                UPDATE mobile_group_turns
                SET state = ?, execution_generation = execution_generation + 1,
                    active_member_id = NULL, lease_token = NULL,
                    lease_owner_pid = NULL, lease_owner_token = NULL,
                    lease_until = NULL, cancel_requested = 1,
                    completed_side_effects_not_undone = 1, updated_at = ?
                WHERE turn_id = ? AND state = ?
                """,
                (
                    TurnState.CANCELLED.value,
                    now,
                    turn_id,
                    TurnState.ACTIVE.value,
                ),
            )
            connection.execute(
                """
                UPDATE mobile_groups
                SET active_turn_id = NULL, updated_at = ?
                WHERE group_id = ? AND active_turn_id = ?
                """,
                (now, row["group_id"], turn_id),
            )
            self._insert_event_locked(
                connection,
                group_id=row["group_id"],
                turn_id=turn_id,
                event_type="turn.cancelled",
                payload={
                    "reason": reason,
                    "completed_external_side_effects_not_undone": True,
                },
                provenance=ContentProvenance.SYSTEM,
                created_at=now,
            )
            return _turn_from_row(self._turn_row_locked(connection, turn_id))

    def mark_turn_indeterminate(
        self,
        turn_id: str,
        *,
        reason: str = "execution_outcome_unknown",
    ) -> TurnSnapshot:
        """Fence uncertain active work without permitting an automatic retry."""

        turn_id = _validate_uuid(turn_id, "turn_id")
        reason = _validate_token(reason, "reason")
        now = self._now()
        with self._write_transaction() as connection:
            row = self._turn_with_group_locked(connection, turn_id)
            if row is None:
                raise TurnNotFound("turn does not exist")
            if TurnState(row["state"]) is not TurnState.ACTIVE:
                return _turn_from_row(row)
            connection.execute(
                """
                UPDATE mobile_group_turns
                SET state = ?, execution_generation = execution_generation + 1,
                    active_member_id = NULL, lease_token = NULL,
                    lease_owner_pid = NULL, lease_owner_token = NULL,
                    lease_until = NULL, updated_at = ?
                WHERE turn_id = ? AND state = ?
                """,
                (TurnState.INDETERMINATE.value, now, turn_id, TurnState.ACTIVE.value),
            )
            connection.execute(
                """
                UPDATE mobile_groups
                SET active_turn_id = NULL, updated_at = ?
                WHERE group_id = ? AND active_turn_id = ?
                """,
                (now, row["group_id"], turn_id),
            )
            self._insert_event_locked(
                connection,
                group_id=row["group_id"],
                turn_id=turn_id,
                event_type="turn.indeterminate",
                payload={"reason": reason},
                provenance=ContentProvenance.SYSTEM,
                created_at=now,
            )
            return _turn_from_row(self._turn_row_locked(connection, turn_id))

    def stop_group(self, group_id: str, *, reason: str = "user_stop") -> GroupSnapshot:
        """Stop future turns and cancel active work without undoing side effects."""

        group_id = _validate_uuid(group_id, "group_id")
        reason = _validate_token(reason, "reason")
        now = self._now()
        with self._write_transaction() as connection:
            group = self._group_row_locked(connection, group_id)
            if group is None:
                raise GroupNotFound("group does not exist")
            if GroupState(group["state"]) is GroupState.STOPPED:
                return self._group_from_row(connection, group)
            active_turn_id = group["active_turn_id"]
            epoch = int(group["authority_epoch"]) + 1
            if active_turn_id is not None:
                connection.execute(
                    """
                    UPDATE mobile_group_turns
                    SET state = ?, authority_epoch = ?, execution_generation = execution_generation + 1,
                        active_member_id = NULL, lease_token = NULL,
                        lease_owner_pid = NULL, lease_owner_token = NULL,
                        lease_until = NULL, cancel_requested = 1,
                        completed_side_effects_not_undone = 1, updated_at = ?
                    WHERE turn_id = ? AND state = ?
                    """,
                    (
                        TurnState.CANCELLED.value,
                        epoch,
                        now,
                        active_turn_id,
                        TurnState.ACTIVE.value,
                    ),
                )
                self._insert_event_locked(
                    connection,
                    group_id=group_id,
                    turn_id=active_turn_id,
                    event_type="turn.cancelled",
                    payload={
                        "reason": reason,
                        "completed_external_side_effects_not_undone": True,
                    },
                    provenance=ContentProvenance.SYSTEM,
                    created_at=now,
                )
            connection.execute(
                """
                UPDATE mobile_groups
                SET state = ?, authority_epoch = ?, active_turn_id = NULL, updated_at = ?
                WHERE group_id = ?
                """,
                (GroupState.STOPPED.value, epoch, now, group_id),
            )
            self._insert_event_locked(
                connection,
                group_id=group_id,
                turn_id=active_turn_id,
                event_type="group.stopped",
                payload={
                    "reason": reason,
                    "completed_external_side_effects_not_undone": True,
                },
                provenance=ContentProvenance.SYSTEM,
                created_at=now,
            )
            return self._group_from_row(connection, self._group_row_locked(connection, group_id))

    def recover_uncertain_active_work(self) -> int:
        """Explicitly fence every active turn during a controlled takeover."""

        with self._write_transaction() as connection:
            return self._recover_active_locked(connection, force=True)

    def list_events(self, group_id: str, *, turn_id: str | None = None) -> tuple[GroupEvent, ...]:
        group_id = _validate_uuid(group_id, "group_id")
        if turn_id is not None:
            turn_id = _validate_uuid(turn_id, "turn_id")
        with self._connection() as connection:
            if self._group_row_locked(connection, group_id) is None:
                raise GroupNotFound("group does not exist")
            if turn_id is None:
                rows = connection.execute(
                    """
                    SELECT sequence, event_id, group_id, turn_id, event_type,
                           payload_json, provenance, created_at
                    FROM mobile_group_events
                    WHERE group_id = ? ORDER BY sequence ASC
                    """,
                    (group_id,),
                ).fetchall()
            else:
                turn_exists = connection.execute(
                    """
                    SELECT 1 FROM mobile_group_turns
                    WHERE group_id = ? AND turn_id = ?
                    """,
                    (group_id, turn_id),
                ).fetchone()
                if turn_exists is None:
                    raise TurnNotFound("turn does not belong to this group")
                rows = connection.execute(
                    """
                    SELECT sequence, event_id, group_id, turn_id, event_type,
                           payload_json, provenance, created_at
                    FROM mobile_group_events
                    WHERE group_id = ? AND turn_id = ? ORDER BY sequence ASC
                    """,
                    (group_id, turn_id),
                ).fetchall()
            return tuple(_event_from_row(row) for row in rows)

    def _initialize(self) -> None:
        with self._write_transaction() as connection:
            for statement in (
                """
                CREATE TABLE IF NOT EXISTS mobile_group_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS mobile_groups (
                    group_id TEXT PRIMARY KEY,
                    instance_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL DEFAULT '',
                    device_id TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL CHECK (state IN ('active', 'stopped')),
                    authority_epoch INTEGER NOT NULL,
                    coordinator_member_id TEXT NOT NULL,
                    active_turn_id TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS mobile_group_members (
                    member_id TEXT PRIMARY KEY,
                    group_id TEXT NOT NULL REFERENCES mobile_groups(group_id) ON DELETE CASCADE,
                    instance_id TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    UNIQUE (group_id, profile_id)
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS mobile_group_turns (
                    turn_id TEXT PRIMARY KEY,
                    group_id TEXT NOT NULL REFERENCES mobile_groups(group_id) ON DELETE CASCADE,
                    user_event_id TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL CHECK (state IN ('active', 'completed', 'cancelled', 'indeterminate')),
                    authority_epoch INTEGER NOT NULL,
                    execution_generation INTEGER NOT NULL,
                    current_round INTEGER NOT NULL,
                    round_closed INTEGER NOT NULL CHECK (round_closed IN (0, 1)),
                    response_count INTEGER NOT NULL CHECK (response_count >= 0),
                    active_member_id TEXT,
                    lease_token TEXT,
                    lease_owner_pid INTEGER,
                    lease_owner_token TEXT,
                    lease_until REAL,
                    cancel_requested INTEGER NOT NULL CHECK (cancel_requested IN (0, 1)),
                    completed_side_effects_not_undone INTEGER NOT NULL CHECK (
                        completed_side_effects_not_undone IN (0, 1)
                    ),
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS mobile_group_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    group_id TEXT NOT NULL REFERENCES mobile_groups(group_id) ON DELETE CASCADE,
                    turn_id TEXT REFERENCES mobile_group_turns(turn_id) ON DELETE CASCADE,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    provenance TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_mobile_group_events_group
                    ON mobile_group_events (group_id, sequence)
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_mobile_group_turns_group_state
                    ON mobile_group_turns (group_id, state)
                """,
            ):
                connection.execute(statement)
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(mobile_groups)").fetchall()
            }
            if "owner_id" not in columns:
                connection.execute(
                    "ALTER TABLE mobile_groups ADD COLUMN owner_id TEXT NOT NULL DEFAULT ''"
                )
            if "device_id" not in columns:
                connection.execute(
                    "ALTER TABLE mobile_groups ADD COLUMN device_id TEXT NOT NULL DEFAULT ''"
                )
            connection.execute(
                "INSERT OR IGNORE INTO mobile_group_meta (key, value) VALUES (?, ?)",
                ("schema_version", _SCHEMA_VERSION),
            )
            connection.execute(
                "INSERT OR IGNORE INTO mobile_group_meta (key, value) VALUES (?, ?)",
                ("instance_id", self._instance_id),
            )
            stored = connection.execute(
                "SELECT value FROM mobile_group_meta WHERE key = 'instance_id'"
            ).fetchone()["value"]
            if stored != self._instance_id:
                raise InstanceIdentityError("group database belongs to a different instance")
            version = connection.execute(
                "SELECT value FROM mobile_group_meta WHERE key = 'schema_version'"
            ).fetchone()["value"]
            if version != _SCHEMA_VERSION:
                raise MobileGroupError(f"unsupported group schema version {version!r}")
            self._recover_active_locked(connection, force=False)

    def _recover_active_locked(self, connection: sqlite3.Connection, *, force: bool) -> int:
        if force:
            rows = connection.execute(
                """
                SELECT turn_id, group_id, authority_epoch, execution_generation
                FROM mobile_group_turns WHERE state = ? ORDER BY created_at ASC
                """,
                (TurnState.ACTIVE.value,),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT turn_id, group_id, authority_epoch, execution_generation
                FROM mobile_group_turns
                WHERE state = ? AND (lease_owner_pid <> ? OR lease_owner_token <> ?)
                ORDER BY created_at ASC
                """,
                (TurnState.ACTIVE.value, os.getpid(), _PROCESS_TOKEN),
            ).fetchall()
        now = self._now()
        count = 0
        for row in rows:
            turn_id = row["turn_id"]
            connection.execute(
                """
                UPDATE mobile_group_turns
                SET state = ?, execution_generation = execution_generation + 1,
                    active_member_id = NULL, lease_token = NULL,
                    lease_owner_pid = NULL, lease_owner_token = NULL,
                    lease_until = NULL, cancel_requested = 1,
                    completed_side_effects_not_undone = 1, updated_at = ?
                WHERE turn_id = ? AND state = ?
                """,
                (
                    TurnState.INDETERMINATE.value,
                    now,
                    turn_id,
                    TurnState.ACTIVE.value,
                ),
            )
            connection.execute(
                """
                UPDATE mobile_groups
                SET active_turn_id = NULL, updated_at = ?
                WHERE group_id = ? AND active_turn_id = ?
                """,
                (now, row["group_id"], turn_id),
            )
            self._insert_event_locked(
                connection,
                group_id=row["group_id"],
                turn_id=turn_id,
                event_type="turn.indeterminate",
                payload={
                    "reason": "process_restart",
                    "authority_epoch": int(row["authority_epoch"]),
                    "execution_generation": int(row["execution_generation"]) + 1,
                    "completed_external_side_effects_not_undone": True,
                },
                provenance=ContentProvenance.SYSTEM,
                created_at=now,
            )
            count += 1
        return count

    def _validate_selection(self, selection: BotSelection) -> None:
        if not isinstance(selection, BotSelection):
            raise ValueError("selection must be a BotSelection")
        _validate_identifier(selection.instance_id, "selection.instance_id")
        _validate_profile_id(selection.profile_id)
        _validate_display_name(selection.display_name)
        if selection.instance_id != self._instance_id:
            raise CrossInstanceGroupUnsupported(
                "group members must belong to this Hermes instance"
            )

    def _group_row_locked(self, connection: sqlite3.Connection, group_id: str) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT group_id, instance_id, owner_id, device_id, state,
                   authority_epoch, coordinator_member_id, active_turn_id
            FROM mobile_groups WHERE group_id = ? AND instance_id = ?
            """,
            (group_id, self._instance_id),
        ).fetchone()

    def _mutable_group_row_locked(self, connection: sqlite3.Connection, group_id: str) -> sqlite3.Row:
        row = self._group_row_locked(connection, group_id)
        if row is None:
            raise GroupNotFound("group does not exist")
        if GroupState(row["state"]) is GroupState.STOPPED:
            raise GroupStopped("group is stopped")
        if row["active_turn_id"] is not None:
            raise GroupBusy("membership cannot change during an active turn")
        return row

    def _active_group_row_locked(self, connection: sqlite3.Connection, group_id: str) -> sqlite3.Row:
        row = self._group_row_locked(connection, group_id)
        if row is None:
            raise GroupNotFound("group does not exist")
        if GroupState(row["state"]) is GroupState.STOPPED:
            raise GroupStopped("group is stopped")
        return row

    def _turn_row_locked(self, connection: sqlite3.Connection, turn_id: str) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT turn_id, group_id, user_event_id, state, authority_epoch,
                   execution_generation, current_round, round_closed,
                   response_count, active_member_id, lease_until,
                   cancel_requested, completed_side_effects_not_undone
            FROM mobile_group_turns WHERE turn_id = ?
            """,
            (turn_id,),
        ).fetchone()

    def _turn_with_group_locked(self, connection: sqlite3.Connection, turn_id: str) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT t.turn_id, t.group_id, t.user_event_id, t.state,
                   t.authority_epoch, t.execution_generation, t.current_round,
                   t.round_closed, t.response_count, t.active_member_id,
                   t.lease_token, t.lease_owner_pid, t.lease_owner_token,
                   t.lease_until, t.cancel_requested,
                   t.completed_side_effects_not_undone,
                   g.state AS group_state, g.authority_epoch AS group_epoch,
                   g.active_turn_id, g.coordinator_member_id
            FROM mobile_group_turns AS t
            JOIN mobile_groups AS g ON g.group_id = t.group_id
            WHERE t.turn_id = ? AND g.instance_id = ?
            """,
            (turn_id, self._instance_id),
        ).fetchone()

    def _assert_member_locked(self, connection: sqlite3.Connection, group_id: str, member_id: str) -> None:
        row = connection.execute(
            """
            SELECT 1 FROM mobile_group_members
            WHERE group_id = ? AND member_id = ? AND instance_id = ?
            """,
            (group_id, member_id, self._instance_id),
        ).fetchone()
        if row is None:
            raise MemberNotFound("member does not exist in this group")

    def _assert_claimable_turn(self, row: sqlite3.Row) -> None:
        state = TurnState(row["state"])
        if state is TurnState.INDETERMINATE:
            raise TurnIndeterminate("turn outcome is uncertain; explicit retry is required")
        if state is not TurnState.ACTIVE:
            raise TurnStateError(f"turn is {state.value}")
        if GroupState(row["group_state"]) is GroupState.STOPPED:
            raise GroupStopped("group is stopped")
        if row["active_turn_id"] != row["turn_id"]:
            raise TurnStateError("turn is no longer the group's active turn")

    def _assert_fence(self, row: sqlite3.Row | None, claim: ExecutionClaim, now: float) -> None:
        if row is None:
            raise ExecutionFenceLost("turn does not exist")
        if TurnState(row["state"]) is not TurnState.ACTIVE:
            raise ExecutionFenceLost("turn is no longer executable")
        if GroupState(row["group_state"]) is GroupState.STOPPED:
            raise ExecutionFenceLost("group is stopped")
        if row["active_turn_id"] != row["turn_id"]:
            raise ExecutionFenceLost("turn is no longer the group's active turn")
        if (
            row["active_member_id"] != claim.member_id
            or int(row["authority_epoch"]) != claim.authority_epoch
            or int(row["group_epoch"]) != claim.authority_epoch
            or int(row["execution_generation"]) != claim.execution_generation
            or row["lease_token"] != claim.lease_token
        ):
            raise ExecutionFenceLost("execution claim has been superseded")
        if row["lease_until"] is None or float(row["lease_until"]) <= now:
            raise ExecutionFenceLost("execution lease expired")

    def _mark_execution_indeterminate_locked(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        reason: str,
        created_at: float,
    ) -> None:
        generation = int(row["execution_generation"]) + 1
        connection.execute(
            """
            UPDATE mobile_group_turns
            SET execution_generation = ?, active_member_id = NULL,
                lease_token = NULL, lease_owner_pid = NULL,
                lease_owner_token = NULL, lease_until = NULL,
                completed_side_effects_not_undone = 1, updated_at = ?
            WHERE turn_id = ? AND state = ?
            """,
            (generation, created_at, row["turn_id"], TurnState.ACTIVE.value),
        )
        self._insert_event_locked(
            connection,
            group_id=row["group_id"],
            turn_id=row["turn_id"],
            event_type="execution.indeterminate",
            payload={
                "member_id": row["active_member_id"],
                "reason": reason,
                "execution_generation": generation,
                "completed_external_side_effects_not_undone": True,
            },
            provenance=ContentProvenance.SYSTEM,
            created_at=created_at,
        )

    def _update_group_epoch_locked(
        self,
        connection: sqlite3.Connection,
        group_id: str,
        epoch: int,
        updated_at: float,
    ) -> None:
        connection.execute(
            "UPDATE mobile_groups SET authority_epoch = ?, updated_at = ? WHERE group_id = ?",
            (epoch, updated_at, group_id),
        )

    def _group_from_row(self, connection: sqlite3.Connection, row: sqlite3.Row) -> GroupSnapshot:
        member_rows = connection.execute(
            """
            SELECT member_id, group_id, instance_id, profile_id, display_name, ordinal
            FROM mobile_group_members WHERE group_id = ? ORDER BY ordinal ASC
            """,
            (row["group_id"],),
        ).fetchall()
        members = tuple(_member_from_row(member_row) for member_row in member_rows)
        return GroupSnapshot(
            group_id=str(row["group_id"]),
            instance_id=str(row["instance_id"]),
            owner_id=str(row["owner_id"]),
            device_id=str(row["device_id"]),
            members=members,
            coordinator_member_id=str(row["coordinator_member_id"]),
            state=GroupState(row["state"]),
            authority_epoch=int(row["authority_epoch"]),
            active_turn_id=row["active_turn_id"],
        )

    def _insert_event_locked(
        self,
        connection: sqlite3.Connection,
        *,
        group_id: str,
        turn_id: str | None,
        event_type: str,
        payload: Mapping[str, Any],
        provenance: ContentProvenance,
        created_at: float,
    ) -> GroupEvent:
        event_id = _new_uuid()
        payload_json = _content_json(payload, "event payload")
        provenance = _validate_provenance(provenance)
        sequence = connection.execute(
            """
            INSERT INTO mobile_group_events (
                event_id, group_id, turn_id, event_type,
                payload_json, provenance, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                group_id,
                turn_id,
                _validate_token(event_type, "event_type"),
                payload_json,
                provenance.value,
                created_at,
            ),
        ).lastrowid
        if sequence is None:
            raise MobileGroupError("SQLite did not return an event sequence")
        return GroupEvent(
            sequence=int(sequence),
            event_id=event_id,
            group_id=group_id,
            turn_id=turn_id,
            event_type=event_type,
            payload=json.loads(payload_json),
            provenance=provenance,
            created_at=created_at,
        )

    def _now(self) -> float:
        value = self._clock()
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
            raise ValueError("clock must return a finite number")
        return float(value)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            self._db_path,
            timeout=self._timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA busy_timeout = 30000")
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


def _member_from_row(row: sqlite3.Row) -> GroupMember:
    return GroupMember(
        member_id=str(row["member_id"]),
        bot_id=BotId(instance_id=str(row["instance_id"]), profile_id=str(row["profile_id"])),
        display_name=str(row["display_name"]),
        ordinal=int(row["ordinal"]),
    )


def _turn_from_row(row: sqlite3.Row | None) -> TurnSnapshot:
    if row is None:
        raise TurnNotFound("turn does not exist")
    return TurnSnapshot(
        turn_id=str(row["turn_id"]),
        group_id=str(row["group_id"]),
        user_event_id=str(row["user_event_id"]),
        state=TurnState(row["state"]),
        authority_epoch=int(row["authority_epoch"]),
        execution_generation=int(row["execution_generation"]),
        current_round=int(row["current_round"]),
        response_count=int(row["response_count"]),
        active_member_id=row["active_member_id"],
        lease_until=None if row["lease_until"] is None else float(row["lease_until"]),
        cancel_requested=bool(row["cancel_requested"]),
        completed_side_effects_not_undone=bool(row["completed_side_effects_not_undone"]),
    )


def _event_from_row(row: sqlite3.Row) -> GroupEvent:
    return GroupEvent(
        sequence=int(row["sequence"]),
        event_id=str(row["event_id"]),
        group_id=str(row["group_id"]),
        turn_id=row["turn_id"],
        event_type=str(row["event_type"]),
        payload=json.loads(str(row["payload_json"])),
        provenance=ContentProvenance(row["provenance"]),
        created_at=float(row["created_at"]),
    )


def _new_uuid() -> str:
    return str(uuid.uuid4())


def _validate_uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an opaque UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{field} must be an opaque UUID") from exc
    if parsed.int == 0:
        raise ValueError(f"{field} must not be the nil UUID")
    return str(parsed)


def _validate_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_IDENTIFIER_LENGTH:
        raise ValueError(f"{field} must be a non-empty bounded string")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ValueError(f"{field} contains a control character")
    return value


def _validate_display_name(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_DISPLAY_NAME_LENGTH:
        raise ValueError("display_name must be a non-empty bounded string")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ValueError("display_name contains a control character")
    return value


def _validate_profile_id(value: Any) -> str:
    value = _validate_identifier(value, "profile_id")
    if "/" in value or "\\" in value:
        raise ValueError("profile_id must be an opaque identifier, not a path")
    return value


def _validate_token(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) > _MAX_EVENT_TYPE_LENGTH or not _TOKEN_RE.fullmatch(value):
        raise ValueError(f"{field} must be an ASCII token")
    return value


def _validate_positive_seconds(value: Any, field: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        raise ValueError(f"{field} must be a finite number")
    if value <= 0:
        raise ValueError(f"{field} must be positive")
    return float(value)


def _validate_provenance(value: Any) -> ContentProvenance:
    if isinstance(value, ContentProvenance):
        return value
    try:
        return ContentProvenance(value)
    except (ValueError, TypeError) as exc:
        raise ValueError("provenance must be a known ContentProvenance value") from exc


def _content_json(value: Any, field: str) -> str:
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
    if len(encoded.encode("utf-8")) > _MAX_CONTENT_BYTES:
        raise ValueError(f"{field} is too large")
    return encoded
