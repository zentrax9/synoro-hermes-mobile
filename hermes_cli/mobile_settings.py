"""Constrained, durable settings service for Hermes Mobile.

This module is intentionally a service seam rather than a configuration
loader.  The host supplies profile and catalog allowlists; mobile requests can
mutate only the safe projection below.  SQLite transactions contain the
revision bump, rollback snapshot, and audit row together, so an HTTP adapter
never has to reconstruct partial settings after a crash.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from threading import Lock, RLock
import time
from typing import Any
from uuid import UUID, uuid4

from hermes_constants import VALID_REASONING_EFFORTS


_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_FIELDS = frozenset(
    {
        "display_name",
        "title",
        "avatar",
        "notification_preferences",
        "privacy_preferences",
        "approval_policy",
    }
)
_SENSITIVE_FIELDS = frozenset({"persona", "model", "provider", "reasoning", "skills"})
_POLICY_RANK = {"deny": 0, "step_up": 1, "once": 2, "allow": 3}
_VALID_REASONING_EFFORTS = frozenset(("none", *VALID_REASONING_EFFORTS))
_MAX_JSON_BYTES = 256_000


class SettingsError(RuntimeError):
    """Base class for mobile settings errors safe to classify at the edge."""


class SettingsNotFound(SettingsError, LookupError):
    """The profile is outside the server-owned mobile scope."""


class SettingsConflict(SettingsError):
    """The caller supplied a stale or invalid revision/ETag."""


class SettingsForbidden(SettingsError, PermissionError):
    """The requested setting is not writable by mobile or weakens policy."""


class StepUpRequired(SettingsForbidden):
    """A sensitive setting lacks a valid user-presence proof."""


class SettingsValidation(SettingsError, ValueError):
    """A mobile setting is malformed or outside the host allowlist."""


@dataclass(frozen=True, slots=True)
class ProfileSettings:
    profile_id: str
    revision: int
    etag: str
    display_name: str
    title: str
    avatar: str
    notification_preferences: Mapping[str, Any]
    privacy_preferences: Mapping[str, Any]
    approval_policy: Mapping[str, str]
    persona: str = ""
    model: str = ""
    provider: str = ""
    reasoning: str = ""
    skills: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        """Return the intentionally narrow mobile projection."""

        return {
            "profile_id": self.profile_id,
            "revision": self.revision,
            "etag": self.etag,
            "display_name": self.display_name,
            "title": self.title,
            "avatar": self.avatar,
            "notification_preferences": dict(self.notification_preferences),
            "privacy_preferences": dict(self.privacy_preferences),
            "approval_policy": dict(self.approval_policy),
            "persona": self.persona,
            "model": self.model,
            "provider": self.provider,
            "reasoning": self.reasoning,
            "skills": list(self.skills),
        }


@dataclass(frozen=True, slots=True)
class SettingsAudit:
    audit_id: str
    profile_id: str
    actor_id: str
    action: str
    revision: int
    changed_fields: tuple[str, ...]
    context_digest: str
    created_at: float


@dataclass(frozen=True, slots=True)
class RollbackSnapshot:
    snapshot_id: str
    profile_id: str
    revision: int
    created_at: float


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
        raise SettingsValidation("setting values must be JSON data") from exc
    if len(encoded.encode("utf-8")) > _MAX_JSON_BYTES:
        raise SettingsValidation("setting values are too large")
    return encoded


def context_digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def changes_digest(changes: Mapping[str, Any]) -> str:
    return context_digest(dict(changes))


def step_up_context(
    *, instance_id: str, profile_id: str, revision: int, changes: Mapping[str, Any]
) -> dict[str, Any]:
    """Build the exact context that must be signed for a sensitive write."""

    return {
        "action": "settings.step_up.write",
        "instance_id": instance_id,
        "profile_id": profile_id,
        "revision": revision,
        "changes_digest": changes_digest(changes),
    }


def rollback_step_up_context(
    *, instance_id: str, profile_id: str, revision: int, snapshot_id: str
) -> dict[str, Any]:
    return {
        "action": "settings.rollback",
        "instance_id": instance_id,
        "profile_id": profile_id,
        "revision": revision,
        "snapshot_id": snapshot_id,
    }


def _token(value: str, field: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise SettingsValidation(f"invalid {field}")
    return value


def _profile(value: str) -> str:
    return _token(value, "profile identifier")


def _actor(value: str) -> str:
    return _token(value, "actor identifier")


def _uuid(value: str, field: str) -> str:
    try:
        UUID(value)
    except (TypeError, ValueError) as exc:
        raise SettingsValidation(f"invalid {field}") from exc
    return value


def _copy_json(value: Any, field: str) -> Any:
    encoded = _canonical(value)
    try:
        result = json.loads(encoded)
    except json.JSONDecodeError as exc:  # pragma: no cover - _canonical emits valid JSON
        raise SettingsValidation(f"invalid {field}") from exc
    if not isinstance(result, (dict, list, str, int, float, bool, type(None))):
        raise SettingsValidation(f"invalid {field}")
    return result


class MobileSettingsStore:
    """SQLite-backed profile settings with server-owned authorization policy."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        profile_allowlist: Iterable[str],
        instance_id: str,
        model_allowlist: Iterable[str] = (),
        provider_allowlist: Iterable[str] = (),
        skill_allowlist: Iterable[str] = (),
        initial_profiles: Mapping[str, Mapping[str, Any]] | None = None,
        step_up: Any | None = None,
        clock=time.time,
    ) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._profiles = frozenset(_profile(value) for value in profile_allowlist)
        self._instance_id = _token(instance_id, "instance identifier")
        self._models = frozenset(_token(value, "model") for value in model_allowlist)
        self._providers = frozenset(_token(value, "provider") for value in provider_allowlist)
        self._skills = frozenset(_token(value, "skill") for value in skill_allowlist)
        self._step_up = step_up
        self._clock = clock
        self._locks: dict[str, Lock] = {}
        self._locks_guard = RLock()
        self._initialize()
        if initial_profiles:
            self._seed_profiles(initial_profiles)

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
                CREATE TABLE IF NOT EXISTS mobile_settings_profiles (
                    profile_id TEXT PRIMARY KEY,
                    revision INTEGER NOT NULL,
                    values_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS mobile_settings_rollbacks (
                    snapshot_id TEXT PRIMARY KEY,
                    profile_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    values_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS mobile_settings_audit (
                    audit_id TEXT PRIMARY KEY,
                    profile_id TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    changed_fields_json TEXT NOT NULL,
                    context_digest TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS mobile_settings_idempotency (
                    actor_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    body_digest TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    PRIMARY KEY (actor_id, action, idempotency_key)
                );
                """
            )

    def _profile_lock(self, profile_id: str) -> Lock:
        with self._locks_guard:
            return self._locks.setdefault(profile_id, Lock())

    def _require_profile(self, profile_id: str) -> str:
        profile_id = _profile(profile_id)
        if profile_id not in self._profiles:
            raise SettingsNotFound("profile settings not found")
        return profile_id

    def _seed_profiles(self, profiles: Mapping[str, Mapping[str, Any]]) -> None:
        for profile_id, values in profiles.items():
            profile_id = self._require_profile(profile_id)
            normalized = self._normalize_initial(values)
            with self._profile_lock(profile_id), self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT 1 FROM mobile_settings_profiles WHERE profile_id = ?", (profile_id,)
                ).fetchone()
                if existing is None:
                    now = float(self._clock())
                    connection.execute(
                        "INSERT INTO mobile_settings_profiles VALUES (?, ?, ?, ?, ?)",
                        (profile_id, 1, _canonical(normalized), now, now),
                    )
                connection.commit()

    def _normalize_initial(self, values: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(values, Mapping):
            raise SettingsValidation("initial profile values must be an object")
        normalized = {
            "display_name": "",
            "title": "",
            "avatar": "",
            "notification_preferences": {},
            "privacy_preferences": {},
            "approval_policy": {},
            "persona": "",
            "model": "",
            "provider": "",
            "reasoning": "",
            "skills": [],
        }
        for key, value in values.items():
            if key not in normalized:
                raise SettingsValidation(f"unsupported profile field: {key}")
            normalized[key] = self._validate_value(key, value)
        self._validate_sensitive_allowlists(normalized)
        return normalized

    def get(self, profile_id: str) -> ProfileSettings:
        profile_id = self._require_profile(profile_id)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM mobile_settings_profiles WHERE profile_id = ?", (profile_id,)
            ).fetchone()
        if row is None:
            raise SettingsNotFound("profile settings not found")
        return self._from_row(row)

    def update(
        self,
        profile_id: str,
        *,
        actor_id: str,
        if_match: str,
        changes: Mapping[str, Any],
        idempotency_key: str | None = None,
    ) -> ProfileSettings:
        profile_id = self._require_profile(profile_id)
        actor_id = _actor(actor_id)
        if not isinstance(changes, Mapping) or not changes:
            raise SettingsValidation("changes must be a non-empty object")
        if set(changes) - _SAFE_FIELDS:
            if set(changes) & _SENSITIVE_FIELDS:
                raise StepUpRequired("sensitive settings require step-up")
            raise SettingsValidation("unsupported profile setting")
        normalized = {key: self._validate_value(key, value) for key, value in changes.items()}
        return self._mutate(
            profile_id,
            actor_id=actor_id,
            if_match=if_match,
            changes=normalized,
            action="settings.update",
            idempotency_key=idempotency_key,
        )

    def update_sensitive(
        self,
        profile_id: str,
        *,
        actor_id: str,
        if_match: str,
        changes: Mapping[str, Any],
        challenge: Any,
        signature: str,
        context: Mapping[str, Any],
        idempotency_key: str | None = None,
    ) -> ProfileSettings:
        profile_id = self._require_profile(profile_id)
        actor_id = _actor(actor_id)
        if not isinstance(changes, Mapping) or not changes or set(changes) - _SENSITIVE_FIELDS:
            raise SettingsValidation("only sensitive settings belong in this operation")
        normalized = {key: self._validate_value(key, value) for key, value in changes.items()}
        current = self.get(profile_id)
        expected = step_up_context(
            instance_id=self._instance_id,
            profile_id=profile_id,
            revision=current.revision,
            changes=normalized,
        )
        if dict(context) != expected:
            raise StepUpRequired("step-up context does not match this write")
        if self._step_up is None:
            raise StepUpRequired("step-up verifier is unavailable")
        try:
            self._step_up.verify(challenge, context=expected, signature=signature, now=float(self._clock()))
        except Exception as exc:
            raise StepUpRequired("step-up authorization is invalid") from exc
        self._validate_sensitive_allowlists(normalized)
        return self._mutate(
            profile_id,
            actor_id=actor_id,
            if_match=if_match,
            changes=normalized,
            action="settings.step_up.write",
            idempotency_key=idempotency_key,
        )

    def rollback(
        self,
        profile_id: str,
        *,
        actor_id: str,
        if_match: str,
        snapshot_id: str,
        challenge: Any,
        signature: str,
        context: Mapping[str, Any],
    ) -> ProfileSettings:
        profile_id = self._require_profile(profile_id)
        actor_id = _actor(actor_id)
        snapshot_id = _uuid(snapshot_id, "snapshot identifier")
        current = self.get(profile_id)
        expected = rollback_step_up_context(
            instance_id=self._instance_id,
            profile_id=profile_id,
            revision=current.revision,
            snapshot_id=snapshot_id,
        )
        if dict(context) != expected:
            raise StepUpRequired("step-up context does not match rollback")
        if self._step_up is None:
            raise StepUpRequired("step-up verifier is unavailable")
        try:
            self._step_up.verify(challenge, context=expected, signature=signature, now=float(self._clock()))
        except Exception as exc:
            raise StepUpRequired("step-up authorization is invalid") from exc
        lock = self._profile_lock(profile_id)
        with lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._row_locked(connection, profile_id)
            self._check_match(row, if_match)
            snapshot = connection.execute(
                "SELECT values_json, revision FROM mobile_settings_rollbacks "
                "WHERE snapshot_id = ? AND profile_id = ?",
                (snapshot_id, profile_id),
            ).fetchone()
            if snapshot is None:
                connection.rollback()
                raise SettingsNotFound("rollback snapshot not found")
            values = json.loads(snapshot["values_json"])
            result = self._write_locked(
                connection,
                row,
                values,
                actor_id=actor_id,
                action="settings.rollback",
                changed_fields=tuple(sorted(values)),
                context_value=expected,
            )
            connection.commit()
            return result

    def rollback_snapshots(self, profile_id: str) -> tuple[RollbackSnapshot, ...]:
        profile_id = self._require_profile(profile_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT snapshot_id, profile_id, revision, created_at "
                "FROM mobile_settings_rollbacks WHERE profile_id = ? ORDER BY revision",
                (profile_id,),
            ).fetchall()
        return tuple(RollbackSnapshot(row[0], row[1], row[2], row[3]) for row in rows)

    def audit(self, profile_id: str) -> tuple[SettingsAudit, ...]:
        profile_id = self._require_profile(profile_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM mobile_settings_audit WHERE profile_id = ? ORDER BY created_at, audit_id",
                (profile_id,),
            ).fetchall()
        return tuple(
            SettingsAudit(
                row["audit_id"],
                row["profile_id"],
                row["actor_id"],
                row["action"],
                row["revision"],
                tuple(json.loads(row["changed_fields_json"])),
                row["context_digest"],
                row["created_at"],
            )
            for row in rows
        )

    def _mutate(
        self,
        profile_id: str,
        *,
        actor_id: str,
        if_match: str,
        changes: Mapping[str, Any],
        action: str,
        idempotency_key: str | None,
    ) -> ProfileSettings:
        if idempotency_key is not None:
            idempotency_key = _token(idempotency_key, "idempotency key")
        body_digest = changes_digest(changes)
        lock = self._profile_lock(profile_id)
        with lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if idempotency_key is not None:
                prior = connection.execute(
                    "SELECT body_digest, result_json FROM mobile_settings_idempotency "
                    "WHERE actor_id = ? AND action = ? AND idempotency_key = ?",
                    (actor_id, action, idempotency_key),
                ).fetchone()
                if prior is not None:
                    if prior["body_digest"] != body_digest:
                        connection.rollback()
                        raise SettingsConflict("idempotency key conflicts with another body")
                    result = self._from_dict(json.loads(prior["result_json"]))
                    connection.commit()
                    return result
            row = self._row_locked(connection, profile_id)
            self._check_match(row, if_match)
            old = json.loads(row["values_json"])
            merged = dict(old)
            for key, value in changes.items():
                if key == "approval_policy":
                    merged[key] = self._tighten_policy(old.get(key, {}), value)
                else:
                    merged[key] = value
            self._validate_sensitive_allowlists(merged)
            result = self._write_locked(
                connection,
                row,
                merged,
                actor_id=actor_id,
                action=action,
                changed_fields=tuple(sorted(changes)),
                context_value=changes,
            )
            if idempotency_key is not None:
                connection.execute(
                    "INSERT INTO mobile_settings_idempotency VALUES (?, ?, ?, ?, ?)",
                    (actor_id, action, idempotency_key, body_digest, _canonical(result.as_dict())),
                )
            connection.commit()
            return result

    def _write_locked(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        values: Mapping[str, Any],
        *,
        actor_id: str,
        action: str,
        changed_fields: tuple[str, ...],
        context_value: Any,
    ) -> ProfileSettings:
        profile_id = row["profile_id"]
        old_revision = int(row["revision"])
        new_revision = old_revision + 1
        now = float(self._clock())
        snapshot_id = str(uuid4())
        connection.execute(
            "INSERT INTO mobile_settings_rollbacks VALUES (?, ?, ?, ?, ?)",
            (snapshot_id, profile_id, old_revision, row["values_json"], now),
        )
        connection.execute(
            "UPDATE mobile_settings_profiles SET revision = ?, values_json = ?, updated_at = ? "
            "WHERE profile_id = ? AND revision = ?",
            (new_revision, _canonical(values), now, profile_id, old_revision),
        )
        connection.execute(
            "INSERT INTO mobile_settings_audit VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid4()),
                profile_id,
                actor_id,
                action,
                new_revision,
                _canonical(list(changed_fields)),
                context_digest(context_value),
                now,
            ),
        )
        return ProfileSettings(
            profile_id=profile_id,
            revision=new_revision,
            etag=self._etag(new_revision),
            **dict(values),
        )

    def _row_locked(self, connection: sqlite3.Connection, profile_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM mobile_settings_profiles WHERE profile_id = ?", (profile_id,)
        ).fetchone()
        if row is None:
            raise SettingsNotFound("profile settings not found")
        return row

    def _check_match(self, row: sqlite3.Row, if_match: str) -> None:
        if not isinstance(if_match, str) or if_match != self._etag(int(row["revision"])):
            raise SettingsConflict("If-Match does not identify the current revision")

    @staticmethod
    def _etag(revision: int) -> str:
        return f'"settings-{revision}"'

    def _from_row(self, row: sqlite3.Row) -> ProfileSettings:
        return self._from_dict(
            {
                "profile_id": row["profile_id"],
                "revision": row["revision"],
                "etag": self._etag(row["revision"]),
                **json.loads(row["values_json"]),
            }
        )

    @staticmethod
    def _from_dict(value: Mapping[str, Any]) -> ProfileSettings:
        return ProfileSettings(
            profile_id=value["profile_id"],
            revision=int(value["revision"]),
            etag=value["etag"],
            display_name=value.get("display_name", ""),
            title=value.get("title", ""),
            avatar=value.get("avatar", ""),
            notification_preferences=dict(value.get("notification_preferences", {})),
            privacy_preferences=dict(value.get("privacy_preferences", {})),
            approval_policy=dict(value.get("approval_policy", {})),
            persona=value.get("persona", ""),
            model=value.get("model", ""),
            provider=value.get("provider", ""),
            reasoning=value.get("reasoning", ""),
            skills=tuple(value.get("skills", ())),
        )

    def _validate_value(self, key: str, value: Any) -> Any:
        if key in {"display_name", "title", "avatar", "persona"}:
            if not isinstance(value, str) or len(value) > (16_384 if key == "persona" else 256):
                raise SettingsValidation(f"invalid {key}")
            return value
        if key in {"notification_preferences", "privacy_preferences"}:
            if not isinstance(value, Mapping):
                raise SettingsValidation(f"{key} must be an object")
            return _copy_json(value, key)
        if key == "approval_policy":
            return self._validate_policy(value)
        if key in {"model", "provider", "reasoning"}:
            if not isinstance(value, str) or not value or len(value) > 128:
                raise SettingsValidation(f"invalid {key}")
            return value
        if key == "skills":
            if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
                raise SettingsValidation("skills must be a list")
            skills = tuple(value)
            if len(skills) > 128 or any(not isinstance(skill, str) for skill in skills):
                raise SettingsValidation("invalid skills")
            return list(skills)
        raise SettingsValidation(f"unsupported profile field: {key}")

    @staticmethod
    def _validate_policy(value: Any) -> dict[str, str]:
        if not isinstance(value, Mapping) or len(value) > 128:
            raise SettingsValidation("approval_policy must be an object")
        result: dict[str, str] = {}
        for action, mode in value.items():
            if not isinstance(action, str) or not _TOKEN.fullmatch(action):
                raise SettingsValidation("invalid approval policy action")
            if mode not in _POLICY_RANK:
                raise SettingsValidation("invalid approval policy mode")
            result[action] = mode
        return result

    @classmethod
    def _tighten_policy(cls, old: Mapping[str, str], requested: Mapping[str, str]) -> dict[str, str]:
        old = cls._validate_policy(old)
        requested = cls._validate_policy(requested)
        result = dict(old)
        for action, mode in requested.items():
            current = old.get(action, "allow")
            if _POLICY_RANK[mode] >= _POLICY_RANK[current]:
                raise SettingsForbidden("mobile cannot weaken approval policy")
            result[action] = mode
        return result

    def _validate_sensitive_allowlists(self, values: Mapping[str, Any]) -> None:
        if values.get("model") and values["model"] not in self._models:
            raise SettingsForbidden("model is not host-approved")
        if values.get("provider") and values["provider"] not in self._providers:
            raise SettingsForbidden("provider is not host-approved")
        if values.get("reasoning") and values["reasoning"] not in _VALID_REASONING_EFFORTS:
            raise SettingsForbidden("reasoning is not host-approved")
        if any(skill not in self._skills for skill in values.get("skills", ())):
            raise SettingsForbidden("skill is not host-approved")
