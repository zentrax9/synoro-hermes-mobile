"""Stable opaque identifiers for server-side Hermes profile objects."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3
import threading
from collections.abc import Iterable
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class MobileProfileBinding:
    instance_id: UUID
    opaque_profile_id: UUID
    profile_name: str


class MobileObjectRegistry:
    """Persist mappings without deriving identifiers from names or paths."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.db_path,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute("PRAGMA synchronous = FULL")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS mobile_object_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS mobile_profile_bindings (
                profile_name TEXT PRIMARY KEY,
                opaque_profile_id TEXT NOT NULL UNIQUE
            );
            """
        )
        row = self._connection.execute(
            "SELECT value FROM mobile_object_metadata WHERE key = 'instance_id'"
        ).fetchone()
        if row is None:
            value = str(uuid4())
            self._connection.execute(
                "INSERT INTO mobile_object_metadata (key, value) VALUES ('instance_id', ?)",
                (value,),
            )
        else:
            value = str(row["value"])
        self.instance_id = UUID(value)

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "MobileObjectRegistry":
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()

    def profiles(self, profile_names: tuple[str, ...] | list[str]) -> tuple[MobileProfileBinding, ...]:
        if not profile_names:
            return ()
        if any(
            not isinstance(name, str)
            or not name
            or len(name) > 128
            or any(ord(character) < 0x20 for character in name)
            for name in profile_names
        ):
            raise ValueError("profile names must be non-empty safe strings")
        if len(set(profile_names)) != len(profile_names):
            raise ValueError("profile names must be unique")
        result: list[MobileProfileBinding] = []
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                for profile_name in profile_names:
                    row = self._connection.execute(
                        "SELECT opaque_profile_id FROM mobile_profile_bindings WHERE profile_name = ?",
                        (profile_name,),
                    ).fetchone()
                    if row is None:
                        opaque_id = str(uuid4())
                        self._connection.execute(
                            "INSERT INTO mobile_profile_bindings (profile_name, opaque_profile_id) "
                            "VALUES (?, ?)",
                            (profile_name, opaque_id),
                        )
                    else:
                        opaque_id = str(row["opaque_profile_id"])
                    result.append(
                        MobileProfileBinding(
                            instance_id=self.instance_id,
                            opaque_profile_id=UUID(opaque_id),
                            profile_name=profile_name,
                        )
                    )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        return tuple(result)

    def reconcile_profiles(self, live_profile_names: Iterable[str]) -> tuple[str, ...]:
        """Remove bindings for profiles that are no longer live in the host.

        The mobile registry is the durable source for opaque profile identifiers, but it must
        not keep advertising a deleted/tombstoned host directory forever.  Reconciliation is
        deliberately delete-only: a rename is treated as a new host object and therefore gets a
        fresh opaque identifier when it is materialized later; an old identifier can never be
        silently remapped to the new name.  Callers should pass the already canonicalized,
        host-verified allowlist.

        Returns the canonical profile names whose bindings were removed.  No profile contents,
        credentials, or settings are touched here; those stores fail closed when their profile
        principal can no longer be resolved.
        """

        names = tuple(live_profile_names)
        if any(
            not isinstance(name, str)
            or not name
            or len(name) > 128
            or any(ord(character) < 0x20 for character in name)
            for name in names
        ):
            raise ValueError("profile names must be non-empty safe strings")
        if len(set(names)) != len(names):
            raise ValueError("profile names must be unique")
        live = set(names)
        removed: list[str] = []
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                rows = self._connection.execute(
                    "SELECT profile_name FROM mobile_profile_bindings"
                ).fetchall()
                removed = [
                    str(row["profile_name"])
                    for row in rows
                    if str(row["profile_name"]) not in live
                ]
                if removed:
                    self._connection.executemany(
                        "DELETE FROM mobile_profile_bindings WHERE profile_name = ?",
                        ((name,) for name in removed),
                    )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        return tuple(sorted(removed))

    def resolve_profile(self, opaque_profile_id: UUID | str, allowed: set[str]) -> str:
        try:
            canonical = str(UUID(str(opaque_profile_id)))
        except (TypeError, ValueError, AttributeError) as exc:
            raise KeyError("unknown mobile profile") from exc
        with self._lock:
            row = self._connection.execute(
                "SELECT profile_name FROM mobile_profile_bindings WHERE opaque_profile_id = ?",
                (canonical,),
            ).fetchone()
        if row is None or str(row["profile_name"]) not in allowed:
            raise KeyError("unknown mobile profile")
        return str(row["profile_name"])

    def binding_for_profile(self, profile_name: str) -> MobileProfileBinding:
        """Return the persistent opaque binding for a server-owned profile.

        This is intentionally a read-only lookup.  Mobile responses must never
        need to create an identifier while serializing an already-authorized
        object (which could otherwise mask stale database state).
        """

        if (
            not isinstance(profile_name, str)
            or not profile_name
            or len(profile_name) > 128
            or any(ord(character) < 0x20 for character in profile_name)
        ):
            raise KeyError("unknown mobile profile")
        with self._lock:
            row = self._connection.execute(
                "SELECT opaque_profile_id FROM mobile_profile_bindings WHERE profile_name = ?",
                (profile_name,),
            ).fetchone()
        if row is None:
            raise KeyError("unknown mobile profile")
        return MobileProfileBinding(
            instance_id=self.instance_id,
            opaque_profile_id=UUID(str(row["opaque_profile_id"])),
            profile_name=profile_name,
        )
