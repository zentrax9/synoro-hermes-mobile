"""Server-owned, safe projections of the choices exposed to Hermes Mobile.

The mobile listener must not become a second configuration authority.  This
module therefore accepts an allowlisted catalog from the host and exposes only
opaque identifiers plus presentation-safe descriptions.  It has no access to
provider credentials, raw tool definitions, or the host configuration file.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import re
from threading import RLock
from typing import Literal
from uuid import UUID


_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_KINDS = frozenset({"model", "provider", "skill", "toolset"})
_REASONING = frozenset({"none", "low", "medium", "high", "xhigh"})


class CatalogError(RuntimeError):
    """Base class for safe mobile catalog errors."""


class CatalogNotFound(CatalogError, LookupError):
    """The profile or catalog entry is outside the caller's visible scope."""


class CatalogForbidden(CatalogError, PermissionError):
    """The host policy does not permit a requested catalog selection."""


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    """Presentation-safe catalog data.  ``key`` is never a secret or command."""

    entry_id: str
    kind: Literal["model", "provider", "skill", "toolset"]
    key: str
    label: str
    summary: str
    profiles: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        try:
            UUID(self.entry_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("catalog entry_id must be an opaque UUID") from exc
        if self.kind not in _KINDS:
            raise ValueError("unsupported catalog entry kind")
        for name, value, limit in (
            ("entry_id", self.entry_id, 64),
            ("key", self.key, 128),
            ("label", self.label, 160),
            ("summary", self.summary, 512),
        ):
            if not isinstance(value, str) or not value or len(value) > limit:
                raise ValueError(f"invalid catalog {name}")
        if not _TOKEN.fullmatch(self.key):
            raise ValueError("catalog key is not a safe identifier")
        if any(not isinstance(profile, str) or not _TOKEN.fullmatch(profile) for profile in self.profiles):
            raise ValueError("catalog profile scope is invalid")


@dataclass(frozen=True, slots=True)
class CatalogSnapshot:
    revision: int
    etag: str
    entries: tuple[CatalogEntry, ...]


@dataclass(frozen=True, slots=True)
class CatalogSelection:
    profile_id: str
    model: str
    provider: str
    reasoning: str
    skills: tuple[str, ...]


def _profile(value: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise ValueError("invalid profile identifier")
    return value


def _allowlist(values: Iterable[str] | None, *, fallback: Iterable[str] = ()) -> frozenset[str]:
    if values is None:
        values = fallback
    normalized = frozenset(values)
    if any(not isinstance(value, str) or not _TOKEN.fullmatch(value) for value in normalized):
        raise ValueError("catalog allowlist contains an invalid identifier")
    return normalized


class MobileCatalog:
    """Read-only mobile catalog backed by host-owned allowlists."""

    def __init__(
        self,
        *,
        entries: Iterable[CatalogEntry],
        profile_allowlist: Iterable[str],
        model_allowlist: Iterable[str] | None = None,
        provider_allowlist: Iterable[str] | None = None,
        skill_allowlist: Iterable[str] | None = None,
        toolset_allowlist: Iterable[str] | None = None,
        reasoning_allowlist: Iterable[str] = ("none", "low", "medium", "high"),
        revision: int = 1,
    ) -> None:
        if not isinstance(revision, int) or revision < 1:
            raise ValueError("catalog revision must be positive")
        self._profiles = frozenset(_profile(value) for value in profile_allowlist)
        raw_entries = tuple(entries)
        if any(not isinstance(entry, CatalogEntry) for entry in raw_entries):
            raise TypeError("entries must contain CatalogEntry values")
        by_id: dict[str, CatalogEntry] = {}
        for entry in raw_entries:
            if entry.entry_id in by_id:
                raise ValueError("duplicate catalog entry id")
            by_id[entry.entry_id] = entry
        self._entries = by_id
        self._models = _allowlist(
            model_allowlist,
            fallback=(entry.key for entry in raw_entries if entry.kind == "model"),
        )
        self._providers = _allowlist(
            provider_allowlist,
            fallback=(entry.key for entry in raw_entries if entry.kind == "provider"),
        )
        self._skills = _allowlist(
            skill_allowlist,
            fallback=(entry.key for entry in raw_entries if entry.kind == "skill"),
        )
        self._toolsets = _allowlist(
            toolset_allowlist,
            fallback=(entry.key for entry in raw_entries if entry.kind == "toolset"),
        )
        self._reasoning = frozenset(reasoning_allowlist)
        if not self._reasoning or not self._reasoning.issubset(_REASONING):
            raise ValueError("reasoning allowlist contains an unsupported value")
        self._revision = revision
        self._lock = RLock()

    @property
    def revision(self) -> int:
        with self._lock:
            return self._revision

    @property
    def etag(self) -> str:
        return f'"catalog-{self.revision}"'

    def list(self, profile_id: str, *, kind: str | None = None) -> CatalogSnapshot:
        profile_id = self._require_profile(profile_id)
        if kind is not None and kind not in _KINDS:
            raise ValueError("unsupported catalog kind")
        with self._lock:
            entries = tuple(
                sorted(
                    (
                        entry
                        for entry in self._entries.values()
                        if (kind is None or entry.kind == kind)
                        and (not entry.profiles or profile_id in entry.profiles)
                        and self._allowed(entry.kind, entry.key)
                    ),
                    key=lambda item: (item.kind, item.label, item.entry_id),
                )
            )
            return CatalogSnapshot(self._revision, f'"catalog-{self._revision}"', entries)

    def get(self, profile_id: str, entry_id: str) -> CatalogEntry:
        profile_id = self._require_profile(profile_id)
        try:
            UUID(entry_id)
        except (TypeError, ValueError) as exc:
            raise CatalogNotFound("catalog entry not found") from exc
        with self._lock:
            entry = self._entries.get(entry_id)
            if (
                entry is None
                or (entry.profiles and profile_id not in entry.profiles)
                or not self._allowed(entry.kind, entry.key)
            ):
                raise CatalogNotFound("catalog entry not found")
            return entry

    def validate_selection(
        self,
        profile_id: str,
        *,
        model: str,
        provider: str,
        reasoning: str,
        skills: Iterable[str] = (),
    ) -> CatalogSelection:
        profile_id = self._require_profile(profile_id)
        skill_tuple = tuple(skills)
        if (
            model not in self._models
            or provider not in self._providers
            or reasoning not in self._reasoning
            or any(skill not in self._skills for skill in skill_tuple)
        ):
            raise CatalogForbidden("selection is not host-approved")
        if any(not isinstance(skill, str) or not _TOKEN.fullmatch(skill) for skill in skill_tuple):
            raise CatalogForbidden("selection is not host-approved")
        for kind, key in (("model", model), ("provider", provider)):
            if not any(
                entry.kind == kind
                and entry.key == key
                and (not entry.profiles or profile_id in entry.profiles)
                for entry in self._entries.values()
            ):
                raise CatalogForbidden("selection is not visible for this profile")
        for skill in skill_tuple:
            if not any(
                entry.kind == "skill"
                and entry.key == skill
                and (not entry.profiles or profile_id in entry.profiles)
                for entry in self._entries.values()
            ):
                raise CatalogForbidden("selection is not visible for this profile")
        return CatalogSelection(profile_id, model, provider, reasoning, skill_tuple)

    def _require_profile(self, profile_id: str) -> str:
        profile_id = _profile(profile_id)
        if profile_id not in self._profiles:
            raise CatalogNotFound("catalog is not visible for this profile")
        return profile_id

    def _allowed(self, kind: str, key: str) -> bool:
        return key in {
            "model": self._models,
            "provider": self._providers,
            "skill": self._skills,
            "toolset": self._toolsets,
        }[kind]
