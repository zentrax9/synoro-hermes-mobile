from __future__ import annotations

from uuid import uuid4

import pytest

from hermes_cli.mobile_catalog import (
    CatalogEntry,
    CatalogForbidden,
    CatalogNotFound,
    MobileCatalog,
)


def _catalog() -> MobileCatalog:
    return MobileCatalog(
        entries=(
            CatalogEntry(
                entry_id=str(uuid4()),
                kind="model",
                key="model-safe",
                label="Safe model",
                summary="A host-approved model",
                profiles=("profile-1",),
            ),
            CatalogEntry(
                entry_id=str(uuid4()),
                kind="provider",
                key="provider-safe",
                label="Safe provider",
                summary="A host-approved provider",
                profiles=("profile-1",),
            ),
            CatalogEntry(
                entry_id=str(uuid4()),
                kind="skill",
                key="skill-safe",
                label="Safe skill",
                summary="A host-approved skill",
                profiles=("profile-1",),
            ),
        ),
        profile_allowlist=("profile-1",),
        model_allowlist=("model-safe",),
        provider_allowlist=("provider-safe",),
        skill_allowlist=("skill-safe",),
    )


def test_catalog_is_server_owned_and_profile_scoped() -> None:
    catalog = _catalog()

    snapshot = catalog.list("profile-1")

    assert snapshot.etag == catalog.etag
    assert {entry.key for entry in snapshot.entries} == {
        "model-safe",
        "provider-safe",
        "skill-safe",
    }
    with pytest.raises(CatalogNotFound):
        catalog.list("profile-2")
    with pytest.raises(CatalogNotFound):
        catalog.get("profile-2", snapshot.entries[0].entry_id)


def test_catalog_rejects_client_side_allowlist_widening() -> None:
    catalog = _catalog()

    with pytest.raises(CatalogForbidden):
        catalog.validate_selection(
            "profile-1",
            model="model-not-approved",
            provider="provider-safe",
            reasoning="high",
        )
    with pytest.raises(CatalogForbidden):
        catalog.validate_selection(
            "profile-1",
            model="model-safe",
            provider="provider-not-approved",
            reasoning="high",
        )


def test_catalog_exposes_safe_projection_only() -> None:
    catalog = _catalog()
    entry = catalog.list("profile-1").entries[0]

    assert entry.entry_id
    assert entry.label
    assert not hasattr(entry, "secret")
    assert not hasattr(entry, "credential_status")
    assert catalog.validate_selection(
        "profile-1",
        model="model-safe",
        provider="provider-safe",
        reasoning="low",
        skills=(skill for skill in ("skill-safe",)),
    ).skills == ("skill-safe",)
