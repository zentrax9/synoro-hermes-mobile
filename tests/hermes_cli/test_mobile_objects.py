from uuid import UUID

import pytest

from hermes_cli.mobile_objects import MobileObjectRegistry


def test_profile_ids_are_random_stable_and_do_not_encode_names_or_paths(tmp_path):
    path = tmp_path / "objects.sqlite"
    registry = MobileObjectRegistry(path)
    first = registry.profiles(["private-owner-profile"])[0]
    registry.close()

    reopened = MobileObjectRegistry(path)
    second = reopened.profiles(["private-owner-profile"])[0]

    assert first.instance_id == second.instance_id
    assert first.opaque_profile_id == second.opaque_profile_id
    assert "private" not in str(first.opaque_profile_id)
    assert isinstance(UUID(str(first.opaque_profile_id)), UUID)


def test_resolution_is_always_intersected_with_the_current_host_allowlist(tmp_path):
    registry = MobileObjectRegistry(tmp_path / "objects.sqlite")
    binding = registry.profiles(["owner"])[0]

    assert registry.resolve_profile(binding.opaque_profile_id, {"owner"}) == "owner"
    with pytest.raises(KeyError):
        registry.resolve_profile(binding.opaque_profile_id, {"different"})


def test_reconcile_removes_stale_bindings_without_remapping_their_ids(tmp_path):
    registry = MobileObjectRegistry(tmp_path / "objects.sqlite")
    old, kept = registry.profiles(["renamed", "kept"])

    assert registry.reconcile_profiles(["kept"]) == ("renamed",)
    with pytest.raises(KeyError):
        registry.resolve_profile(old.opaque_profile_id, {"renamed"})
    assert registry.binding_for_profile("kept").opaque_profile_id == kept.opaque_profile_id

    replacement = registry.profiles(["renamed"])[0]
    assert replacement.opaque_profile_id != old.opaque_profile_id
