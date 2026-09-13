from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

import pytest

from hermes_cli.mobile_settings import (
    SettingsConflict,
    SettingsForbidden,
    SettingsNotFound,
    MobileSettingsStore,
    step_up_context,
)


@dataclass
class _Challenge:
    context: dict[str, object]


class _StepUp:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def verify(self, challenge, *, context, signature, now=None) -> None:
        assert challenge.context == dict(context)
        assert signature == "valid-signature"
        self.calls.append(dict(context))


def _store(tmp_path, step_up=None) -> MobileSettingsStore:
    return MobileSettingsStore(
        tmp_path / "settings.sqlite3",
        profile_allowlist=("profile-1",),
        instance_id="instance-1",
        model_allowlist=("model-safe",),
        provider_allowlist=("provider-safe",),
        skill_allowlist=("skill-safe",),
        initial_profiles={
            "profile-1": {
                "display_name": "Hermes",
                "approval_policy": {"shell": "once"},
            }
        },
        step_up=step_up,
    )


def test_normal_settings_use_exact_etag_and_atomic_audit(tmp_path) -> None:
    store = _store(tmp_path)
    before = store.get("profile-1")

    after = store.update(
        "profile-1",
        actor_id="device-1",
        if_match=before.etag,
        changes={
            "display_name": "Hermes Mobile",
            "notification_preferences": {"push": False},
            "approval_policy": {"shell": "deny"},
        },
    )

    assert after.revision == before.revision + 1
    assert after.etag != before.etag
    assert after.display_name == "Hermes Mobile"
    assert store.audit("profile-1")[-1].changed_fields == (
        "approval_policy",
        "display_name",
        "notification_preferences",
    )
    with pytest.raises(SettingsConflict):
        store.update(
            "profile-1",
            actor_id="device-1",
            if_match=before.etag,
            changes={"display_name": "stale"},
        )


def test_mobile_can_only_tighten_approval_policy(tmp_path) -> None:
    store = _store(tmp_path)
    current = store.get("profile-1")

    with pytest.raises(SettingsForbidden):
        store.update(
            "profile-1",
            actor_id="device-1",
            if_match=current.etag,
            changes={"approval_policy": {"shell": "once"}},
        )
    tightened = store.update(
        "profile-1",
        actor_id="device-1",
        if_match=current.etag,
        changes={"approval_policy": {"shell": "deny"}},
    )
    assert tightened.approval_policy["shell"] == "deny"


def test_sensitive_settings_require_exact_single_use_step_up_context(tmp_path) -> None:
    step_up = _StepUp()
    store = _store(tmp_path, step_up=step_up)
    current = store.get("profile-1")
    changes = {
        "persona": "A concise assistant",
        "model": "model-safe",
        "provider": "provider-safe",
        "reasoning": "low",
        "skills": ["skill-safe"],
    }
    context = step_up_context(
        instance_id="instance-1",
        profile_id="profile-1",
        revision=current.revision,
        changes=changes,
    )
    challenge = _Challenge(context)

    updated = store.update_sensitive(
        "profile-1",
        actor_id="device-1",
        if_match=current.etag,
        changes=changes,
        challenge=challenge,
        signature="valid-signature",
        context=context,
    )
    assert updated.model == "model-safe"
    assert step_up.calls == [context]

    with pytest.raises(SettingsForbidden):
        store.update_sensitive(
            "profile-1",
            actor_id="device-1",
            if_match=updated.etag,
            changes={"model": "model-safe"},
            challenge=challenge,
            signature="valid-signature",
            context=context,
        )

    bad_context = dict(context)
    bad_context["changes_digest"] = sha256(b"tampered").hexdigest()
    with pytest.raises(SettingsForbidden):
        store.update_sensitive(
            "profile-1",
            actor_id="device-1",
            if_match=updated.etag,
            changes={"provider": "provider-safe"},
            challenge=_Challenge(bad_context),
            signature="valid-signature",
            context=bad_context,
        )


@pytest.mark.parametrize("effort", ["minimal", "max", "ultra"])
def test_sensitive_settings_accept_all_host_reasoning_efforts(tmp_path, effort) -> None:
    step_up = _StepUp()
    store = _store(tmp_path, step_up=step_up)
    current = store.get("profile-1")
    changes = {"reasoning": effort}
    context = step_up_context(
        instance_id="instance-1",
        profile_id="profile-1",
        revision=current.revision,
        changes=changes,
    )

    updated = store.update_sensitive(
        "profile-1",
        actor_id="device-1",
        if_match=current.etag,
        changes=changes,
        challenge=_Challenge(context),
        signature="valid-signature",
        context=context,
    )

    assert updated.reasoning == effort


def test_settings_hide_cross_profile_and_never_return_raw_config(tmp_path) -> None:
    store = _store(tmp_path)

    with pytest.raises(SettingsNotFound):
        store.get("profile-2")
    snapshot = store.get("profile-1")
    assert "api_key" not in snapshot.as_dict()
    assert "raw_config" not in snapshot.as_dict()
