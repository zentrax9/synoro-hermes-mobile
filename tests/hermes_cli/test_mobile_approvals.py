from __future__ import annotations

from dataclasses import dataclass

import pytest

from hermes_cli.mobile_approvals import (
    ApprovalAlreadyResolved,
    ApprovalContext,
    ApprovalExpired,
    ApprovalNotFound,
    MobileApprovalStore,
)


@dataclass
class _Challenge:
    context: dict[str, object]


class _StepUp:
    def verify(self, challenge, *, context, signature, now=None) -> None:
        assert challenge.context == dict(context)
        assert signature == "valid-signature"


def _context(profile: str = "profile-1") -> ApprovalContext:
    return ApprovalContext(
        instance_id="instance-1",
        profile_id=profile,
        session_id="session-opaque",
        run_id="run-opaque",
        tool_call_id="call-opaque",
        request_id="request-opaque",
        arguments_digest="a" * 64,
        expires_at=500.0,
    )


def test_approval_supports_approve_once_or_deny_only_and_is_durable(tmp_path) -> None:
    store = MobileApprovalStore(
        tmp_path / "approvals.sqlite3",
        instance_id="instance-1",
        profile_allowlist=("profile-1",),
        step_up=_StepUp(),
        clock=lambda: 100.0,
    )
    pending = store.create(
        actor_id="device-1",
        context=_context(),
        summary="A safe, redacted approval summary",
    )

    with pytest.raises(ValueError):
        store.decide(
            pending.approval_id,
            actor_id="device-1",
            decision="always",
            context=pending.context,
        )
    approved = store.decide(
        pending.approval_id,
        actor_id="device-1",
        decision="approve_once",
        context=pending.context,
        challenge=_Challenge(pending.context.as_dict()),
        signature="valid-signature",
    )
    assert approved.status == "approved"
    with pytest.raises(ApprovalAlreadyResolved):
        store.decide(
            pending.approval_id,
            actor_id="device-1",
            decision="deny",
            context=pending.context,
        )

    reopened = MobileApprovalStore(
        tmp_path / "approvals.sqlite3",
        instance_id="instance-1",
        profile_allowlist=("profile-1",),
        step_up=_StepUp(),
        clock=lambda: 100.0,
    )
    assert reopened.get(pending.approval_id).status == "approved"


def test_approval_expiry_and_cross_profile_are_fail_closed(tmp_path) -> None:
    store = MobileApprovalStore(
        tmp_path / "approvals.sqlite3",
        instance_id="instance-1",
        profile_allowlist=("profile-1",),
        clock=lambda: 600.0,
    )
    pending = store.create(
        actor_id="device-1",
        context=_context(),
        summary="expired",
    )
    with pytest.raises(ApprovalExpired):
        store.decide(
            pending.approval_id,
            actor_id="device-1",
            decision="deny",
            context=pending.context,
        )
    with pytest.raises(ApprovalNotFound):
        store.get(pending.approval_id, profile_id="profile-2")


def test_approval_context_is_exact_and_does_not_expose_tool_arguments(tmp_path) -> None:
    store = MobileApprovalStore(
        tmp_path / "approvals.sqlite3",
        instance_id="instance-1",
        profile_allowlist=("profile-1",),
    )
    context = _context()
    pending = store.create(actor_id="device-1", context=context, summary="safe")
    assert pending.context.arguments_digest == "a" * 64
    assert "arguments" not in pending.as_dict()
    assert "secret" not in pending.as_dict()
