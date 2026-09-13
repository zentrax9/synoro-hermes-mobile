from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

import pytest

from hermes_cli.mobile_routines import (
    RoutineAlreadyRunning,
    RoutineConflict,
    RoutineIndeterminate,
    RoutineNotFound,
    RoutineDefinition,
    MobileRoutineService,
)


@dataclass
class _Challenge:
    context: dict[str, object]


class _StepUp:
    def verify(self, challenge, *, context, signature, now=None) -> None:
        challenge_context = getattr(challenge, "context", None)
        if challenge_context is not None:
            assert challenge_context == dict(context)
        assert signature == "valid-signature"


class _OpaqueChallenge:
    """Matches MobileStepUpStore's challenge shape: context is not exposed."""


def _service(tmp_path, *, clock=lambda: 100.0) -> tuple[MobileRoutineService, str]:
    routine_id = str(uuid4())
    return (
        MobileRoutineService(
            tmp_path / "routines.sqlite3",
            instance_id="instance-1",
            profile_allowlist=("profile-1",),
            routines=(
                RoutineDefinition(
                    routine_id=routine_id,
                    profile_id="profile-1",
                    label="Existing routine",
                    summary="A safe routine summary",
                ),
            ),
            step_up=_StepUp(),
            clock=clock,
        ),
        routine_id,
    )


def test_only_existing_routines_run_and_side_effects_are_idempotent(tmp_path) -> None:
    service, routine_id = _service(tmp_path)
    routine = service.get("profile-1", routine_id)
    context = service.run_context("profile-1", routine_id, "k-1", body={"input": "x"})
    claim = service.run(
        "profile-1",
        routine_id,
        actor_id="device-1",
        idempotency_key="k-1",
        body={"input": "x"},
        challenge=_Challenge(context),
        signature="valid-signature",
        context=context,
    )
    assert claim.status == "pending"
    assert routine.label == "Existing routine"
    with pytest.raises(RoutineAlreadyRunning):
        service.run(
            "profile-1",
            routine_id,
            actor_id="device-1",
            idempotency_key="k-1",
            body={"input": "x"},
            challenge=_Challenge(context),
            signature="valid-signature",
            context=context,
        )
    done = service.complete(claim.run_id, actor_id="device-1", result={"ok": True})
    replay = service.run(
        "profile-1",
        routine_id,
        actor_id="device-1",
        idempotency_key="k-1",
        body={"input": "x"},
        challenge=_Challenge(context),
        signature="valid-signature",
        context=context,
    )
    assert replay.result == done.result == {"ok": True}


def test_restart_marks_uncertain_work_indeterminate_without_auto_resubmit(tmp_path) -> None:
    service, routine_id = _service(tmp_path)
    context = service.run_context("profile-1", routine_id, "k-2", body={})
    claim = service.run(
        "profile-1",
        routine_id,
        actor_id="device-1",
        idempotency_key="k-2",
        body={},
        challenge=_Challenge(context),
        signature="valid-signature",
        context=context,
    )
    recovered = MobileRoutineService(
        tmp_path / "routines.sqlite3",
        instance_id="instance-1",
        profile_allowlist=("profile-1",),
        routines=service.routines("profile-1"),
        step_up=_StepUp(),
        clock=lambda: 101.0,
    )
    assert recovered.recover_uncertain() == 1
    with pytest.raises(RoutineIndeterminate):
        recovered.run(
            "profile-1",
            routine_id,
            actor_id="device-1",
            idempotency_key="k-2",
            body={},
            challenge=_Challenge(context),
            signature="valid-signature",
            context=context,
        )
    assert recovered.get_run(claim.run_id).status == "indeterminate"


def test_pause_resume_and_cross_profile_404(tmp_path) -> None:
    service, routine_id = _service(tmp_path)
    current = service.get("profile-1", routine_id)
    paused = service.pause("profile-1", routine_id, actor_id="device-1", if_match=current.etag)
    assert paused.paused
    with pytest.raises(RoutineNotFound):
        service.get("profile-2", routine_id)
    resumed = service.resume("profile-1", routine_id, actor_id="device-1", if_match=paused.etag)
    assert not resumed.paused


def test_real_step_up_shape_is_accepted_without_exposing_signed_context(tmp_path) -> None:
    service, routine_id = _service(tmp_path)
    context = service.run_context("profile-1", routine_id, "k-3", body={})
    claim = service.run(
        "profile-1",
        routine_id,
        actor_id="device-1",
        idempotency_key="k-3",
        body={},
        challenge=_OpaqueChallenge(),
        signature="valid-signature",
        context=context,
    )
    assert claim.status == "pending"


def test_started_execution_cannot_be_reported_as_cleanly_cancelled(tmp_path) -> None:
    service, routine_id = _service(tmp_path)
    context = service.run_context("profile-1", routine_id, "k-race", body={})
    claim = service.run(
        "profile-1",
        routine_id,
        actor_id="device-1",
        idempotency_key="k-race",
        body={},
        challenge=_Challenge(context),
        signature="valid-signature",
        context=context,
    )

    started = service.begin_execution(
        claim.run_id,
        actor_id=claim.actor_id,
        execution_generation=claim.execution_generation,
        fence_token=claim.fence_token,
    )
    assert started.started_at == 100.0

    cancelled = service.cancel(claim.run_id, actor_id="device-1")
    assert cancelled.status == "indeterminate"
    with pytest.raises(RoutineConflict):
        service.complete(
            claim.run_id,
            actor_id="device-1",
            result={"late": True},
            execution_generation=claim.execution_generation,
            fence_token=claim.fence_token,
        )
