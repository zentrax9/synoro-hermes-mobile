from __future__ import annotations

from dataclasses import dataclass
from threading import Event
import time
from uuid import uuid4

import pytest

from hermes_cli.mobile_routine_worker import (
    MobileRoutineWorker,
    RoutineExecutionRejected,
    RoutineWorkerUnavailable,
)
from hermes_cli.mobile_routines import MobileRoutineService, RoutineDefinition


@dataclass
class _Challenge:
    context: dict[str, object]


class _StepUp:
    def verify(self, challenge, *, context, signature, now=None) -> None:
        assert challenge.context == dict(context)
        assert signature == "valid-signature"


def _service(tmp_path, *, lease_seconds: float = 1.0):
    routine_id = str(uuid4())
    service = MobileRoutineService(
        tmp_path / "routines.sqlite3",
        instance_id="instance-1",
        profile_allowlist=("profile-1",),
        routines=(RoutineDefinition(routine_id, "profile-1", "Safe", "Display only"),),
        step_up=_StepUp(),
        lease_seconds=lease_seconds,
    )
    return service, routine_id


def _claim(service, routine_id: str, key: str = "key-1", body=None):
    body = {} if body is None else body
    context = service.run_context("profile-1", routine_id, key, body=body)
    return service.run(
        "profile-1",
        routine_id,
        actor_id="device-1",
        idempotency_key=key,
        body=body,
        challenge=_Challenge(context),
        signature="valid-signature",
        context=context,
    )


def test_worker_executes_with_trusted_definition_and_ephemeral_json_input(tmp_path):
    service, routine_id = _service(tmp_path)
    claim = _claim(service, routine_id, body={"value": "x"})
    seen = {}
    done = Event()

    def execute(*, routine, profile_name, input, run_id, actor_id):
        seen.update(
            routine_id=routine.routine_id,
            summary=routine.summary,
            profile_name=profile_name,
            input=input,
            run_id=run_id,
            actor_id=actor_id,
        )
        done.set()
        return {"ok": True}

    worker = MobileRoutineWorker(service, execute)
    try:
        worker.submit(
            claim,
            profile_name="profile-1",
            routine=service.definition("profile-1", routine_id),
            input={"value": "x"},
        )
        assert done.wait(2)
        for _ in range(20):
            if service.get_run(claim.run_id).status == "completed":
                break
            time.sleep(0.01)
        assert service.get_run(claim.run_id).result == {"ok": True}
        assert seen["routine_id"] == routine_id
        assert seen["summary"] == "Display only"
        assert seen["input"] == {"value": "x"}
    finally:
        worker.close()


def test_executor_failure_is_indeterminate_and_not_retried(tmp_path):
    service, routine_id = _service(tmp_path)
    claim = _claim(service, routine_id)
    attempts = 0
    failed = Event()

    def execute(**_kwargs):
        nonlocal attempts
        attempts += 1
        failed.set()
        raise RuntimeError("provider uncertain")

    worker = MobileRoutineWorker(service, execute)
    try:
        worker.submit(
            claim,
            profile_name="profile-1",
            routine=service.definition("profile-1", routine_id),
            input=None,
        )
        assert failed.wait(2)
        for _ in range(20):
            if service.get_run(claim.run_id).status == "indeterminate":
                break
            time.sleep(0.01)
        assert service.get_run(claim.run_id).status == "indeterminate"
        assert attempts == 1
    finally:
        worker.close()


def test_cancellation_after_worker_claim_is_indeterminate_and_late_result_is_fenced(tmp_path):
    service, routine_id = _service(tmp_path)
    claim = _claim(service, routine_id)
    entered = Event()
    release = Event()
    done = Event()
    attempts = 0

    def execute(**_kwargs):
        nonlocal attempts
        attempts += 1
        entered.set()
        assert release.wait(2)
        done.set()
        return {"late": True}

    worker = MobileRoutineWorker(service, execute)
    try:
        worker.submit(
            claim,
            profile_name="profile-1",
            routine=service.definition("profile-1", routine_id),
            input={},
        )
        assert entered.wait(2)
        cancelled = service.cancel(claim.run_id, actor_id="device-1")
        assert cancelled.status == "indeterminate"
        release.set()
        assert done.wait(2)
        for _ in range(50):
            if service.get_run(claim.run_id).status == "indeterminate":
                break
            time.sleep(0.01)
        final = service.get_run(claim.run_id)
        assert final.status == "indeterminate"
        assert final.started_at is not None
        assert attempts == 1
    finally:
        release.set()
        worker.close()


def test_rejected_execution_fails_deterministically(tmp_path):
    service, routine_id = _service(tmp_path)
    claim = _claim(service, routine_id)

    def execute(**_kwargs):
        raise RoutineExecutionRejected

    worker = MobileRoutineWorker(service, execute)
    try:
        worker.submit(
            claim,
            profile_name="profile-1",
            routine=service.definition("profile-1", routine_id),
            input={},
        )
        for _ in range(50):
            if service.get_run(claim.run_id).status == "failed":
                break
            time.sleep(0.01)
        assert service.get_run(claim.run_id).result == {"error": "routine_execution_rejected"}
    finally:
        worker.close()


def test_worker_rejects_mismatched_definition_and_unbounded_input(tmp_path):
    service, routine_id = _service(tmp_path)
    claim = _claim(service, routine_id)
    worker = MobileRoutineWorker(service, lambda **_kwargs: None)
    try:
        with pytest.raises(RoutineWorkerUnavailable):
            worker.submit(
                claim,
                profile_name="profile-1",
                routine=RoutineDefinition(str(uuid4()), "profile-1", "other", "other"),
                input={},
            )
        with pytest.raises(ValueError):
            worker.submit(
                claim,
                profile_name="profile-1",
                routine=service.definition("profile-1", routine_id),
                input={"x": "a" * 300_000},
            )
    finally:
        worker.close()
