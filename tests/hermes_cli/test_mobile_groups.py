from __future__ import annotations

from pathlib import Path

import pytest

from hermes_cli import mobile_groups as groups_module
from hermes_cli.mobile_groups import (
    BotSelection,
    ContentProvenance,
    CrossInstanceGroupUnsupported,
    ExecutionFenceLost,
    GroupBusy,
    GroupCapExceeded,
    GroupStopped,
    MobileGroupCoordinator,
    RoundLimitExceeded,
    TurnState,
)
from hermes_cli.mobile_group_execution import MobileGroupExecutionService


def _bots(count: int = 2, *, instance_id: str = "install-a") -> list[BotSelection]:
    return [
        BotSelection(
            instance_id=instance_id,
            profile_id=f"profile-{index}",
            display_name=f"Bot {index}",
        )
        for index in range(count)
    ]


def _coordinator(tmp_path: Path, *, clock=None) -> MobileGroupCoordinator:
    kwargs = {"instance_id": "install-a"}
    if clock is not None:
        kwargs["clock"] = clock
    return MobileGroupCoordinator(tmp_path / "groups.db", **kwargs)


def test_group_creation_uses_opaque_members_and_first_selected_coordinator(tmp_path: Path) -> None:
    coordinator = _coordinator(tmp_path)

    group = coordinator.create_group(_bots(3))

    assert len(group.members) == 3
    assert group.coordinator_member_id == group.members[0].member_id
    assert all(member.member_id != member.display_name for member in group.members)
    assert coordinator.resolve_member(group.group_id, group.members[0].member_id).member_id == (
        group.members[0].member_id
    )
    with pytest.raises(ValueError):
        coordinator.resolve_member(group.group_id, "Bot 0")


def test_list_groups_is_scoped_to_authenticated_owner_and_device(tmp_path: Path) -> None:
    coordinator = _coordinator(tmp_path)
    owned = coordinator.create_group(_bots(), owner_id="owner-a", device_id="device-a")
    second = coordinator.create_group(_bots(), owner_id="owner-a", device_id="device-a")
    coordinator.create_group(_bots(), owner_id="owner-a", device_id="device-b")
    coordinator.create_group(_bots(), owner_id="owner-b", device_id="device-a")

    listed = coordinator.list_groups(owner_id="owner-a", device_id="device-a")

    assert {group.group_id for group in listed} == {owned.group_id, second.group_id}
    assert all(group.instance_id == coordinator.instance_id for group in listed)
    first_page = coordinator.list_groups_page(owner_id="owner-a", device_id="device-a", limit=1)
    assert first_page.has_more is True
    assert first_page.next_created_at is not None
    assert first_page.next_group_id is not None
    second_page = coordinator.list_groups_page(
        owner_id="owner-a",
        device_id="device-a",
        after_created_at=first_page.next_created_at,
        after_group_id=first_page.next_group_id,
        limit=1,
    )
    assert second_page.has_more is False
    assert {group.group_id for group in first_page.groups + second_page.groups} == {
        owned.group_id,
        second.group_id,
    }
    with pytest.raises(ValueError):
        coordinator.list_groups(owner_id="", device_id="device-a")
    with pytest.raises(ValueError):
        coordinator.list_groups(owner_id="owner-a", device_id="device-a", limit=102)
    with pytest.raises(ValueError):
        coordinator.list_groups_page(
            owner_id="owner-a",
            device_id="device-a",
            after_created_at=first_page.next_created_at,
        )


def test_cross_instance_group_creation_is_rejected_as_422_equivalent(tmp_path: Path) -> None:
    coordinator = _coordinator(tmp_path)

    with pytest.raises(CrossInstanceGroupUnsupported) as exc_info:
        coordinator.create_group(_bots(2, instance_id="different-install"))

    assert exc_info.value.status_code == 422
    assert exc_info.value.code == "cross_instance_group_unsupported"


def test_membership_changes_are_busy_while_a_turn_is_active(tmp_path: Path) -> None:
    coordinator = _coordinator(tmp_path)
    group = coordinator.create_group(_bots())
    turn = coordinator.start_turn(group.group_id, content={"text": "hello"})

    with pytest.raises(GroupBusy):
        coordinator.add_member(group.group_id, _bots(1)[0])
    with pytest.raises(GroupBusy):
        coordinator.remove_member(group.group_id, group.members[1].member_id)
    assert turn.state is TurnState.ACTIVE


def test_three_round_and_ten_response_caps_are_enforced(tmp_path: Path) -> None:
    coordinator = _coordinator(tmp_path)
    group = coordinator.create_group(_bots())
    turn = coordinator.start_turn(group.group_id, content={"text": "hello"})

    for index in range(3):
        claim = coordinator.claim_response(turn.turn_id, group.members[0].member_id)
        turn = coordinator.complete_response(
            claim,
            content={"text": f"round-{index}"},
            provenance=ContentProvenance.BOT,
            round_complete=True,
        )

    with pytest.raises(RoundLimitExceeded):
        coordinator.claim_response(turn.turn_id, group.members[0].member_id)

    second_turn = coordinator.finish_turn(turn.turn_id)
    assert second_turn.state is TurnState.COMPLETED

    turn = coordinator.start_turn(group.group_id, content={"text": "ten responses"})
    for index in range(10):
        claim = coordinator.claim_response(turn.turn_id, group.members[0].member_id)
        turn = coordinator.complete_response(
            claim,
            content={"text": str(index)},
            provenance=ContentProvenance.BOT,
        )

    with pytest.raises(GroupCapExceeded):
        coordinator.claim_response(turn.turn_id, group.members[0].member_id)


def test_expired_lease_reclaim_fences_duplicate_execution(tmp_path: Path) -> None:
    now = [100.0]
    coordinator = MobileGroupCoordinator(
        tmp_path / "groups.db",
        instance_id="install-a",
        clock=lambda: now[0],
        lease_seconds=5.0,
    )
    group = coordinator.create_group(_bots())
    turn = coordinator.start_turn(group.group_id, content={"text": "hello"})
    old_claim = coordinator.claim_response(turn.turn_id, group.members[0].member_id)
    now[0] = 106.0

    with pytest.raises(Exception):
        coordinator.claim_response(turn.turn_id, group.members[0].member_id)
    new_claim = coordinator.claim_response(
        turn.turn_id,
        group.members[0].member_id,
        reclaim_expired=True,
    )

    assert new_claim.execution_generation > old_claim.execution_generation
    with pytest.raises(ExecutionFenceLost):
        coordinator.complete_response(
            old_claim,
            content={"text": "late"},
            provenance=ContentProvenance.BOT,
        )


def test_restart_marks_active_work_indeterminate_without_resubmission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "groups.db"
    monkeypatch.setattr(groups_module, "_PROCESS_TOKEN", "boot-one")
    coordinator = MobileGroupCoordinator(db_path, instance_id="install-a")
    group = coordinator.create_group(_bots())
    turn = coordinator.start_turn(group.group_id, content={"text": "hello"})
    old_claim = coordinator.claim_response(turn.turn_id, group.members[0].member_id)

    monkeypatch.setattr(groups_module, "_PROCESS_TOKEN", "boot-two")
    restarted = MobileGroupCoordinator(db_path, instance_id="install-a")
    recovered = restarted.get_turn(turn.turn_id)

    assert recovered.state is TurnState.INDETERMINATE
    with pytest.raises(GroupStopped):
        restarted.claim_response(turn.turn_id, group.members[0].member_id)
    with pytest.raises(ExecutionFenceLost):
        restarted.complete_response(
            old_claim,
            content={"text": "late"},
            provenance=ContentProvenance.BOT,
        )


def test_restart_fences_an_active_turn_between_serial_responses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "groups.db"
    monkeypatch.setattr(groups_module, "_PROCESS_TOKEN", "boot-one")
    coordinator = MobileGroupCoordinator(db_path, instance_id="install-a")
    group = coordinator.create_group(_bots())
    turn = coordinator.start_turn(group.group_id, content={"text": "hello"})
    claim = coordinator.claim_response(turn.turn_id, group.members[0].member_id)
    coordinator.complete_response(
        claim,
        content={"text": "first"},
        provenance=ContentProvenance.BOT,
    )

    monkeypatch.setattr(groups_module, "_PROCESS_TOKEN", "boot-two")
    restarted = MobileGroupCoordinator(db_path, instance_id="install-a")

    assert restarted.get_turn(turn.turn_id).state is TurnState.INDETERMINATE



def test_cancel_fences_active_execution_and_records_untrusted_provenance(tmp_path: Path) -> None:
    coordinator = _coordinator(tmp_path)
    group = coordinator.create_group(_bots())
    turn = coordinator.start_turn(group.group_id, content={"text": "hello"})
    claim = coordinator.claim_response(turn.turn_id, group.members[0].member_id)

    cancelled = coordinator.cancel_turn(turn.turn_id, reason="user_stop")

    assert cancelled.state is TurnState.CANCELLED
    with pytest.raises(ExecutionFenceLost):
        coordinator.complete_response(
            claim,
            content={"text": "side effect already happened"},
            provenance=ContentProvenance.WEB,
        )
    events = coordinator.list_events(group.group_id, turn_id=turn.turn_id)
    assert any(event.event_type == "turn.cancelled" for event in events)

    next_turn = coordinator.start_turn(group.group_id, content={"text": "next"})
    next_claim = coordinator.claim_response(next_turn.turn_id, group.members[0].member_id)
    coordinator.complete_response(
        next_claim,
        content={"text": "untrusted web result"},
        provenance=ContentProvenance.WEB,
    )
    assert any(
        event.event_type == "bot.response" and event.provenance is ContentProvenance.WEB
        for event in coordinator.list_events(group.group_id, turn_id=next_turn.turn_id)
    )


def test_stop_group_blocks_future_work_and_marks_side_effects_not_undone(tmp_path: Path) -> None:
    coordinator = _coordinator(tmp_path)
    group = coordinator.create_group(_bots())
    turn = coordinator.start_turn(group.group_id, content={"text": "hello"})

    stopped = coordinator.stop_group(group.group_id, reason="operator_stop")

    assert stopped.state.value == "stopped"
    assert coordinator.get_turn(turn.turn_id).completed_side_effects_not_undone is True
    with pytest.raises(GroupStopped):
        coordinator.start_turn(group.group_id, content={"text": "blocked"})
    with pytest.raises(GroupStopped):
        coordinator.add_member(group.group_id, BotSelection("install-a", "profile-2", "Bot 2"))


def test_group_execution_uses_profile_scoped_agents_and_untrusted_peer_context(tmp_path: Path) -> None:
    coordinator = _coordinator(tmp_path)
    group = coordinator.create_group(_bots(3))
    calls = []

    def execute(**kwargs):
        calls.append(kwargs)
        return f"reply-{kwargs['profile_name']}"

    service = MobileGroupExecutionService(
        coordinator,
        executor=execute,
        profile_resolver=lambda opaque: f"resolved-{opaque}",
    )
    result = service.run_turn(
        group.group_id,
        text="compare approaches",
        access_subject="access-owner",
    )

    assert result.turn.state is TurnState.COMPLETED
    assert len(result.responses) == 9
    assert result.turn.current_round == 3
    assert calls[0]["profile_name"] == "resolved-profile-0"
    assert calls[0]["access_subject"] == "access-owner"
    assert "<untrusted_group_content>" in calls[1]["prompt"]
    assert "reply-resolved-profile-0" in calls[1]["prompt"]
    assert len({call["session_id"] for call in calls}) == 3


def test_group_execution_stops_at_ten_responses_across_serial_rounds(tmp_path: Path) -> None:
    coordinator = _coordinator(tmp_path)
    group = coordinator.create_group(_bots(6))
    calls = []

    def execute(**kwargs):
        calls.append(kwargs)
        return f"reply-{len(calls)}"

    service = MobileGroupExecutionService(
        coordinator,
        executor=execute,
        profile_resolver=lambda opaque: opaque,
    )

    result = service.run_turn(group.group_id, text="bounded", access_subject="owner")

    assert result.turn.state is TurnState.COMPLETED
    assert result.turn.response_count == 10
    assert len(result.responses) == 10
    assert len(calls) == 10


def test_group_execution_failure_is_indeterminate_and_never_auto_retried(tmp_path: Path) -> None:
    coordinator = _coordinator(tmp_path)
    group = coordinator.create_group(_bots())
    calls = []

    def execute(**kwargs):
        calls.append(kwargs)
        raise ConnectionError("provider outcome unknown")

    service = MobileGroupExecutionService(
        coordinator,
        executor=execute,
        profile_resolver=lambda opaque: opaque,
    )

    with pytest.raises(ConnectionError):
        service.run_turn(group.group_id, text="hello", access_subject="owner")

    turn_id = next(event.turn_id for event in coordinator.list_events(group.group_id) if event.turn_id)
    assert coordinator.get_turn(turn_id).state is TurnState.INDETERMINATE
    assert len(calls) == 1


def test_group_execution_rechecks_profile_before_each_member(tmp_path: Path) -> None:
    coordinator = _coordinator(tmp_path)
    group = coordinator.create_group(_bots())
    resolve_calls: dict[str, int] = {}
    executions = []

    def resolve(profile_id: str) -> str:
        resolve_calls[profile_id] = resolve_calls.get(profile_id, 0) + 1
        # Simulate a host profile being renamed/deleted after the initial
        # group preflight but before that member's execution.
        if profile_id == "profile-1" and resolve_calls[profile_id] > 1:
            raise KeyError("profile is no longer live")
        return profile_id

    def execute(**kwargs):
        executions.append(kwargs)
        return "reply"

    service = MobileGroupExecutionService(
        coordinator,
        executor=execute,
        profile_resolver=resolve,
    )

    with pytest.raises(KeyError, match="no longer live"):
        service.run_turn(group.group_id, text="hello", access_subject="owner")

    turn_id = next(event.turn_id for event in coordinator.list_events(group.group_id) if event.turn_id)
    assert coordinator.get_turn(turn_id).state is TurnState.INDETERMINATE
    assert len(executions) == 1


def test_group_execution_observes_cancellation_before_response_claim(tmp_path: Path) -> None:
    class CancelBeforeClaimCoordinator(MobileGroupCoordinator):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._cancel_once = True

        def claim_response(self, turn_id, member_id=None, **kwargs):
            if self._cancel_once:
                self._cancel_once = False
                self.cancel_turn(turn_id)
            return super().claim_response(turn_id, member_id, **kwargs)

    coordinator = CancelBeforeClaimCoordinator(tmp_path / "groups.db", instance_id="install-a")
    group = coordinator.create_group(_bots())
    executions = []

    def execute(**kwargs):
        executions.append(kwargs)
        return "should not run"

    service = MobileGroupExecutionService(
        coordinator,
        executor=execute,
        profile_resolver=lambda profile: profile,
    )

    result = service.run_turn(group.group_id, text="hello", access_subject="owner")

    assert result.turn.state is TurnState.CANCELLED
    assert executions == []
