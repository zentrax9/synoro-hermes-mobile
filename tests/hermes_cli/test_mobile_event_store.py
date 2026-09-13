from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from hermes_cli import mobile_event_store as store_module
from hermes_cli.mobile_event_store import (
    CursorExpired,
    EventInput,
    IdempotencyConflict,
    MobileEventStore,
    MutationResult,
    MutationStatus,
)


def _event(text: str, *, event_id: str | None = None, tombstone: bool = False) -> EventInput:
    return EventInput(
        event_type="message.created" if not tombstone else "message.deleted",
        aggregate_type="message",
        aggregate_id=f"message-{text}",
        payload={"text": text},
        event_id=event_id,
        tombstone=tombstone,
    )


def test_events_have_monotonic_instance_cursors_and_survive_reopen(tmp_path: Path) -> None:
    db_path = tmp_path / "mobile-events.db"
    store = MobileEventStore(db_path, instance_id="install-a")

    first = store.append_event(_event("one"))
    second = store.append_event(_event("two", tombstone=True))

    assert second.cursor > first.cursor
    assert second.tombstone is True

    reopened = MobileEventStore(db_path, instance_id="install-a")
    backlog = reopened.events_since(after_cursor=0)

    assert [event.cursor for event in backlog.events] == [first.cursor, second.cursor]
    assert [event.event_type for event in backlog.events] == [
        "message.created",
        "message.deleted",
    ]
    assert backlog.latest_cursor == second.cursor


def test_concurrent_appends_receive_unique_monotonic_cursors(tmp_path: Path) -> None:
    store = MobileEventStore(tmp_path / "mobile-events.db", instance_id="install-a")

    with ThreadPoolExecutor(max_workers=8) as executor:
        events = list(executor.map(lambda index: store.append_event(_event(str(index))), range(24)))

    cursors = sorted(event.cursor for event in events)
    assert cursors == list(range(1, 25))


def test_retention_expires_old_cursors_but_allows_resume_at_retained_cursor(
    tmp_path: Path,
) -> None:
    now = [100.0]
    store = MobileEventStore(
        tmp_path / "mobile-events.db",
        instance_id="install-a",
        retention_seconds=10.0,
        clock=lambda: now[0],
    )

    first = store.append_event(_event("old"))
    now[0] = 111.0
    second = store.append_event(_event("new"))

    with pytest.raises(CursorExpired) as exc_info:
        store.events_since(after_cursor=0)

    assert exc_info.value.retained_floor == first.cursor
    assert [event.cursor for event in store.events_since(after_cursor=first.cursor).events] == [
        second.cursor
    ]
    snapshot = store.snapshot_events_since(after_cursor=0)
    assert [event.cursor for event in snapshot.events] == [second.cursor]


def test_aggregate_query_avoids_global_page_gaps_and_cursor_expiry(tmp_path: Path) -> None:
    now = [100.0]
    store = MobileEventStore(
        tmp_path / "mobile-events.db",
        instance_id="install-a",
        retention_seconds=10.0,
        clock=lambda: now[0],
    )
    run_id = "run-opaque"

    store.append_events(
        tuple(
            EventInput(
                event_type="message.created",
                aggregate_type="message",
                aggregate_id=f"message-{index}",
                payload={"index": index},
                created_at=100.0,
            )
            for index in range(1001)
        )
    )
    run_event = store.append_event(
        EventInput(
            event_type="run.completed",
            aggregate_type="run",
            aggregate_id=run_id,
            payload={"text": "answer"},
            created_at=101.0,
        )
    )

    assert store.events_for_aggregate(
        aggregate_type="run", aggregate_id=run_id
    ) == (run_event,)

    now[0] = 112.0
    store.append_event(
        EventInput(
            event_type="message.created",
            aggregate_type="message",
            aggregate_id="message-trigger",
            payload={"index": "trigger"},
        )
    )
    assert store.events_for_aggregate(aggregate_type="run", aggregate_id=run_id) == ()


def test_idempotency_replays_result_and_rejects_body_conflicts(tmp_path: Path) -> None:
    store = MobileEventStore(tmp_path / "mobile-events.db", instance_id="install-a")
    body = {"conversation_id": "conversation-1", "text": "hello"}

    claim = store.reserve_mutation(
        actor_id="user-1",
        action="message.send",
        key="request-1",
        body=body,
    )
    assert claim.status is MutationStatus.NEW
    assert claim.is_new is True

    result = MutationResult(status_code=202, body={"run_id": "run-1"})
    completed = store.complete_mutation(
        claim.mutation_id,
        result=result,
        events=(_event("accepted"),),
    )
    replay = store.reserve_mutation(
        actor_id="user-1",
        action="message.send",
        key="request-1",
        body=body,
    )

    assert completed.status is MutationStatus.SUCCEEDED
    assert replay.status is MutationStatus.SUCCEEDED
    assert replay.is_new is False
    assert replay.result == result

    with pytest.raises(IdempotencyConflict):
        store.reserve_mutation(
            actor_id="user-1",
            action="message.send",
            key="request-1",
            body={"conversation_id": "conversation-1", "text": "different"},
        )


def test_complete_publishes_events_atomically(tmp_path: Path) -> None:
    store = MobileEventStore(tmp_path / "mobile-events.db", instance_id="install-a")
    claim = store.reserve_mutation(
        actor_id="user-1",
        action="message.send",
        key="request-1",
        body={"text": "hello"},
    )

    with pytest.raises(ValueError):
        store.complete_mutation(
            claim.mutation_id,
            result=MutationResult(status_code=202, body={"ok": True}),
            events=(
                _event("one", event_id="duplicate-event"),
                _event("two", event_id="duplicate-event"),
            ),
        )

    replay = store.reserve_mutation(
        actor_id="user-1",
        action="message.send",
        key="request-1",
        body={"text": "hello"},
    )
    assert replay.status is MutationStatus.PENDING
    assert store.events_since(after_cursor=0).events == ()


def test_pending_mutation_is_recovered_as_indeterminate_and_not_resubmitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "mobile-events.db"
    monkeypatch.setattr(store_module, "_PROCESS_TOKEN", "boot-one")
    store = MobileEventStore(db_path, instance_id="install-a")
    claim = store.reserve_mutation(
        actor_id="user-1",
        action="message.send",
        key="request-1",
        body={"text": "hello"},
    )
    assert claim.status is MutationStatus.NEW

    monkeypatch.setattr(store_module, "_PROCESS_TOKEN", "boot-two")
    restarted = MobileEventStore(db_path, instance_id="install-a")
    replay = restarted.reserve_mutation(
        actor_id="user-1",
        action="message.send",
        key="request-1",
        body={"text": "hello"},
    )

    assert replay.status is MutationStatus.INDETERMINATE
    assert replay.is_new is False
    assert replay.result is None
    assert any(
        event.event_type == "mutation.indeterminate"
        for event in restarted.events_since(after_cursor=0).events
    )


def test_database_uses_wal_mode(tmp_path: Path) -> None:
    import sqlite3

    db_path = tmp_path / "mobile-events.db"
    MobileEventStore(db_path, instance_id="install-a")

    with sqlite3.connect(db_path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
