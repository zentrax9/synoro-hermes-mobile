from __future__ import annotations

import sqlite3
import threading
from uuid import uuid4

from fastapi.testclient import TestClient

from hermes_cli.mobile_auth import AccessIdentity
from hermes_cli.mobile_chat import MobileChatService
from hermes_cli.mobile_devices import DeviceAuthorization
from hermes_cli.mobile_event_store import MobileEventStore, MutationStatus
from hermes_cli.mobile_objects import MobileObjectRegistry
from hermes_cli.mobile_request_auth import MobileRequestIdentity
from hermes_cli.mobile_server import create_mobile_app


class _Sessions:
    def __init__(self) -> None:
        self.rows: list[dict[str, str]] = []
        self.messages: dict[str, list[dict[str, object]]] = {}

    def create_session(self, session_id: str, source: str, **kwargs: object) -> str:
        self.rows.append({"id": session_id, "source": source, **kwargs})
        self.messages[session_id] = []
        return session_id

    def list_sessions_rich(self, **_kwargs: object) -> list[dict[str, object]]:
        return [
            {**row, "title": "Chat", "message_count": 0, "last_active": 1}
            for row in self.rows
        ]

    def get_messages(self, session_id: str, **_kwargs: object) -> list[dict[str, object]]:
        return self.messages[session_id]


def test_event_store_lookup_is_read_only_and_returns_durable_mutation_state(tmp_path) -> None:
    store = MobileEventStore(tmp_path / "events.sqlite", instance_id="instance-one")
    body = {"conversation_id": "conversation-one", "text": "hello", "attachment_ids": []}

    reserved = store.reserve_mutation(
        actor_id="device-one",
        action="message.send",
        key="message-status-key",
        body=body,
    )

    found = store.lookup_mutation(
        actor_id="device-one",
        action="message.send",
        key="message-status-key",
    )

    assert found is not None
    assert found.mutation_id == reserved.mutation_id
    assert found.status is MutationStatus.PENDING
    assert store.lookup_mutation(
        actor_id="device-one",
        action="message.send",
        key="missing-message-status-key",
    ) is None

    with sqlite3.connect(store.db_path) as connection:
        assert connection.execute(
            "SELECT status FROM mobile_idempotency WHERE mutation_id = ?",
            (reserved.mutation_id,),
        ).fetchone()[0] == MutationStatus.PENDING.value


def _fixture(tmp_path, *, executor):
    objects = MobileObjectRegistry(tmp_path / "objects.sqlite")
    binding = objects.profiles(["profile-one"])[0]
    events = MobileEventStore(tmp_path / "events.sqlite", instance_id=str(objects.instance_id))
    sessions = _Sessions()
    chat = MobileChatService(
        tmp_path / "chat.sqlite",
        events=events,
        session_backend=lambda _profile: sessions,
        executor=executor,
    )
    conversation = chat.new_conversation("profile-one")
    identity = MobileRequestIdentity(
        access=AccessIdentity("subject-one", "one@example.test"),
        device=DeviceAuthorization(
            device_id="device-one",
            profile=None,
            scope="chat",
            token_claims={"profiles": ["profile-one"]},
            dpop_claims={},
        ),
    )

    identity_holder = {"value": identity}

    class _RequestAuth:
        def authorize(self, _request, **_kwargs):
            return identity_holder["value"]

    client = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            objects=objects,
            events=events,
            request_authorizer=_RequestAuth(),
            chat=chat,
        )
    )
    route = (
        f"/mobile/v1/profiles/{binding.opaque_profile_id}/conversations/"
        f"{conversation.conversation_id}/message-status"
    )
    return client, route, chat, events, objects, binding, conversation, identity_holder


def test_message_status_is_unknown_before_run_then_tracks_completion_without_execution(
    tmp_path,
    monkeypatch,
) -> None:
    started = threading.Event()
    release = threading.Event()
    calls: list[dict[str, object]] = []

    def execute(**kwargs):
        calls.append(kwargs)
        started.set()
        assert release.wait(2)
        return "answer"

    client, route, chat, events, _objects, _binding, conversation, identity_holder = _fixture(
        tmp_path,
        executor=execute,
    )
    identity = identity_holder["value"]
    key = "message-status-key"
    claim = chat.reserve_send_mutation(
        profile_name="profile-one",
        conversation_id=conversation.conversation_id,
        device_id=identity.device.device_id,
        idempotency_key=key,
        text="hello",
    )

    # The status endpoint is a read path: it must not turn a pending claim into
    # a retry or call the executor while the run row does not yet exist.
    def unexpected_reservation(*_args, **_kwargs):
        raise AssertionError("message-status must not reserve a mutation")

    monkeypatch.setattr(events, "reserve_mutation", unexpected_reservation)
    unknown = client.get(route, headers={"Idempotency-Key": key})
    assert unknown.status_code == 200, unknown.text
    assert unknown.headers["cache-control"] == "no-store"
    assert unknown.json() == {"request_state": "unknown", "run": None}
    assert calls == []

    result: list[object] = []

    def send() -> None:
        try:
            result.append(
                chat.send(
                    profile_name="profile-one",
                    opaque_profile_id=str(_binding.opaque_profile_id),
                    conversation_id=conversation.conversation_id,
                    device_id=identity.device.device_id,
                    access_subject=identity.access.subject,
                    idempotency_key=key,
                    text="hello",
                    claim=claim,
                )
            )
        except BaseException as exc:  # pragma: no cover - assertion below reports failures
            result.append(exc)

    worker = threading.Thread(target=send)
    worker.start()
    assert started.wait(2)
    run_id = calls[0]["run_id"]

    active = client.get(route, headers={"Idempotency-Key": key})
    assert active.status_code == 200, active.text
    assert active.json()["request_state"] == "run_found"
    assert active.json()["run"]["run_id"] == str(run_id)
    assert active.json()["run"]["state"] == "thinking"

    release.set()
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert len(result) == 1
    assert not isinstance(result[0], BaseException)

    completed = client.get(route, headers={"Idempotency-Key": key})
    assert completed.status_code == 200, completed.text
    assert completed.json()["run"]["state"] == "completed"
    assert completed.json()["run"]["completed_external_side_effects_not_undone"] is False

    direct_run = client.get(f"/mobile/v1/runs/{run_id}")
    assert direct_run.status_code == 200, direct_run.text
    assert direct_run.json()["completed_external_side_effects_not_undone"] is False

    run_events = client.get(f"/mobile/v1/runs/{run_id}/events")
    assert run_events.status_code == 200, run_events.text
    events_payload = run_events.json()["events"]
    assert {
        (event["event_type"], event["aggregate_type"], event["aggregate_id"])
        for event in events_payload
        if event["event_type"].startswith("run.")
    } >= {
        ("run.queued", "run", str(run_id)),
        ("run.completed", "run", str(run_id)),
    }


def test_message_status_tracks_cancellation_and_restart_fencing(tmp_path) -> None:
    started = threading.Event()
    release = threading.Event()

    def execute(**_kwargs):
        started.set()
        assert release.wait(2)
        return "late answer"

    client, route, chat, _events, _objects, _binding, conversation, identity_holder = _fixture(
        tmp_path,
        executor=execute,
    )
    identity = identity_holder["value"]
    key = "message-cancel-status-key"
    result: list[object] = []

    def send() -> None:
        try:
            result.append(
                chat.send(
                    profile_name="profile-one",
                    opaque_profile_id=None,
                    conversation_id=conversation.conversation_id,
                    device_id=identity.device.device_id,
                    access_subject=identity.access.subject,
                    idempotency_key=key,
                    text="hello",
                )
            )
        except BaseException as exc:  # cancellation is expected to fence the result
            result.append(exc)

    worker = threading.Thread(target=send)
    worker.start()
    assert started.wait(2)
    run_id = chat.message_status(
        "profile-one",
        conversation.conversation_id,
        device_id=identity.device.device_id,
        access_subject=identity.access.subject,
        idempotency_key=key,
    ).run_id
    cancelled = client.post(
        f"/mobile/v1/runs/{run_id}/cancel",
        headers={"Idempotency-Key": "cancel-status-key"},
    )
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["state"] == "indeterminate"
    assert cancelled.json()["completed_external_side_effects_not_undone"] is True
    replay = client.post(
        f"/mobile/v1/runs/{run_id}/cancel",
        headers={"Idempotency-Key": "cancel-status-key"},
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["completed_external_side_effects_not_undone"] is True
    status = client.get(route, headers={"Idempotency-Key": key})
    assert status.status_code == 200, status.text
    assert status.json()["run"]["state"] == "indeterminate"
    assert status.json()["run"]["completed_external_side_effects_not_undone"] is True
    direct_run = client.get(f"/mobile/v1/runs/{run_id}")
    assert direct_run.status_code == 200, direct_run.text
    assert direct_run.json()["completed_external_side_effects_not_undone"] is True

    release.set()
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert len(result) == 1
    assert isinstance(result[0], RuntimeError)

    # A queued row fenced during startup recovery remains discoverable by the
    # original status key, but the read path itself does not perform recovery.
    restart_key = "message-restart-status-key"
    restart_claim = chat.reserve_send_mutation(
        profile_name="profile-one",
        conversation_id=conversation.conversation_id,
        device_id=identity.device.device_id,
        idempotency_key=restart_key,
        text="restart me",
    )
    restart_run_id = uuid4()
    chat._create_run(
        restart_run_id,
        conversation.conversation_id,
        profile_name="profile-one",
        device_id=identity.device.device_id,
        access_subject=identity.access.subject,
        mutation_id=restart_claim.mutation_id,
        now=10,
    )
    assert chat.recover_uncertain_runs(profile_marker=lambda _profile: "opaque-profile") == 1
    restart_status = client.get(route, headers={"Idempotency-Key": restart_key})
    assert restart_status.status_code == 200, restart_status.text
    assert restart_status.json()["run"] == {
        "run_id": str(restart_run_id),
        "conversation_id": str(conversation.conversation_id),
        "state": "indeterminate",
        "text": None,
        "error": "process_restart",
        "created_at": 10.0,
        "updated_at": restart_status.json()["run"]["updated_at"],
        "cancel_requested": False,
        "completed_external_side_effects_not_undone": True,
    }


def test_message_status_isolated_by_device_subject_and_conversation(tmp_path) -> None:
    client, route, chat, _events, objects, _binding, conversation, identity_holder = _fixture(
        tmp_path,
        executor=lambda **_kwargs: "answer",
    )
    identity = identity_holder["value"]
    claim = chat.reserve_send_mutation(
        profile_name="profile-one",
        conversation_id=conversation.conversation_id,
        device_id=identity.device.device_id,
        idempotency_key="message-isolation-key",
        text="hello",
    )
    run_id = uuid4()
    chat._create_run(
        run_id,
        conversation.conversation_id,
        profile_name="profile-one",
        device_id=identity.device.device_id,
        access_subject=identity.access.subject,
        mutation_id=claim.mutation_id,
        now=10,
    )

    # Same profile but another device/Access subject receives the deliberately
    # indistinguishable unknown result.
    identity_holder["value"] = MobileRequestIdentity(
        access=AccessIdentity("subject-two", "two@example.test"),
        device=DeviceAuthorization(
            device_id="device-two",
            profile=None,
            scope="chat",
            token_claims={"profiles": ["profile-one"]},
            dpop_claims={},
        ),
    )
    foreign = client.get(route, headers={"Idempotency-Key": "message-isolation-key"})
    assert foreign.status_code == 200, foreign.text
    assert foreign.json() == {"request_state": "unknown", "run": None}

    # The original conversation ID is not valid under another profile even
    # when that profile is otherwise authorized by the device token.
    second_binding = objects.profiles(["profile-two"])[0]
    identity_holder["value"] = MobileRequestIdentity(
        access=AccessIdentity("subject-one", "one@example.test"),
        device=DeviceAuthorization(
            device_id="device-one",
            profile=None,
            scope="chat",
            token_claims={"profiles": ["profile-one", "profile-two"]},
            dpop_claims={},
        ),
    )
    wrong_profile_route = (
        f"/mobile/v1/profiles/{second_binding.opaque_profile_id}/conversations/"
        f"{conversation.conversation_id}/message-status"
    )
    wrong_profile = client.get(
        wrong_profile_route,
        headers={"Idempotency-Key": "message-isolation-key"},
    )
    assert wrong_profile.status_code == 404
