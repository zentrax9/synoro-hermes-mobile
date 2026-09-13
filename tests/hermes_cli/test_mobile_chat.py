from contextlib import contextmanager
import threading
from uuid import uuid4

from hermes_cli.mobile_chat import (
    ConversationNotFound,
    HermesMobileChatExecutor,
    MobileChatService,
)
from hermes_cli.mobile_event_store import EventInput, MobileEventStore

import pytest


class FakeSessions:
    def __init__(self):
        self.sessions = []
        self.messages = {}

    def create_session(self, session_id, source, **kwargs):
        self.sessions.append({"id": session_id, "source": source, **kwargs})
        self.messages[session_id] = []
        return session_id

    def list_sessions_rich(self, **_kwargs):
        return [
            {
                **session,
                "title": "Private chat",
                "message_count": len(self.messages[session["id"]]),
                "last_active": 10,
            }
            for session in self.sessions
        ]

    def get_messages(self, session_id, **_kwargs):
        return self.messages[session_id]


def _service(tmp_path, executor=None):
    sessions = FakeSessions()
    events = MobileEventStore(tmp_path / "events.sqlite", instance_id="instance-one")
    service = MobileChatService(
        tmp_path / "chat.sqlite",
        events=events,
        session_backend=lambda _profile: sessions,
        executor=executor,
        clock=lambda: 10,
    )
    return service, sessions, events


def test_conversation_and_message_ids_are_opaque_and_cross_profile_reads_are_hidden(tmp_path):
    service, sessions, _ = _service(tmp_path)
    conversation = service.new_conversation("owner")
    source_id = sessions.sessions[0]["id"]
    sessions.messages[source_id] = [
        {"id": 1, "role": "user", "content": "hello", "timestamp": 11},
        {"id": 2, "role": "tool", "name": "terminal", "content": "secret output", "timestamp": 12},
    ]

    history = service.history("owner", conversation.conversation_id)

    assert history[0].text == "hello"
    assert history[1].text is None
    assert history[1].tool_summary == "terminal completed"
    assert source_id not in {str(message.message_id) for message in history}
    with pytest.raises(ConversationNotFound):
        service.history("other", conversation.conversation_id)


def test_send_executes_once_and_replays_exact_result_for_same_key_and_body(tmp_path):
    calls = []

    def execute(**kwargs):
        calls.append(kwargs)
        return "answer"

    service, _, events = _service(tmp_path, executor=execute)
    conversation = service.new_conversation("owner")

    first = service.send(
        profile_name="owner",
        conversation_id=conversation.conversation_id,
        device_id="device-opaque-id",
        idempotency_key="request-opaque-id",
        text="hello",
    )
    replay = service.send(
        profile_name="owner",
        conversation_id=conversation.conversation_id,
        device_id="device-opaque-id",
        idempotency_key="request-opaque-id",
        text="hello",
    )

    assert first == replay
    assert len(calls) == 1
    assert [event.event_type for event in events.events_since(after_cursor=0).events] == [
        "message.created",
        "run.queued",
        "message.created",
        "run.completed",
    ]


def test_uncertain_executor_failure_is_fenced_and_never_automatically_retried(tmp_path):
    calls = []

    def execute(**kwargs):
        calls.append(kwargs)
        raise ConnectionError("outcome unknown")

    service, _, events = _service(tmp_path, executor=execute)
    conversation = service.new_conversation("owner")
    kwargs = {
        "profile_name": "owner",
        "conversation_id": conversation.conversation_id,
        "device_id": "device-opaque-id",
        "idempotency_key": "request-opaque-id",
        "text": "hello",
    }

    with pytest.raises(ConnectionError):
        service.send(**kwargs)
    with pytest.raises(RuntimeError, match="indeterminate"):
        service.send(**kwargs)

    assert len(calls) == 1
    assert events.events_since(after_cursor=0).events[-1].event_type == "mutation.indeterminate"


def test_restart_fences_queued_direct_runs_and_preserves_profile_scoped_event(tmp_path):
    service, _, events = _service(tmp_path)
    conversation = service.new_conversation("owner")
    claim = events.reserve_mutation(
        actor_id="device-opaque-id",
        action="message.send",
        key="request-opaque-id",
        body={
            "conversation_id": str(conversation.conversation_id),
            "text": "hello",
            "attachment_ids": [],
        },
    )
    run_id = uuid4()
    service._create_run(
        run_id,
        conversation.conversation_id,
        profile_name="owner",
        device_id="device-opaque-id",
        access_subject="access-user",
        mutation_id=claim.mutation_id,
        now=10,
    )

    recovered = service.recover_uncertain_runs(profile_marker=lambda name: "opaque-owner")

    assert recovered == 1
    run = service.get_run(
        run_id,
        device_id="device-opaque-id",
        access_subject="access-user",
    )
    assert run.state == "indeterminate"
    assert events.reserve_mutation(
        actor_id="device-opaque-id",
        action="message.send",
        key="request-opaque-id",
        body={
            "conversation_id": str(conversation.conversation_id),
            "text": "hello",
            "attachment_ids": [],
        },
    ).status.value == "indeterminate"
    recovered_events = events.events_since(after_cursor=0).events
    assert recovered_events[-1].event_type == "run.indeterminate"
    assert recovered_events[-1].payload["profile_id"] == "opaque-owner"


def test_run_events_are_not_hidden_by_unrelated_global_activity(tmp_path):
    service, _, events = _service(tmp_path)
    run_id = uuid4()
    events.append_events(
        tuple(
            EventInput(
                event_type="message.created",
                aggregate_type="message",
                aggregate_id=f"message-{index}",
                payload={"index": index},
            )
            for index in range(1001)
        )
    )
    expected = events.append_event(
        EventInput(
            event_type="run.completed",
            aggregate_type="run",
            aggregate_id=str(run_id),
            payload={"text": "answer"},
        )
    )

    assert service.events_for_run(run_id) == (expected,)


def test_active_direct_run_cancel_is_durable_and_fences_late_executor_result(tmp_path):
    started = threading.Event()
    release = threading.Event()
    calls = []

    def execute(**kwargs):
        calls.append(kwargs)
        started.set()
        assert release.wait(2)
        return "late answer"

    service, _, events = _service(tmp_path, executor=execute)
    conversation = service.new_conversation("owner")
    kwargs = {
        "profile_name": "owner",
        "conversation_id": conversation.conversation_id,
        "device_id": "device-opaque-id",
        "access_subject": "access-user",
        "idempotency_key": "request-opaque-id",
        "text": "hello",
    }
    result = []

    def send() -> None:
        try:
            service.send(**kwargs)
        except BaseException as exc:  # The cancellation fence is the assertion below.
            result.append(exc)

    worker = threading.Thread(target=send)
    worker.start()
    assert started.wait(2)
    run_id = calls[0]["run_id"]

    cancelled = service.cancel_run(
        run_id,
        device_id="device-opaque-id",
        access_subject="access-user",
    )
    assert cancelled.state == "indeterminate"
    assert cancelled.cancel_requested is True

    release.set()
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert len(result) == 1
    assert isinstance(result[0], RuntimeError)
    assert "indeterminate" in str(result[0])
    assert service.get_run(
        run_id,
        device_id="device-opaque-id",
        access_subject="access-user",
    ).state == "indeterminate"

    replay = events.reserve_mutation(
        actor_id="device-opaque-id",
        action="message.send",
        key="request-opaque-id",
        body={
            "conversation_id": str(conversation.conversation_id),
            "text": "hello",
            "attachment_ids": [],
        },
    )
    assert replay.status.value == "indeterminate"
    assert len(calls) == 1


def test_production_executor_scopes_identity_and_reuses_only_the_same_session(tmp_path):
    sessions = FakeSessions()
    built = []
    observed = []

    class FakeAgent:
        def __init__(self, session_id):
            self.session_id = session_id
            self.closed = False

        def run_conversation(self, prompt, task_id):
            from gateway.session_context import get_session_env

            observed.append(
                {
                    "prompt": prompt,
                    "task_id": task_id,
                    "platform": get_session_env("HERMES_SESSION_PLATFORM"),
                    "profile": get_session_env("HERMES_SESSION_PROFILE"),
                    "user": get_session_env("HERMES_SESSION_USER_ID"),
                }
            )
            return {"final_response": "mobile answer"}

        def close(self):
            self.closed = True

    def build(profile_name, session_id, backend):
        assert profile_name == "owner"
        assert backend is sessions
        agent = FakeAgent(session_id)
        built.append(agent)
        return agent

    entered = []

    @contextmanager
    def scope(home):
        entered.append(home)
        yield

    executor = HermesMobileChatExecutor(
        lambda _profile: sessions,
        agent_builder=build,
        profile_home_resolver=lambda profile: tmp_path / profile,
        profile_scope=scope,
    )

    assert executor(
        profile_name="owner",
        session_id="session-one",
        prompt="hello",
        run_id="run-one",
        access_subject="access-user",
    ) == "mobile answer"
    assert executor(
        profile_name="owner",
        session_id="session-one",
        prompt="again",
        run_id="run-two",
        access_subject="access-user",
    ) == "mobile answer"

    assert len(built) == 1
    assert entered == [tmp_path / "owner", tmp_path / "owner"]
    assert observed[0] == {
        "prompt": "hello",
        "task_id": "run-one",
        "platform": "api_server",
        "profile": "owner",
        "user": "access-user",
    }

    executor.close()
    assert built[0].closed is True


def test_send_passes_server_authenticated_identity_to_executor(tmp_path):
    calls = []
    service, _, _ = _service(tmp_path, executor=lambda **kwargs: calls.append(kwargs) or "ok")
    conversation = service.new_conversation("owner")

    service.send(
        profile_name="owner",
        conversation_id=conversation.conversation_id,
        device_id="device-opaque-id",
        access_subject="access-user",
        idempotency_key="request-opaque-id",
        text="hello",
    )

    assert calls[0]["access_subject"] == "access-user"
