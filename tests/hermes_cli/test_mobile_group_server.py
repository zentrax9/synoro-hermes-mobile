from __future__ import annotations

from fastapi.testclient import TestClient

from hermes_cli.mobile_auth import AccessIdentity
from hermes_cli.mobile_devices import DeviceAuthorization
from hermes_cli.mobile_event_store import MobileEventStore
from hermes_cli.mobile_group_execution import GroupExecutionResult, MobileGroupExecutionService
from hermes_cli.mobile_groups import BotSelection, ExecutionFenceLost, MobileGroupCoordinator
from hermes_cli.mobile_objects import MobileObjectRegistry
from hermes_cli.mobile_request_auth import MobileRequestIdentity
from hermes_cli.mobile_server import create_mobile_app


def test_group_list_paginates_bounded_snapshot(tmp_path) -> None:
    objects = MobileObjectRegistry(tmp_path / "objects.sqlite")
    objects.profiles(["alpha", "beta"])
    coordinator = MobileGroupCoordinator(tmp_path / "groups.sqlite", instance_id=str(objects.instance_id))
    identity = MobileRequestIdentity(
        access=AccessIdentity("owner", "owner@example.com"),
        device=DeviceAuthorization(
            device_id="device-opaque-123",
            profile=None,
            scope="groups",
            token_claims={"profiles": ["alpha", "beta"]},
            dpop_claims={},
        ),
    )

    class Auth:
        def authorize(self, _request, **_kwargs):
            return identity

    created_ids = []
    for _ in range(101):
        created_ids.append(
            coordinator.create_group(
                [
                    BotSelection(str(objects.instance_id), "alpha", "Alpha"),
                    BotSelection(str(objects.instance_id), "beta", "Beta"),
                ],
                owner_id="owner",
                device_id="device-opaque-123",
            ).group_id
        )

    client = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            request_authorizer=Auth(),
            objects=objects,
            groups=coordinator,
        )
    )
    listed = client.get("/mobile/v1/groups")

    assert listed.status_code == 200, listed.text
    assert len(listed.json()["groups"]) == 100
    assert listed.json()["has_more"] is True
    next_cursor = listed.json()["next_cursor"]
    assert isinstance(next_cursor, str) and next_cursor
    remainder = client.get("/mobile/v1/groups", params={"cursor": next_cursor})
    assert remainder.status_code == 200, remainder.text
    assert len(remainder.json()["groups"]) == 1
    assert remainder.json()["has_more"] is False
    assert remainder.json()["next_cursor"] is None
    assert {
        item["group_id"] for item in listed.json()["groups"] + remainder.json()["groups"]
    } == set(created_ids)
    assert client.get("/mobile/v1/groups", params={"cursor": "not-a-cursor"}).status_code == 400
    assert client.get("/mobile/v1/groups", params={"cursor": "a.b"}).status_code == 400

    secure_client = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            request_authorizer=Auth(),
            objects=objects,
            groups=coordinator,
            cursor_secret=b"installation-secret-a",
        )
    )
    secure_cursor = secure_client.get("/mobile/v1/groups").json()["next_cursor"]
    other_installation = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            request_authorizer=Auth(),
            objects=objects,
            groups=coordinator,
            cursor_secret=b"installation-secret-b",
        )
    )
    assert other_installation.get(
        "/mobile/v1/groups", params={"cursor": secure_cursor}
    ).status_code == 400


def test_group_routes_are_opaque_owned_and_idempotent(tmp_path) -> None:
    objects = MobileObjectRegistry(tmp_path / "objects.sqlite")
    bindings = objects.profiles(["alpha", "beta"])
    events = MobileEventStore(tmp_path / "events.sqlite", instance_id=str(objects.instance_id))
    coordinator = MobileGroupCoordinator(tmp_path / "groups.sqlite", instance_id=str(objects.instance_id))
    identity = MobileRequestIdentity(
        access=AccessIdentity("owner", "owner@example.com"),
        device=DeviceAuthorization(
            device_id="device-opaque-123",
            profile=None,
            scope="groups",
            token_claims={"profiles": ["alpha", "beta"]},
            dpop_claims={},
        ),
    )

    class Auth:
        def authorize(self, _request, **_kwargs):
            return identity

    def execute(**kwargs):
        return f"reply from {kwargs['profile_name']}"

    execution = MobileGroupExecutionService(
        coordinator,
        executor=execute,
        profile_resolver=lambda profile: profile,
    )
    client = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            request_authorizer=Auth(),
            objects=objects,
            events=events,
            groups=coordinator,
            group_execution=execution,
        )
    )
    body = {
        "bots": [
            {"instance_id": str(objects.instance_id), "opaque_profile_id": str(bindings[0].opaque_profile_id)},
            {"instance_id": str(objects.instance_id), "opaque_profile_id": str(bindings[1].opaque_profile_id)},
        ]
    }
    created = client.post(
        "/mobile/v1/groups",
        headers={"Idempotency-Key": "group-create-key-1"},
        json=body,
    )
    assert created.status_code == 201, created.text
    assert client.post(
        "/mobile/v1/groups",
        headers={"Idempotency-Key": "group-create-key-1"},
        json=body,
    ).json() == created.json()
    group = created.json()
    listed = client.get("/mobile/v1/groups")
    assert listed.status_code == 200, listed.text
    assert [item["group_id"] for item in listed.json()["groups"]] == [group["group_id"]]
    assert listed.json()["has_more"] is False
    narrowed = MobileRequestIdentity(
        access=identity.access,
        device=DeviceAuthorization(
            device_id=identity.device.device_id,
            profile=None,
            scope="groups",
            token_claims={"profiles": ["alpha"]},
            dpop_claims={},
        ),
    )
    narrowed_client = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            request_authorizer=type("NarrowAuth", (), {"authorize": lambda *_args, **_kwargs: narrowed})(),
            objects=objects,
            groups=coordinator,
        )
    )
    assert narrowed_client.get("/mobile/v1/groups").json() == {
        "groups": [],
        "has_more": False,
        "next_cursor": None,
    }
    sent = client.post(
        f"/mobile/v1/groups/{group['group_id']}/messages",
        headers={"Idempotency-Key": "group-message-key-1"},
        json={"text": "hello"},
    )
    assert sent.status_code == 200, sent.text
    assert sent.json()["state"] == "completed"
    assert len(sent.json()["responses"]) == 6
    run_id = sent.json()["run_id"]
    run = client.get(f"/mobile/v1/runs/{run_id}")
    assert run.status_code == 200
    assert run.json()["state"] == "completed"
    assert client.get(f"/mobile/v1/runs/{run_id}/events").status_code == 200
    stopped = client.post(
        f"/mobile/v1/groups/{group['group_id']}/stop",
        headers={"Idempotency-Key": "group-stop-key-1"},
    )
    assert stopped.status_code == 200, stopped.text
    assert stopped.json()["state"] == "stopped"
    assert client.post(
        f"/mobile/v1/groups/{group['group_id']}/stop",
        headers={"Idempotency-Key": "group-stop-key-1"},
    ).json() == stopped.json()

    other = MobileRequestIdentity(
        access=AccessIdentity("other", "other@example.com"),
        device=identity.device,
    )
    client_other = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            request_authorizer=type("OtherAuth", (), {"authorize": lambda *_args, **_kwargs: other})(),
            objects=objects,
            groups=coordinator,
        )
    )
    assert client_other.get(f"/mobile/v1/groups/{group['group_id']}").status_code == 404
    assert client_other.get("/mobile/v1/groups").json() == {
        "groups": [],
        "has_more": False,
        "next_cursor": None,
    }


def test_indeterminate_group_execution_fences_the_mutation(tmp_path) -> None:
    objects = MobileObjectRegistry(tmp_path / "objects.sqlite")
    objects.profiles(["alpha", "beta"])
    events = MobileEventStore(tmp_path / "events.sqlite", instance_id=str(objects.instance_id))
    coordinator = MobileGroupCoordinator(tmp_path / "groups.sqlite", instance_id=str(objects.instance_id))
    identity = MobileRequestIdentity(
        access=AccessIdentity("owner", "owner@example.com"),
        device=DeviceAuthorization(
            device_id="device-opaque-123",
            profile=None,
            scope="groups",
            token_claims={"profiles": ["alpha", "beta"]},
            dpop_claims={},
        ),
    )

    group = coordinator.create_group(
        [
            BotSelection(str(objects.instance_id), "alpha", "Alpha"),
            BotSelection(str(objects.instance_id), "beta", "Beta"),
        ],
        owner_id="owner",
        device_id="device-opaque-123",
    )

    class Auth:
        def authorize(self, _request, **_kwargs):
            return identity

    class IndeterminateExecution:
        def run_turn(self, group_id, *, text, access_subject, mentioned_member_ids):
            turn = coordinator.start_turn(group_id, content={"text": text})
            fenced = coordinator.mark_turn_indeterminate(turn.turn_id, reason="test_fence")
            return GroupExecutionResult(fenced, ())

    client = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            request_authorizer=Auth(),
            objects=objects,
            events=events,
            groups=coordinator,
            group_execution=IndeterminateExecution(),
        )
    )
    key = "group-message-indeterminate-1"
    response = client.post(
        f"/mobile/v1/groups/{group.group_id}/messages",
        headers={"Idempotency-Key": key},
        json={"text": "hello"},
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "turn_indeterminate"}
    claim = events.reserve_mutation(
        actor_id="device-opaque-123",
        action="group.message.send",
        key=key,
        body={"text": "hello", "mentioned_member_ids": [], "group_id": str(group.group_id)},
    )
    assert claim.status.value == "indeterminate"
    assert any(
        event.event_type == "group.turn.indeterminate"
        and event.aggregate_id == str(group.group_id)
        for event in events.events_since(after_cursor=0, limit=100).events
    )
    assert client.post(
        f"/mobile/v1/groups/{group.group_id}/messages",
        headers={"Idempotency-Key": key},
        json={"text": "hello"},
    ).status_code == 409


def test_fenced_group_execution_marks_request_indeterminate(tmp_path) -> None:
    objects = MobileObjectRegistry(tmp_path / "objects.sqlite")
    objects.profiles(["alpha", "beta"])
    events = MobileEventStore(tmp_path / "events.sqlite", instance_id=str(objects.instance_id))
    coordinator = MobileGroupCoordinator(tmp_path / "groups.sqlite", instance_id=str(objects.instance_id))
    identity = MobileRequestIdentity(
        access=AccessIdentity("owner", "owner@example.com"),
        device=DeviceAuthorization(
            device_id="device-opaque-123",
            profile=None,
            scope="groups",
            token_claims={"profiles": ["alpha", "beta"]},
            dpop_claims={},
        ),
    )
    group = coordinator.create_group(
        [
            BotSelection(str(objects.instance_id), "alpha", "Alpha"),
            BotSelection(str(objects.instance_id), "beta", "Beta"),
        ],
        owner_id="owner",
        device_id="device-opaque-123",
    )

    class Auth:
        def authorize(self, _request, **_kwargs):
            return identity

    class FencedExecution:
        def run_turn(self, *_args, **_kwargs):
            raise ExecutionFenceLost("execution claim was superseded")

    client = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            request_authorizer=Auth(),
            objects=objects,
            events=events,
            groups=coordinator,
            group_execution=FencedExecution(),
        )
    )
    key = "group-message-fenced-1"
    response = client.post(
        f"/mobile/v1/groups/{group.group_id}/messages",
        headers={"Idempotency-Key": key},
        json={"text": "hello"},
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "turn_indeterminate"}
    claim = events.reserve_mutation(
        actor_id="device-opaque-123",
        action="group.message.send",
        key=key,
        body={"text": "hello", "mentioned_member_ids": [], "group_id": str(group.group_id)},
    )
    assert claim.status.value == "indeterminate"
    assert any(
        event.event_type == "group.turn.indeterminate"
        and event.aggregate_id == str(group.group_id)
        and event.payload.get("reason") == "execution_fence_lost"
        for event in events.events_since(after_cursor=0, limit=100).events
    )
