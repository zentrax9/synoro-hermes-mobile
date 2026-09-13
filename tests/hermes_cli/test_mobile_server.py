from __future__ import annotations

import argparse
from base64 import urlsafe_b64encode
from hashlib import sha256
import threading
from uuid import uuid4

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
import httpx
import pytest

from hermes_cli.mobile_auth import AccessIdentity
from hermes_cli.mobile_attachments import (
    AttachmentNotFound,
    COMPLETED_UNATTACHED_AFTER_SECONDS,
    MobileAttachmentStore,
)
from hermes_cli.mobile_chat import MobileChatService
from hermes_cli.mobile_devices import MobileDeviceStore, public_jwk_from_key, token_challenge_message
from hermes_cli.mobile_event_store import EventInput, MobileEventStore
from hermes_cli.mobile_objects import MobileObjectRegistry
from hermes_cli.mobile_request_auth import MobileRequestIdentity
from hermes_cli.mobile_devices import DeviceAuthorization
from hermes_cli.mobile_routines import MobileRoutineService, RoutineDefinition
from hermes_cli.mobile_settings import ProfileSettings, SettingsConflict
from hermes_cli.mobile_server import create_mobile_app, running_mobile_listener
from hermes_cli.subcommands.dashboard import build_dashboard_parser, build_serve_parser


def test_mobile_app_exposes_only_versioned_mobile_routes() -> None:
    client = TestClient(create_mobile_app(authorize=lambda _request: None))

    response = client.get("/mobile/v1/capabilities")

    assert response.status_code == 200
    assert response.json()["api_version"] == "v1"
    for forbidden_path in (
        "/",
        "/docs",
        "/openapi.json",
        "/api/ws",
        "/api/pty",
        "/api/console",
        "/api/config",
        "/api/files",
        "/api/rpc",
    ):
        assert client.get(forbidden_path).status_code == 404


def test_capabilities_report_injected_optional_mobile_services() -> None:
    client = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            settings=object(),
            catalog=object(),
            routines=object(),
            approvals=object(),
        )
    )

    response = client.get("/mobile/v1/capabilities")

    assert response.status_code == 200
    assert set(response.json()["features"]) >= {"settings", "catalog", "routines", "approvals"}

    runnable = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            routines=object(),
            routine_worker=object(),
        )
    )
    assert "routine_runs" in runnable.get("/mobile/v1/capabilities").json()["features"]


def test_sensitive_settings_conflict_preserves_retryable_status(tmp_path) -> None:
    objects = MobileObjectRegistry(tmp_path / "objects.sqlite")
    binding = objects.profiles(["private-profile"])[0]
    events = MobileEventStore(tmp_path / "events.sqlite", instance_id=str(objects.instance_id))
    identity = MobileRequestIdentity(
        access=AccessIdentity("owner", "owner@example.com"),
        device=DeviceAuthorization(
            device_id="opaque-device-id-123",
            profile=None,
            scope="settings:write:safe",
            token_claims={"profiles": ["private-profile"]},
            dpop_claims={},
        ),
    )

    class RequestAuth:
        def authorize(self, _request, **_kwargs):
            return identity

    class Settings:
        def get(self, _profile_name):
            return ProfileSettings(
                profile_id="private-profile",
                revision=3,
                etag='"settings-3"',
                display_name="",
                title="",
                avatar="",
                notification_preferences={},
                privacy_preferences={},
                approval_policy={},
            )

        def update_sensitive(self, *_args, **_kwargs):
            raise SettingsConflict("stale settings revision")

    client = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            objects=objects,
            events=events,
            request_authorizer=RequestAuth(),
            settings=Settings(),
        )
    )
    route = f"/mobile/v1/profiles/{binding.opaque_profile_id}/settings/sensitive"
    body = {
        "changes": {"model": "approved-model"},
        "step_up": {
            "challenge_id": str(uuid4()),
            "action": "settings.step_up.write",
            "context_digest": "0" * 64,
            "nonce": "n" * 16,
            "expires_at": 2_000_000_000,
            "signature": "s" * 16,
        },
    }
    headers = {"If-Match": '"settings-2"', "Idempotency-Key": "sensitive-settings-key"}
    first = client.patch(route, headers=headers, json=body)
    replay = client.patch(route, headers=headers, json=body)

    assert first.status_code == 409
    assert first.json() == {"detail": "settings_revision_conflict"}
    assert replay.status_code == 409
    assert replay.json() == first.json()


def test_mobile_app_fails_closed_without_an_authorizer() -> None:
    client = TestClient(create_mobile_app())

    response = client.get("/mobile/v1/capabilities")

    assert response.status_code == 401
    assert response.json() == {"detail": "mobile authentication required"}


def test_mobile_listener_flags_are_available_only_on_serve() -> None:
    def capture(_args) -> None:
        return None

    serve = build_serve_parser(cmd_dashboard=capture)
    parsed = serve.parse_args(["--mobile-host", "127.0.0.1", "--mobile-port", "9120"])

    assert (parsed.mobile_host, parsed.mobile_port) == ("127.0.0.1", 9120)

    root = argparse.ArgumentParser()
    subparsers = root.add_subparsers(dest="command")
    build_dashboard_parser(
        subparsers,
        cmd_dashboard=capture,
        cmd_dashboard_register=capture,
    )
    with pytest.raises(SystemExit):
        root.parse_args(["dashboard", "--mobile-port", "9120"])


def test_live_mobile_listener_does_not_serve_dashboard_or_rpc_routes() -> None:
    with running_mobile_listener(
        host="127.0.0.1",
        port=0,
        authorize=lambda _request: None,
    ) as listener:
        base_url = f"http://127.0.0.1:{listener.port}"

        assert httpx.get(f"{base_url}/mobile/v1/capabilities").status_code == 200
        assert httpx.get(f"{base_url}/api/ws").status_code == 404
        assert httpx.get(f"{base_url}/api/pty").status_code == 404
        assert httpx.get(f"{base_url}/api/config").status_code == 404


def test_mobile_startup_refuses_missing_cloudflare_identity_configuration(
    monkeypatch,
) -> None:
    from hermes_cli import mobile_startup

    monkeypatch.setattr(mobile_startup, "load_config", lambda: {"mobile": {}})
    args = argparse.Namespace(
        headless_backend=True,
        mobile_host="127.0.0.1",
        mobile_port=9120,
    )

    with pytest.raises(SystemExit, match="Cloudflare Access issuer and audience"):
        with mobile_startup.mobile_listener_for_serve(args):
            pass


def test_mobile_startup_refuses_public_bind_without_explicit_private_vpn_policy(
    monkeypatch,
):
    from hermes_cli import mobile_startup

    monkeypatch.setattr(mobile_startup, "load_config", lambda: {"mobile": {}})
    args = argparse.Namespace(
        headless_backend=True,
        mobile_host="0.0.0.0",
        mobile_port=9120,
    )

    with pytest.raises(SystemExit, match="wildcard|must be loopback"):
        with mobile_startup.mobile_listener_for_serve(args):
            pass


def test_mobile_startup_rejects_wildcard_even_with_private_bind_policy(monkeypatch) -> None:
    from hermes_cli import mobile_startup

    config = _valid_mobile_operator_config()
    config["allow_private_bind"] = True
    monkeypatch.setattr(mobile_startup, "load_config", lambda: {"mobile": config})
    args = argparse.Namespace(
        headless_backend=True,
        mobile_host="0.0.0.0",
        mobile_port=9120,
    )

    with pytest.raises(SystemExit, match="wildcard"):
        with mobile_startup.mobile_listener_for_serve(args):
            pass


def _valid_mobile_operator_config() -> dict:
    return {
        "public_url": "https://mobile.example.com",
        "allowed_profiles": ["default"],
        "allowed_scopes": ["chat", "attachments"],
        "turn_timeout_seconds": 600,
        "cloudflare_access": {
            "issuer": "https://team.cloudflareaccess.com",
            "audience": "installation-specific-audience",
        },
    }


@pytest.mark.parametrize(
    "field,value,match",
    [
        ("public_url", "http://mobile.example.com", "HTTPS origin"),
        ("allow_private_bind", "false", "boolean"),
        ("turn_timeout_seconds", 5, "between 10 and 3600"),
        ("allowed_scopes", ["dashboard"], "unsupported scope"),
        ("allowed_profiles", ["unsafe/profile"], "invalid mobile.allowed_profiles item"),
        ("model_allowlist", "gpt", "must be a list"),
        ("push_relay", {"url": "https://relay.example.com"}, "both"),
        ("push_relay", [], "must be a mapping"),
        ("catalog", "not-a-list", "must be a list"),
        (
            "cloudflare_access",
            {
                "issuer": "https://user:pass@team.cloudflareaccess.com",
                "audience": "installation-specific-audience",
            },
            "HTTPS origin",
        ),
    ],
)
def test_mobile_operator_config_validation_fails_before_startup_state(
    field,
    value,
    match,
):
    from hermes_cli.mobile_startup import validate_mobile_operator_config

    config = _valid_mobile_operator_config()
    config[field] = value
    with pytest.raises(ValueError, match=match):
        validate_mobile_operator_config(config)


def test_mobile_operator_config_validation_accepts_push_relay_without_network_call():
    from hermes_cli.mobile_startup import validate_mobile_operator_config

    config = _valid_mobile_operator_config()
    config["push_relay"] = {"url": "https://relay.example.com"}
    validate_mobile_operator_config(config, push_token="r" * 32)


def test_mobile_startup_wires_persistent_isolated_services(monkeypatch, tmp_path) -> None:
    from hermes_cli import mobile_startup

    monkeypatch.setattr(mobile_startup, "get_hermes_home", lambda: tmp_path)
    monkeypatch.setattr(
        mobile_startup,
        "load_config",
        lambda: {
            "mobile": {
                "public_url": "https://mobile.example.com",
                "allowed_profiles": ["default"],
                "allowed_scopes": ["chat", "attachments"],
                "cloudflare_access": {
                    "issuer": "https://team.cloudflareaccess.com",
                    "audience": "installation-specific-audience",
                },
            }
        },
    )
    args = argparse.Namespace(
        headless_backend=True,
        mobile_host="127.0.0.1",
        mobile_port=0,
    )

    with mobile_startup.mobile_listener_for_serve(args) as listener:
        response = httpx.get(f"http://127.0.0.1:{listener.port}/mobile/v1/capabilities")
        assert response.status_code == 401

    mobile_root = tmp_path / "mobile"
    assert (mobile_root / "device-token-key.pem").is_file()
    assert (mobile_root / "devices.sqlite3").is_file()
    assert (mobile_root / "objects.sqlite3").is_file()
    assert (mobile_root / "events.sqlite3").is_file()
    assert (mobile_root / "rate-limits.sqlite3").is_file()


def test_mobile_startup_group_profile_resolver_rechecks_profile_liveness(monkeypatch, tmp_path) -> None:
    from hermes_cli import mobile_startup, profiles

    live = True
    captured = {}

    def fake_profile_exists(_profile_name):
        return live

    class CapturingGroupExecution:
        def __init__(self, _groups, *, executor, profile_resolver):
            captured["resolver"] = profile_resolver

    class CapturingListener:
        def __init__(self, **kwargs):
            captured["listener"] = kwargs

        def __enter__(self):
            return argparse.Namespace(port=0)

        def __exit__(self, _exc_type, _exc_value, _traceback):
            return False

    monkeypatch.setattr(mobile_startup, "get_hermes_home", lambda: tmp_path)
    monkeypatch.setattr(profiles, "profile_exists", fake_profile_exists)
    monkeypatch.setattr(mobile_startup, "MobileGroupExecutionService", CapturingGroupExecution)
    monkeypatch.setattr(mobile_startup, "running_mobile_listener", CapturingListener)
    monkeypatch.setattr(
        mobile_startup,
        "load_config",
        lambda: {
            "mobile": {
                "public_url": "https://mobile.example.com",
                "allowed_profiles": ["default"],
                "allowed_scopes": ["chat", "groups"],
                "cloudflare_access": {
                    "issuer": "https://team.cloudflareaccess.com",
                    "audience": "installation-specific-audience",
                },
            }
        },
    )
    args = argparse.Namespace(
        headless_backend=True,
        mobile_host="127.0.0.1",
        mobile_port=0,
    )

    with mobile_startup.mobile_listener_for_serve(args):
        resolver = captured["resolver"]
        assert resolver("default") == "default"
        live = False
        with pytest.raises(KeyError, match="no longer allowed"):
            resolver("default")


def test_device_enrollment_and_nonce_refresh_are_access_authenticated(tmp_path) -> None:
    background = ec.generate_private_key(ec.SECP256R1())
    user_presence = ec.generate_private_key(ec.SECP256R1())
    store = MobileDeviceStore(
        tmp_path / "devices.sqlite",
        profile_allowlist=("profile-opaque-id",),
        scope_allowlist=("chat",),
    )
    app = create_mobile_app(
        authorize=lambda _request: None,
        access_authorize=lambda _request: AccessIdentity("owner-subject", "owner@example.com"),
        devices=store,
    )
    client = TestClient(app)

    enrolled = client.post(
        "/mobile/v1/devices",
        json={
            "device_label": "Owner phone",
            "background_jwk": public_jwk_from_key(background),
            "user_presence_jwk": public_jwk_from_key(user_presence),
        },
    )

    assert enrolled.status_code == 201
    payload = enrolled.json()
    record = store.get_device(payload["device_id"])
    assert record.status == "pending"
    assert record.access_subject == "owner-subject"
    assert record.device_label == "Owner phone"
    assert client.post(f"/mobile/v1/devices/{record.device_id}/token/challenge").status_code == 401

    store.redeem_enrollment_code(payload["enrollment_code"])
    store.approve_device(record.device_id)
    challenge = client.post(f"/mobile/v1/devices/{record.device_id}/token/challenge")
    assert challenge.status_code == 200
    nonce = challenge.json()["nonce"]
    signature = background.sign(
        token_challenge_message(record.device_id, nonce),
        ec.ECDSA(hashes.SHA256()),
    )
    completed = client.post(
        f"/mobile/v1/devices/{record.device_id}/token",
        json={
            "nonce": nonce,
            "signature": urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
        },
    )

    assert completed.status_code == 200
    assert store.verify_device_token(completed.json()["device_token"])["sub"] == record.device_id
    listed = client.get("/mobile/v1/devices")
    assert listed.status_code == 200
    assert listed.json()["devices"][0]["device_id"] == record.device_id
    assert client.delete(f"/mobile/v1/devices/{record.device_id}").status_code == 204
    with pytest.raises(Exception):
        store.verify_device_token(completed.json()["device_token"])


def test_device_routes_fail_closed_without_access_auth_or_storage() -> None:
    client = TestClient(create_mobile_app(authorize=lambda _request: None))

    response = client.post(
        "/mobile/v1/devices",
        json={"device_label": "Phone", "background_jwk": {}, "user_presence_jwk": {}},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "mobile authentication required"}


def test_sync_returns_durable_semantic_events_after_an_instance_cursor(tmp_path) -> None:
    events = MobileEventStore(tmp_path / "events.sqlite", instance_id="instance-opaque")
    first = events.append_event(
        EventInput(
            event_type="message.created",
            aggregate_type="message",
            aggregate_id="message-opaque",
            payload={"message_id": "message-opaque"},
        )
    )
    client = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            sync_authorize=lambda _request: None,
            events=events,
        )
    )

    response = client.get("/mobile/v1/sync", params={"cursor": 0})

    assert response.status_code == 200
    assert response.json()["instance_id"] == "instance-opaque"
    assert response.json()["events"][0]["cursor"] == first.cursor
    assert response.json()["next_cursor"] == first.cursor


def test_snapshot_sync_can_restart_below_the_retained_floor(tmp_path) -> None:
    from hermes_cli.mobile_event_store import EventInput

    now = [100.0]
    events = MobileEventStore(
        tmp_path / "events.sqlite",
        instance_id="instance-opaque",
        retention_seconds=1.0,
        clock=lambda: now[0],
    )
    events.append_event(
        EventInput(
            event_type="message.created",
            aggregate_type="message",
            aggregate_id="old-message",
            payload={"profile_id": "profile-a", "text": "old"},
        )
    )
    now[0] = 102.0
    retained = events.append_event(
        EventInput(
            event_type="message.created",
            aggregate_type="message",
            aggregate_id="new-message",
            payload={"profile_id": "profile-a", "text": "new"},
        )
    )
    client = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            sync_authorize=lambda _request: None,
            events=events,
        )
    )

    response = client.get("/mobile/v1/sync", params={"cursor": 0, "snapshot": "true"})

    assert response.status_code == 200
    assert [event["cursor"] for event in response.json()["events"]] == [retained.cursor]


def test_scoped_sync_filters_events_to_the_requested_opaque_profile(tmp_path) -> None:
    objects = MobileObjectRegistry(tmp_path / "objects.sqlite")
    first, second = objects.profiles(["profile-a", "profile-b"])
    events = MobileEventStore(tmp_path / "events.sqlite", instance_id=str(objects.instance_id))
    visible = events.append_event(
        EventInput(
            event_type="message.created",
            aggregate_type="conversation",
            aggregate_id="conversation-a",
            payload={"profile_id": str(first.opaque_profile_id), "text": "visible"},
        )
    )
    hidden = events.append_event(
        EventInput(
            event_type="message.created",
            aggregate_type="conversation",
            aggregate_id="conversation-b",
            payload={"profile_id": str(second.opaque_profile_id), "text": "hidden"},
        )
    )
    identity = MobileRequestIdentity(
        access=AccessIdentity("owner-subject", "owner@example.com"),
        device=DeviceAuthorization(
            device_id="opaque-device-id-123",
            profile=None,
            scope="chat",
            token_claims={"profiles": ["profile-a", "profile-b"]},
            dpop_claims={},
        ),
    )
    client = TestClient(
        create_mobile_app(
            sync_authorize=lambda _request: identity,
            objects=objects,
            events=events,
        )
    )

    response = client.get(
        "/mobile/v1/sync",
        params={
            "instance_id": str(objects.instance_id),
            "profile_id": str(first.opaque_profile_id),
            "cursor": 0,
        },
    )

    assert response.status_code == 200
    assert [event["payload"]["text"] for event in response.json()["events"]] == ["visible"]
    assert response.json()["next_cursor"] == hidden.cursor == visible.cursor + 1


def test_scoped_sync_reconciles_deleted_profile_bindings(tmp_path) -> None:
    objects = MobileObjectRegistry(tmp_path / "objects.sqlite")
    binding = objects.profiles(["profile-a"])[0]
    events = MobileEventStore(tmp_path / "events.sqlite", instance_id=str(objects.instance_id))
    identity = MobileRequestIdentity(
        access=AccessIdentity("owner-subject", "owner@example.com"),
        device=DeviceAuthorization(
            device_id="opaque-device-id-123",
            profile=None,
            scope="chat",
            token_claims={"profiles": ["profile-a"]},
            dpop_claims={},
        ),
    )
    client = TestClient(
        create_mobile_app(
            sync_authorize=lambda _request: identity,
            objects=objects,
            events=events,
            allowed_profiles=("profile-a",),
            profile_liveness=lambda _profile: False,
        )
    )

    response = client.get(
        "/mobile/v1/sync",
        params={
            "instance_id": str(objects.instance_id),
            "profile_id": str(binding.opaque_profile_id),
            "cursor": 0,
        },
    )

    assert response.status_code == 404
    with pytest.raises(KeyError):
        objects.resolve_profile(binding.opaque_profile_id, {"profile-a"})


def test_sync_fails_closed_without_its_scoped_authorizer(tmp_path) -> None:
    events = MobileEventStore(tmp_path / "events.sqlite", instance_id="instance-opaque")
    client = TestClient(create_mobile_app(authorize=lambda _request: None, events=events))

    response = client.get("/mobile/v1/sync")

    assert response.status_code == 401


def test_profiles_return_only_opaque_ids_and_generic_labels(tmp_path) -> None:
    objects = MobileObjectRegistry(tmp_path / "objects.sqlite")
    identity = MobileRequestIdentity(
        access=AccessIdentity("owner-subject", "owner@example.com"),
        device=DeviceAuthorization(
            device_id="opaque-device-id-123",
            profile=None,
            scope="chat",
            token_claims={"profiles": ["private-profile-name"]},
            dpop_claims={},
        ),
    )
    client = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            profiles_authorize=lambda _request: identity,
            objects=objects,
            allowed_profiles=("private-profile-name", "other-profile"),
        )
    )

    response = client.get("/mobile/v1/profiles")

    assert response.status_code == 200
    serialized = response.text
    assert "private-profile-name" not in serialized
    assert "other-profile" not in serialized
    assert response.json()["profiles"][0]["label"] == "Hermes bot 1"


def test_push_registration_is_bound_to_the_authenticated_device(tmp_path) -> None:
    class FakeRelay:
        def __init__(self):
            self.registered = []

        def register_device(self, handle, token):
            self.registered.append((handle, token))

        def revoke_device(self, handle):
            self.registered.append((handle, None))

    store = MobileDeviceStore(
        tmp_path / "devices.sqlite",
        profile_allowlist=("profile",),
        scope_allowlist=("chat",),
    )
    background = ec.generate_private_key(ec.SECP256R1())
    user = ec.generate_private_key(ec.SECP256R1())
    enrollment = store.create_enrollment_code(
        public_jwk_from_key(background),
        public_jwk_from_key(user),
    )
    store.redeem_enrollment_code(enrollment.code)
    record = store.approve_device(enrollment.device_id)
    identity = MobileRequestIdentity(
        access=AccessIdentity("owner", "owner@example.com"),
        device=DeviceAuthorization(
            device_id=record.device_id,
            profile=None,
            scope=None,
            token_claims={},
            dpop_claims={},
        ),
    )
    relay = FakeRelay()
    client = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            push_authorize=lambda _request: identity,
            devices=store,
            push_relay=relay,
        )
    )

    response = client.put(
        f"/mobile/v1/devices/{record.device_id}/push",
        json={"fcm_token": "f" * 64},
    )

    assert response.status_code == 204
    assert relay.registered == [(record.push_handle, "f" * 64)]
    assert client.put(
        "/mobile/v1/devices/another-opaque-device-id/push",
        json={"fcm_token": "f" * 64},
    ).status_code == 404


def test_mobile_device_revoke_is_durable_when_push_relay_is_unavailable(tmp_path) -> None:
    class FailingRelay:
        def __init__(self):
            self.revoked = []

        def revoke_device(self, handle):
            self.revoked.append(handle)
            raise httpx.ConnectError("relay unavailable")

    store = MobileDeviceStore(
        tmp_path / "devices.sqlite",
        profile_allowlist=("profile",),
        scope_allowlist=("chat",),
    )
    background = ec.generate_private_key(ec.SECP256R1())
    user = ec.generate_private_key(ec.SECP256R1())
    enrollment = store.create_enrollment_code(
        public_jwk_from_key(background),
        public_jwk_from_key(user),
        access_subject="owner",
    )
    store.redeem_enrollment_code(enrollment.code)
    record = store.approve_device(enrollment.device_id)
    relay = FailingRelay()
    client = TestClient(
        create_mobile_app(
            access_authorize=lambda _request: AccessIdentity("owner", "owner@example.com"),
            devices=store,
            push_relay=relay,
        )
    )

    response = client.delete(f"/mobile/v1/devices/{record.device_id}")

    assert response.status_code == 204
    assert store.get_device(record.device_id).status == "revoked"
    assert relay.revoked == [record.push_handle]


def test_direct_chat_routes_resolve_opaque_profile_and_preserve_idempotency(tmp_path) -> None:
    class Sessions:
        def __init__(self):
            self.rows = []
            self.messages = {}

        def create_session(self, session_id, source, **kwargs):
            self.rows.append({"id": session_id, "source": source, **kwargs})
            self.messages[session_id] = []
            return session_id

        def list_sessions_rich(self, **_kwargs):
            return [
                {**row, "title": "Chat", "message_count": 0, "last_active": 1}
                for row in self.rows
            ]

        def get_messages(self, session_id, **_kwargs):
            return self.messages[session_id]

    class RequestAuth:
        def __init__(self):
            self.profile_limits = []

        def authorize(self, _request, **_kwargs):
            return identity

        def rate_limit_profile(self, _request, _identity, *, profile):
            self.profile_limits.append(profile)

    objects = MobileObjectRegistry(tmp_path / "objects.sqlite")
    binding = objects.profiles(["private-profile"])[0]
    events = MobileEventStore(
        tmp_path / "events.sqlite",
        instance_id=str(objects.instance_id),
    )
    sessions = Sessions()
    calls = []

    def execute(**kwargs):
        calls.append(kwargs)
        if kwargs["prompt"] == "fail":
            raise ValueError("host executor failed")
        return "answer"

    chat = MobileChatService(
        tmp_path / "chat.sqlite",
        events=events,
        session_backend=lambda _profile: sessions,
        executor=execute,
    )
    conversation = chat.new_conversation("private-profile")
    identity = MobileRequestIdentity(
        access=AccessIdentity("owner", "owner@example.com"),
        device=DeviceAuthorization(
            device_id="opaque-device-id-123",
            profile=None,
            scope="chat",
            token_claims={"profiles": ["private-profile"]},
            dpop_claims={},
        ),
    )
    request_auth = RequestAuth()
    client = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            objects=objects,
            events=events,
            request_authorizer=request_auth,
            chat=chat,
        )
    )
    route = (
        f"/mobile/v1/profiles/{binding.opaque_profile_id}/conversations/"
        f"{conversation.conversation_id}/messages"
    )

    first = client.post(
        route,
        headers={"Idempotency-Key": "request-opaque-id"},
        json={"text": "hello"},
    )
    replay = client.post(
        route,
        headers={"Idempotency-Key": "request-opaque-id"},
        json={"text": "hello"},
    )

    assert first.status_code == 200
    assert replay.json() == first.json()
    assert len(calls) == 1
    assert request_auth.profile_limits[:2] == [
        str(binding.opaque_profile_id),
        str(binding.opaque_profile_id),
    ]
    run_id = first.json()["run_id"]
    direct_run = client.get(f"/mobile/v1/runs/{run_id}")
    assert direct_run.status_code == 200, direct_run.text
    assert direct_run.json()["conversation_id"] == str(conversation.conversation_id)
    assert direct_run.json()["state"] == "completed"
    direct_events = client.get(f"/mobile/v1/runs/{run_id}/events")
    assert direct_events.status_code == 200, direct_events.text
    assert any(event["event_type"] == "run.completed" for event in direct_events.json()["events"])
    failed = client.post(
        route,
        headers={"Idempotency-Key": "request-opaque-failure"},
        json={"text": "fail"},
    )
    assert failed.status_code == 409
    assert failed.json() == {"detail": "mobile_message_indeterminate"}
    failed_run = chat.get_run(
        calls[-1]["run_id"],
        device_id=identity.device.device_id,
        access_subject=identity.access.subject,
    )
    assert failed_run.state == "indeterminate"
    unknown = client.get(
        f"/mobile/v1/profiles/{binding.opaque_profile_id}/conversations/"
        "00000000-0000-0000-0000-000000000000/messages"
    )
    assert unknown.status_code == 404

    # Generic run lookups must retain the profile boundary enforced by the
    # profile-scoped send route; a device grant narrowed after the send cannot
    # recover the old run by guessing its UUID.
    identity.device.token_claims["profiles"] = []
    assert client.get(f"/mobile/v1/runs/{run_id}").status_code == 404
    assert client.get(f"/mobile/v1/runs/{run_id}/events").status_code == 404
    assert client.post(
        f"/mobile/v1/runs/{run_id}/cancel",
        headers={"Idempotency-Key": "scope-narrowed-cancel"},
    ).status_code == 404


def test_new_conversation_is_noncanonical_and_same_key_replays_one_result(tmp_path) -> None:
    class Sessions:
        def __init__(self):
            self.rows = []

        def create_session(self, session_id, source, **kwargs):
            self.rows.append({"id": session_id, "source": source, **kwargs})
            return session_id

        def list_sessions_rich(self, **_kwargs):
            return [
                {**row, "title": "Chat", "message_count": 0, "last_active": index + 1}
                for index, row in enumerate(self.rows)
            ]

        def get_messages(self, _session_id, **_kwargs):
            return []

    objects = MobileObjectRegistry(tmp_path / "objects.sqlite")
    binding = objects.profiles(["private-profile"])[0]
    events = MobileEventStore(tmp_path / "events.sqlite", instance_id=str(objects.instance_id))
    sessions = Sessions()
    chat = MobileChatService(
        tmp_path / "chat.sqlite",
        events=events,
        session_backend=lambda _profile: sessions,
    )
    canonical = chat.new_conversation("private-profile", canonical=True)
    identity = MobileRequestIdentity(
        access=AccessIdentity("owner", "owner@example.com"),
        device=DeviceAuthorization(
            device_id="opaque-device-id-123",
            profile=None,
            scope="chat",
            token_claims={"profiles": ["private-profile"]},
            dpop_claims={},
        ),
    )

    class RequestAuth:
        def authorize(self, _request, **_kwargs):
            return identity

    client = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            objects=objects,
            events=events,
            request_authorizer=RequestAuth(),
            chat=chat,
        )
    )
    route = f"/mobile/v1/profiles/{binding.opaque_profile_id}/conversations"

    first = client.post(
        route,
        headers={"Idempotency-Key": "conversation-create-key"},
        json={"canonical": False},
    )
    replay = client.post(
        route,
        headers={"Idempotency-Key": "conversation-create-key"},
        json={"canonical": False},
    )

    assert first.status_code == 201, first.text
    assert replay.status_code == 201, replay.text
    assert replay.json() == first.json()
    assert first.json()["canonical"] is False
    assert first.json()["conversation_id"] != str(canonical.conversation_id)
    assert len(sessions.rows) == 2
    imported = chat.import_conversations("private-profile")
    assert sum(conversation.canonical for conversation in imported) == 1

    changed_body = client.post(
        route,
        headers={"Idempotency-Key": "conversation-create-key"},
        json={"canonical": True},
    )
    assert changed_body.status_code == 409


def test_direct_run_cancel_route_fences_active_executor_and_replays_idempotently(tmp_path) -> None:
    class Sessions:
        def __init__(self):
            self.rows = []
            self.messages = {}

        def create_session(self, session_id, source, **kwargs):
            self.rows.append({"id": session_id, "source": source, **kwargs})
            self.messages[session_id] = []
            return session_id

        def list_sessions_rich(self, **_kwargs):
            return [
                {**row, "title": "Chat", "message_count": 0, "last_active": 1}
                for row in self.rows
            ]

        def get_messages(self, session_id, **_kwargs):
            return self.messages[session_id]

    class RequestAuth:
        def authorize(self, _request, **_kwargs):
            return identity

    objects = MobileObjectRegistry(tmp_path / "objects.sqlite")
    binding = objects.profiles(["private-profile"])[0]
    events = MobileEventStore(tmp_path / "events.sqlite", instance_id=str(objects.instance_id))
    sessions = Sessions()
    started = threading.Event()
    release = threading.Event()
    calls = []

    def execute(**kwargs):
        calls.append(kwargs)
        started.set()
        assert release.wait(2)
        return "late answer"

    chat = MobileChatService(
        tmp_path / "chat.sqlite",
        events=events,
        session_backend=lambda _profile: sessions,
        executor=execute,
    )
    conversation = chat.new_conversation("private-profile")
    identity = MobileRequestIdentity(
        access=AccessIdentity("owner", "owner@example.com"),
        device=DeviceAuthorization(
            device_id="opaque-device-id-123",
            profile=None,
            scope="chat",
            token_claims={"profiles": ["private-profile"]},
            dpop_claims={},
        ),
    )
    client = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            objects=objects,
            events=events,
            request_authorizer=RequestAuth(),
            chat=chat,
        )
    )
    route = (
        f"/mobile/v1/profiles/{binding.opaque_profile_id}/conversations/"
        f"{conversation.conversation_id}/messages"
    )
    send_response = []

    def send_request() -> None:
        send_response.append(
            client.post(
                route,
                headers={"Idempotency-Key": "request-opaque-id"},
                json={"text": "hello"},
            )
        )

    sender = threading.Thread(target=send_request)
    sender.start()
    assert started.wait(2)
    run_id = calls[0]["run_id"]

    cancelled = client.post(
        f"/mobile/v1/runs/{run_id}/cancel",
        headers={"Idempotency-Key": "cancel-request-key"},
    )
    replay = client.post(
        f"/mobile/v1/runs/{run_id}/cancel",
        headers={"Idempotency-Key": "cancel-request-key"},
    )

    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["state"] == "indeterminate"
    assert cancelled.json()["cancel_requested"] is True
    assert replay.json() == cancelled.json()
    direct_events = client.get(f"/mobile/v1/runs/{run_id}/events")
    assert direct_events.status_code == 200, direct_events.text
    cancel_event = next(
        event for event in direct_events.json()["events"]
        if event["event_type"] == "run.indeterminate"
    )
    assert cancel_event["payload"]["profile_id"] == str(binding.opaque_profile_id)

    release.set()
    sender.join(timeout=2)
    assert not sender.is_alive()
    assert len(send_response) == 1
    assert send_response[0].status_code == 409
    assert client.get(f"/mobile/v1/runs/{run_id}").json()["state"] == "indeterminate"


def test_routine_run_cancel_route_reports_started_execution_as_indeterminate(tmp_path) -> None:
    class RequestAuth:
        def authorize(self, _request, **_kwargs):
            return identity

    class StepUp:
        def verify(self, _challenge, *, context, signature, now=None):
            assert signature == "valid-signature"

    objects = MobileObjectRegistry(tmp_path / "objects.sqlite")
    binding = objects.profiles(["private-profile"])[0]
    events = MobileEventStore(tmp_path / "events.sqlite", instance_id=str(objects.instance_id))
    routine_id = str(uuid4())
    routines = MobileRoutineService(
        tmp_path / "routines.sqlite",
        instance_id=str(objects.instance_id),
        profile_allowlist=("private-profile",),
        routines=(RoutineDefinition(routine_id, "private-profile", "Safe", "Display only"),),
        step_up=StepUp(),
    )
    identity = MobileRequestIdentity(
        access=AccessIdentity("owner", "owner@example.com"),
        device=DeviceAuthorization(
            device_id="opaque-device-id-123",
            profile=None,
            scope="routines:control",
            token_claims={"profiles": ["private-profile"]},
            dpop_claims={},
        ),
    )
    context = routines.run_context("private-profile", routine_id, "routine-run-key", body={})

    class Challenge:
        def __init__(self, value):
            self.context = value

    claim = routines.run(
        "private-profile",
        routine_id,
        actor_id=identity.device.device_id,
        idempotency_key="routine-run-key",
        body={},
        challenge=Challenge(context),
        signature="valid-signature",
        context=context,
    )
    routines.begin_execution(
        claim.run_id,
        actor_id=claim.actor_id,
        execution_generation=claim.execution_generation,
        fence_token=claim.fence_token,
    )
    client = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            objects=objects,
            events=events,
            request_authorizer=RequestAuth(),
            routines=routines,
        )
    )

    response = client.post(
        f"/mobile/v1/runs/{claim.run_id}/cancel",
        headers={"Idempotency-Key": "routine-cancel-key"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["state"] == "indeterminate"
    routine_events = events.events_since(after_cursor=0).events
    cancel_event = next(event for event in routine_events if event.event_type == "routine.run.indeterminate")
    assert cancel_event.payload["profile_id"] == str(binding.opaque_profile_id)
    assert cancel_event.payload["state"] == "indeterminate"


def test_attachment_routes_are_resumable_owned_and_idempotent(tmp_path) -> None:
    class Sessions:
        def __init__(self):
            self.rows = []

        def create_session(self, session_id, source, **kwargs):
            self.rows.append({"id": session_id, "source": source, **kwargs})
            return session_id

        def list_sessions_rich(self, **_kwargs):
            return []

        def get_messages(self, _session_id, **_kwargs):
            return []

    class RequestAuth:
        def authorize(self, _request, **kwargs):
            seen_scopes.append(kwargs.get("scope"))
            return identity

    objects = MobileObjectRegistry(tmp_path / "objects.sqlite")
    binding = objects.profiles(["private-profile"])[0]
    events = MobileEventStore(tmp_path / "events.sqlite", instance_id=str(objects.instance_id))
    sessions = Sessions()
    chat = MobileChatService(
        tmp_path / "chat.sqlite",
        events=events,
        session_backend=lambda _profile: sessions,
    )
    conversation = chat.new_conversation("private-profile")
    attachments = MobileAttachmentStore(tmp_path / "attachments", chunk_size=4)
    identity = MobileRequestIdentity(
        access=AccessIdentity("owner", "owner@example.com"),
        device=DeviceAuthorization(
            device_id="opaque-device-id-123",
            profile=None,
            scope="attachments",
            token_claims={"profiles": ["private-profile"]},
            dpop_claims={},
        ),
    )
    seen_scopes = []
    client = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            objects=objects,
            events=events,
            request_authorizer=RequestAuth(),
            chat=chat,
            attachments=attachments,
        )
    )
    payload = b"hello"
    declared = client.post(
        "/mobile/v1/attachments",
        headers={"Idempotency-Key": "declare-request-1"},
        json={
            "bot": {
                "instance_id": str(binding.instance_id),
                "opaque_profile_id": str(binding.opaque_profile_id),
            },
            "conversation_id": str(conversation.conversation_id),
            "filename": "note.txt",
            "size": len(payload),
            "mime_type": "text/plain",
            "sha256": sha256(payload).hexdigest(),
        },
    )
    replay = client.post(
        "/mobile/v1/attachments",
        headers={"Idempotency-Key": "declare-request-1"},
        json={
            "bot": {
                "instance_id": str(binding.instance_id),
                "opaque_profile_id": str(binding.opaque_profile_id),
            },
            "conversation_id": str(conversation.conversation_id),
            "filename": "note.txt",
            "size": len(payload),
            "mime_type": "text/plain",
            "sha256": sha256(payload).hexdigest(),
        },
    )
    assert declared.status_code == 201
    assert replay.json() == declared.json()
    upload_id = declared.json()["upload_id"]
    scope_headers = {
        "X-Hermes-Instance-Id": str(binding.instance_id),
        "X-Hermes-Profile-Id": str(binding.opaque_profile_id),
        "X-Hermes-Conversation-Id": str(conversation.conversation_id),
    }
    first = client.put(
        f"/mobile/v1/attachments/{upload_id}",
        headers={
            **scope_headers,
            "Idempotency-Key": "chunk-request-one",
            "Content-Range": "bytes 0-3/5",
            "Content-Type": "application/octet-stream",
        },
        content=payload[:4],
    )
    assert first.status_code == 200
    assert first.json()["next_offset"] == 4
    oversized = client.put(
        f"/mobile/v1/attachments/{upload_id}",
        headers={
            **scope_headers,
            "Idempotency-Key": "chunk-request-oversized",
            "Content-Range": "bytes 0-4/5",
        },
        content=payload,
    )
    assert oversized.status_code == 413
    assert client.put(
        f"/mobile/v1/attachments/{upload_id}",
        headers={
            **scope_headers,
            "Idempotency-Key": "chunk-request-one",
            "Content-Range": "bytes 0-3/5",
        },
        content=payload[:4],
    ).json() == first.json()
    assert client.put(
        f"/mobile/v1/attachments/{upload_id}",
        headers={
            **scope_headers,
            "Idempotency-Key": "chunk-request-two",
            "Content-Range": "bytes 4-4/5",
        },
        content=payload[4:],
    ).status_code == 200
    completed = client.post(
        f"/mobile/v1/attachments/{upload_id}/complete",
        headers={**scope_headers, "Idempotency-Key": "complete-request-1"},
    )
    assert completed.status_code == 200
    assert completed.json()["sha256"] == sha256(payload).hexdigest()
    assert client.post(
        f"/mobile/v1/attachments/{upload_id}/complete",
        headers={**scope_headers, "Idempotency-Key": "complete-request-1"},
    ).json() == completed.json()
    assert client.post(
        f"/mobile/v1/attachments/{upload_id}/complete",
        headers={**scope_headers, "Idempotency-Key": "complete-request-1"},
        json={"total_bytes": len(payload), "sha256": sha256(payload).hexdigest()},
    ).status_code == 409
    assert set(seen_scopes) == {"attachments"}

    wrong_instance_headers = dict(scope_headers)
    wrong_instance_headers["X-Hermes-Instance-Id"] = "00000000-0000-0000-0000-000000000000"
    assert client.post(
        f"/mobile/v1/attachments/{upload_id}/complete",
        headers={**wrong_instance_headers, "Idempotency-Key": "complete-request-2"},
    ).status_code == 404


def _direct_chat_attachment_fixture(tmp_path, *, executor):
    class Sessions:
        def __init__(self):
            self.rows = []
            self.messages = {}

        def create_session(self, session_id, source, **kwargs):
            self.rows.append({"id": session_id, "source": source, **kwargs})
            self.messages[session_id] = []
            return session_id

        def list_sessions_rich(self, **_kwargs):
            return [
                {**row, "title": "Chat", "message_count": 0, "last_active": 1}
                for row in self.rows
            ]

        def get_messages(self, session_id, **_kwargs):
            return self.messages[session_id]

    objects = MobileObjectRegistry(tmp_path / "objects.sqlite")
    binding = objects.profiles(["private-profile"])[0]
    events = MobileEventStore(tmp_path / "events.sqlite", instance_id=str(objects.instance_id))
    sessions = Sessions()
    chat = MobileChatService(
        tmp_path / "chat.sqlite",
        events=events,
        session_backend=lambda _profile: sessions,
        executor=executor,
    )
    conversation = chat.new_conversation("private-profile")
    attachments = MobileAttachmentStore(tmp_path / "attachments", chunk_size=64)
    identity = MobileRequestIdentity(
        access=AccessIdentity("owner", "owner@example.com"),
        device=DeviceAuthorization(
            device_id="opaque-device-id-123",
            profile=None,
            scope="attachments",
            token_claims={"profiles": ["private-profile"]},
            dpop_claims={},
        ),
    )

    class RequestAuth:
        def authorize(self, _request, **_kwargs):
            return identity

    client = TestClient(
        create_mobile_app(
            authorize=lambda _request: None,
            objects=objects,
            events=events,
            request_authorizer=RequestAuth(),
            chat=chat,
            attachments=attachments,
        )
    )
    route = (
        f"/mobile/v1/profiles/{binding.opaque_profile_id}/conversations/"
        f"{conversation.conversation_id}/messages"
    )
    return client, route, attachments, identity, conversation


def _complete_direct_chat_attachment(store, identity, conversation_id, data: bytes) -> str:
    upload = store.declare_upload(
        access_subject=identity.access.subject,
        device_id=identity.device.device_id,
        conversation_id=str(conversation_id),
        expected_size=len(data),
        expected_sha256=sha256(data).hexdigest(),
        mime_type="text/plain",
        display_name="note.txt",
        now=1000.0,
    )
    store.upload_chunk(
        upload.upload_id,
        f"bytes 0-{len(data) - 1}/{len(data)}",
        data,
        access_subject=identity.access.subject,
        device_id=identity.device.device_id,
        conversation_id=str(conversation_id),
        now=1001.0,
    )
    attachment = store.finalize_upload(
        upload.upload_id,
        access_subject=identity.access.subject,
        device_id=identity.device.device_id,
        conversation_id=str(conversation_id),
        now=1002.0,
    )
    return attachment.attachment_id


def test_direct_chat_reserves_before_binding_and_reclaims_conflicting_attachment(tmp_path) -> None:
    calls = []

    def execute(**kwargs):
        calls.append(kwargs)
        return "answer"

    client, route, attachments, identity, conversation = _direct_chat_attachment_fixture(
        tmp_path,
        executor=execute,
    )
    first_attachment = _complete_direct_chat_attachment(
        attachments,
        identity,
        conversation.conversation_id,
        b"first",
    )
    conflicting_attachment = _complete_direct_chat_attachment(
        attachments,
        identity,
        conversation.conversation_id,
        b"conflict",
    )
    headers = {"Idempotency-Key": "message-request-key"}

    first = client.post(
        route,
        headers=headers,
        json={"text": "hello", "attachment_ids": [first_attachment]},
    )
    conflict = client.post(
        route,
        headers=headers,
        json={"text": "different", "attachment_ids": [conflicting_attachment]},
    )
    replay = client.post(
        route,
        headers=headers,
        json={"text": "hello", "attachment_ids": [first_attachment]},
    )

    assert first.status_code == 200, first.text
    assert conflict.status_code == 409
    assert replay.json() == first.json()
    assert len(calls) == 1

    attachments.cleanup(now=1002.0 + COMPLETED_UNATTACHED_AFTER_SECONDS + 1)
    with pytest.raises(AttachmentNotFound):
        attachments.get_attachment(
            conflicting_attachment,
            access_subject=identity.access.subject,
            device_id=identity.device.device_id,
            conversation_id=str(conversation.conversation_id),
        )
    attachments.get_attachment(
        first_attachment,
        access_subject=identity.access.subject,
        device_id=identity.device.device_id,
        conversation_id=str(conversation.conversation_id),
    )
