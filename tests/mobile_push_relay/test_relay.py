import sqlite3
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

import pytest

from services.mobile_push_relay.app import RelayRegistry, create_app


class FakeSender:
    def __init__(self):
        self.messages = []

    def send(self, message):
        self.messages.append(message)


class FailOnceSender(FakeSender):
    def __init__(self):
        super().__init__()
        self.attempts = 0

    def send(self, message):
        self.attempts += 1
        if self.attempts == 1:
            raise RuntimeError("provider unavailable")
        super().send(message)


def _setup(tmp_path):
    registry = RelayRegistry(tmp_path / "relay.sqlite", clock=lambda: 100)
    credential = registry.provision_instance("instance-opaque-01")
    registry.register_device("instance-opaque-01", "device-handle-opaque-01", "f" * 64)
    sender = FakeSender()
    return registry, credential, sender, TestClient(
        create_app(registry=registry, sender=sender, clock=lambda: 100)
    )


def test_relay_accepts_only_fixed_event_fields_and_static_notification_text(tmp_path):
    _, credential, sender, client = _setup(tmp_path)
    response = client.post(
        "/v1/push",
        headers={"Authorization": f"Bearer {credential}"},
        json={
            "event_type": "approval_required",
            "event_id": "event-opaque-id-01",
            "device_handle": "device-handle-opaque-01",
            "expires_at": 160,
        },
    )

    assert response.status_code == 200
    assert sender.messages[0].title == "Hermes needs attention"
    assert sender.messages[0].high_priority is True
    rejected = client.post(
        "/v1/push",
        headers={"Authorization": f"Bearer {credential}"},
        json={
            "event_type": "run_completed",
            "event_id": "another-event-id-01",
            "device_handle": "device-handle-opaque-01",
            "expires_at": 160,
            "title": "attacker-controlled",
        },
    )
    assert rejected.status_code == 422


def test_relay_deduplicates_event_id_and_restricts_handles_to_instance(tmp_path):
    registry, credential, sender, client = _setup(tmp_path)
    other_credential = registry.provision_instance("instance-opaque-02")
    payload = {
        "event_type": "run_completed",
        "event_id": "event-opaque-id-02",
        "device_handle": "device-handle-opaque-01",
        "expires_at": 160,
    }

    assert client.post(
        "/v1/push", headers={"Authorization": f"Bearer {credential}"}, json=payload
    ).json() == {"accepted": True, "duplicate": False}
    assert client.post(
        "/v1/push", headers={"Authorization": f"Bearer {credential}"}, json=payload
    ).json() == {"accepted": True, "duplicate": True}
    assert len(sender.messages) == 1
    assert client.post(
        "/v1/push", headers={"Authorization": f"Bearer {other_credential}"}, json=payload
    ).status_code == 404


def test_event_idempotency_is_scoped_to_each_device(tmp_path):
    registry, credential, sender, client = _setup(tmp_path)
    registry.register_device("instance-opaque-01", "device-handle-opaque-02", "g" * 64)
    payload = {
        "event_type": "run_completed",
        "event_id": "same-event-id-opaque-01",
        "expires_at": 160,
    }

    first = client.post(
        "/v1/push",
        headers={"Authorization": f"Bearer {credential}"},
        json={**payload, "device_handle": "device-handle-opaque-01"},
    )
    second = client.post(
        "/v1/push",
        headers={"Authorization": f"Bearer {credential}"},
        json={**payload, "device_handle": "device-handle-opaque-02"},
    )
    assert first.json() == {"accepted": True, "duplicate": False}
    assert second.json() == {"accepted": True, "duplicate": False}
    assert [message.token for message in sender.messages] == ["f" * 64, "g" * 64]


def test_failed_provider_delivery_can_be_retried_without_stuck_dedup(tmp_path):
    registry = RelayRegistry(tmp_path / "relay.sqlite", clock=lambda: 100)
    credential = registry.provision_instance("instance-opaque-05")
    registry.register_device("instance-opaque-05", "device-handle-opaque-05", "f" * 64)
    sender = FailOnceSender()
    client = TestClient(create_app(registry=registry, sender=sender, clock=lambda: 100))
    payload = {
        "event_type": "approval_required",
        "event_id": "retry-event-id-opaque-01",
        "device_handle": "device-handle-opaque-05",
        "expires_at": 160,
    }

    failed = client.post(
        "/v1/push", headers={"Authorization": f"Bearer {credential}"}, json=payload
    )
    retried = client.post(
        "/v1/push", headers={"Authorization": f"Bearer {credential}"}, json=payload
    )
    assert failed.status_code == 503
    assert failed.json() == {"detail": "push delivery unavailable"}
    assert retried.json() == {"accepted": True, "duplicate": False}
    assert sender.attempts == 2
    assert len(sender.messages) == 1


def test_inflight_delivery_is_retryable_instead_of_false_duplicate(tmp_path):
    now = [100.0]
    registry = RelayRegistry(tmp_path / "relay.sqlite", clock=lambda: now[0])
    credential = registry.provision_instance("instance-opaque-06")
    registry.register_device("instance-opaque-06", "device-handle-opaque-06", "f" * 64)
    sender = FakeSender()
    client = TestClient(create_app(registry=registry, sender=sender, clock=lambda: now[0]))
    payload = {
        "event_type": "run_completed",
        "event_id": "inflight-event-id-01",
        "device_handle": "device-handle-opaque-06",
        "expires_at": 500,
    }
    registry.reserve_delivery(
        instance_id="instance-opaque-06",
        event_id=payload["event_id"],
        device_handle=payload["device_handle"],
    )

    in_flight = client.post(
        "/v1/push", headers={"Authorization": f"Bearer {credential}"}, json=payload
    )
    assert in_flight.status_code == 503
    assert in_flight.json() == {"detail": "push delivery in progress"}
    assert sender.messages == []

    now[0] += 61
    retried = client.post(
        "/v1/push", headers={"Authorization": f"Bearer {credential}"}, json=payload
    )
    assert retried.json() == {"accepted": True, "duplicate": False}
    assert len(sender.messages) == 1


def test_authentication_and_payload_errors_do_not_reach_fcm(tmp_path):
    _, credential, sender, client = _setup(tmp_path)
    payload = {
        "event_type": "run_completed",
        "event_id": "privacy-event-id-01",
        "device_handle": "device-handle-opaque-01",
        "expires_at": 160,
    }
    invalid_payload = {**payload, "transcript": "must never be accepted"}

    assert client.post("/v1/push", json=payload).status_code == 401
    assert client.post(
        "/v1/push", headers={"Authorization": "Bearer wrong-credential"}, json=payload
    ).status_code == 401
    assert client.post(
        "/v1/push", headers={"Authorization": f"Bearer {credential}"}, json=invalid_payload
    ).status_code == 422
    assert sender.messages == []


def test_instance_can_rotate_and_revoke_only_its_opaque_device_handles(tmp_path):
    registry, credential, _, client = _setup(tmp_path)
    other = registry.provision_instance("instance-opaque-02")

    assert client.put(
        "/v1/devices/new-device-handle-01",
        headers={"Authorization": f"Bearer {credential}"},
        json={"fcm_token": "n" * 64},
    ).status_code == 204
    assert client.put(
        "/v1/devices/new-device-handle-01",
        headers={"Authorization": f"Bearer {other}"},
        json={"fcm_token": "x" * 64},
    ).status_code == 404
    assert client.delete(
        "/v1/devices/new-device-handle-01",
        headers={"Authorization": f"Bearer {credential}"},
    ).status_code == 204


def test_revoke_is_instance_owned_and_rotation_restores_delivery(tmp_path):
    registry, credential, sender, client = _setup(tmp_path)
    other_credential = registry.provision_instance("instance-opaque-02")

    assert client.put(
        "/v1/devices/device-handle-opaque-01",
        headers={"Authorization": f"Bearer {credential}"},
        json={"fcm_token": "r" * 64},
    ).status_code == 204
    assert client.delete(
        "/v1/devices/device-handle-opaque-01",
        headers={"Authorization": f"Bearer {other_credential}"},
    ).status_code == 404
    assert client.delete(
        "/v1/devices/device-handle-opaque-01",
        headers={"Authorization": f"Bearer {credential}"},
    ).status_code == 204

    denied = client.post(
        "/v1/push",
        headers={"Authorization": f"Bearer {credential}"},
        json={
            "event_type": "run_completed",
            "event_id": "revoked-event-id-01",
            "device_handle": "device-handle-opaque-01",
            "expires_at": 160,
        },
    )
    assert denied.status_code == 404
    assert client.put(
        "/v1/devices/device-handle-opaque-01",
        headers={"Authorization": f"Bearer {credential}"},
        json={"fcm_token": "z" * 64},
    ).status_code == 204
    accepted = client.post(
        "/v1/push",
        headers={"Authorization": f"Bearer {credential}"},
        json={
            "event_type": "run_completed",
            "event_id": "rotated-event-id-01",
            "device_handle": "device-handle-opaque-01",
            "expires_at": 160,
        },
    )
    assert accepted.status_code == 200
    assert sender.messages[-1].token == "z" * 64


def test_sqlite_dedup_expires_and_concurrent_reservation_is_atomic(tmp_path):
    now = [100.0]
    first = RelayRegistry(tmp_path / "relay.sqlite", clock=lambda: now[0])
    second = RelayRegistry(tmp_path / "relay.sqlite", clock=lambda: now[0])
    credential = first.provision_instance("instance-opaque-03")
    first.register_device("instance-opaque-03", "device-handle-opaque-03", "f" * 64)

    def reserve():
        return second.reserve_delivery(
            instance_id="instance-opaque-03",
            event_id="concurrent-event-id-01",
            device_handle="device-handle-opaque-03",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: reserve(), range(2)))
    assert sorted(duplicate for _token, duplicate in results) == [False, True]

    now[0] = 100 + 86_400 + 1
    token, duplicate = first.reserve_delivery(
        instance_id="instance-opaque-03",
        event_id="concurrent-event-id-01",
        device_handle="device-handle-opaque-03",
    )
    assert token == "f" * 64
    assert duplicate is False


def test_sqlite_rate_limit_rejects_zero_and_enforces_window(tmp_path):
    registry = RelayRegistry(tmp_path / "relay.sqlite", clock=lambda: 100)
    registry.provision_instance("instance-opaque-04")
    registry.register_device("instance-opaque-04", "device-handle-opaque-04", "f" * 64)

    with pytest.raises(OverflowError):
        registry.reserve_delivery(
            instance_id="instance-opaque-04",
            event_id="rate-event-id-01",
            device_handle="device-handle-opaque-04",
            limit_per_minute=0,
        )


def test_sqlite_rate_limit_rows_expire_like_firestore_ttl(tmp_path):
    now = [100.0]
    registry = RelayRegistry(tmp_path / "relay.sqlite", clock=lambda: now[0])
    registry.provision_instance("instance-opaque-05")
    registry.register_device("instance-opaque-05", "device-handle-opaque-05", "f" * 64)

    assert registry.reserve_delivery(
        instance_id="instance-opaque-05",
        event_id="rate-expiry-event-01",
        device_handle="device-handle-opaque-05",
        limit_per_minute=1,
    )[1] is False

    with sqlite3.connect(tmp_path / "relay.sqlite") as connection:
        expires_at = connection.execute(
            "SELECT expires_at FROM relay_rate_limits"
        ).fetchone()[0]
        assert expires_at == 180

    now[0] = 181.0
    assert registry.reserve_delivery(
        instance_id="instance-opaque-05",
        event_id="rate-expiry-event-02",
        device_handle="device-handle-opaque-05",
        limit_per_minute=1,
    )[1] is False

    with sqlite3.connect(tmp_path / "relay.sqlite") as connection:
        assert connection.execute("SELECT COUNT(*) FROM relay_rate_limits").fetchone()[0] == 1
