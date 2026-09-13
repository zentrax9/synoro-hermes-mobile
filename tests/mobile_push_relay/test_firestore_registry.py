from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import RLock

import pytest

import services.mobile_push_relay.app as relay_app
from services.mobile_push_relay.app import FirestoreRelayRegistry


class Snapshot:
    def __init__(self, reference, values):
        self.reference = reference
        self._values = None if values is None else dict(values)

    @property
    def exists(self):
        return self._values is not None

    def to_dict(self):
        return None if self._values is None else dict(self._values)


class Reference:
    def __init__(self, client, collection, document_id):
        self.client = client
        self.collection = collection
        self.id = document_id


class Query:
    def __init__(self, client, collection, field, value):
        self.client = client
        self.collection = collection
        self.field = field
        self.value = value

    def stream(self):
        for (collection, _document_id), values in list(self.client.documents.items()):
            if collection == self.collection and values.get(self.field) == self.value:
                yield Snapshot(Reference(self.client, collection, _document_id), values)


class Collection:
    def __init__(self, client, name):
        self.client = client
        self.name = name

    def document(self, document_id):
        return Reference(self.client, self.name, document_id)

    def where(self, field, _operator, value):
        return Query(self.client, self.name, field, value)


class Transaction:
    def __init__(self, client):
        self.client = client
        self.writes = []

    def get(self, reference):
        return Snapshot(reference, self.client.documents.get((reference.collection, reference.id)))

    def create(self, reference, values):
        if (reference.collection, reference.id) in self.client.documents:
            raise ValueError("already exists")
        self.writes.append(("create", reference, dict(values)))

    def set(self, reference, values, merge=False):
        self.writes.append(("set", reference, dict(values), merge))

    def delete(self, reference):
        self.writes.append(("delete", reference))

    def commit(self):
        for write in self.writes:
            operation, reference, *payload = write
            key = (reference.collection, reference.id)
            if operation == "delete":
                self.client.documents.pop(key, None)
                continue
            values = payload[0]
            merge = operation == "set" and len(payload) > 1 and payload[1]
            if merge:
                existing = dict(self.client.documents.get(key, {}))
                existing.update(values)
                self.client.documents[key] = existing
            else:
                self.client.documents[key] = values


class FakeFirestore:
    def __init__(self):
        self.documents = {}
        self.lock = RLock()

    def collection(self, name):
        return Collection(self, name)

    def transaction(self):
        return Transaction(self)

    def run_transaction(self, callback):
        with self.lock:
            transaction = self.transaction()
            value = callback(transaction)
            transaction.commit()
            return value


def _registry(fake, clock=lambda: 100.0):
    return FirestoreRelayRegistry(
        client=fake,
        transaction_runner=fake.run_transaction,
        clock=clock,
    )


def test_firestore_transactionally_owns_handles_and_rotates_tokens():
    fake = FakeFirestore()
    registry = _registry(fake)
    credential = registry.provision_instance("instance-opaque-11")
    registry.provision_instance("instance-opaque-12")
    registry.register_device("instance-opaque-11", "device-handle-opaque-11", "a" * 64)

    with pytest.raises(PermissionError):
        registry.register_device("instance-opaque-12", "device-handle-opaque-11", "b" * 64)
    registry.register_device("instance-opaque-11", "device-handle-opaque-11", "c" * 64)
    assert registry.reserve_delivery(
        instance_id="instance-opaque-11",
        event_id="firestore-event-id-01",
        device_handle="device-handle-opaque-11",
    )[0] == "c" * 64
    assert registry.authenticate(f"Bearer {credential}") == "instance-opaque-11"

    registry.revoke_device("instance-opaque-11", "device-handle-opaque-11")
    with pytest.raises(KeyError):
        registry.reserve_delivery(
            instance_id="instance-opaque-11",
            event_id="firestore-event-id-02",
            device_handle="device-handle-opaque-11",
        )


def test_firestore_dedup_ttl_rate_limit_and_no_content_fields():
    fake = FakeFirestore()
    now = [100.0]
    registry = _registry(fake, clock=lambda: now[0])
    registry.provision_instance("instance-opaque-13")
    registry.register_device("instance-opaque-13", "device-handle-opaque-13", "d" * 64)

    assert registry.reserve_delivery(
        instance_id="instance-opaque-13",
        event_id="firestore-event-id-03",
        device_handle="device-handle-opaque-13",
    )[1] is False
    assert registry.reserve_delivery(
        instance_id="instance-opaque-13",
        event_id="firestore-event-id-03",
        device_handle="device-handle-opaque-13",
    )[1] is True
    with pytest.raises(OverflowError):
        registry.reserve_delivery(
            instance_id="instance-opaque-13",
            event_id="firestore-event-id-04",
            device_handle="device-handle-opaque-13",
            limit_per_minute=0,
        )

    now[0] += registry.dedup_ttl_seconds + 1
    assert registry.reserve_delivery(
        instance_id="instance-opaque-13",
        event_id="firestore-event-id-03",
        device_handle="device-handle-opaque-13",
    )[1] is False
    forbidden = {"body", "content", "title", "transcript", "payload"}
    for values in fake.documents.values():
        assert forbidden.isdisjoint(values)


def test_firestore_failed_delivery_can_be_released_and_completed():
    fake = FakeFirestore()
    registry = _registry(fake)
    registry.provision_instance("instance-opaque-15")
    registry.register_device("instance-opaque-15", "device-handle-opaque-15", "f" * 64)

    assert registry.reserve_delivery(
        instance_id="instance-opaque-15",
        event_id="firestore-retry-event-01",
        device_handle="device-handle-opaque-15",
    )[1] is False
    assert registry.delivery_pending(
        instance_id="instance-opaque-15",
        event_id="firestore-retry-event-01",
        device_handle="device-handle-opaque-15",
    ) is True
    registry.release_delivery(
        instance_id="instance-opaque-15",
        event_id="firestore-retry-event-01",
        device_handle="device-handle-opaque-15",
    )
    assert registry.delivery_pending(
        instance_id="instance-opaque-15",
        event_id="firestore-retry-event-01",
        device_handle="device-handle-opaque-15",
    ) is False
    assert registry.reserve_delivery(
        instance_id="instance-opaque-15",
        event_id="firestore-retry-event-01",
        device_handle="device-handle-opaque-15",
    )[1] is False
    registry.complete_delivery(
        instance_id="instance-opaque-15",
        event_id="firestore-retry-event-01",
        device_handle="device-handle-opaque-15",
    )
    assert registry.delivery_pending(
        instance_id="instance-opaque-15",
        event_id="firestore-retry-event-01",
        device_handle="device-handle-opaque-15",
    ) is False
    assert registry.reserve_delivery(
        instance_id="instance-opaque-15",
        event_id="firestore-retry-event-01",
        device_handle="device-handle-opaque-15",
    )[1] is True


def test_firestore_event_idempotency_is_scoped_to_device():
    fake = FakeFirestore()
    registry = _registry(fake)
    registry.provision_instance("instance-opaque-16")
    registry.register_device("instance-opaque-16", "device-handle-opaque-16", "a" * 64)
    registry.register_device("instance-opaque-16", "device-handle-opaque-17", "b" * 64)

    assert registry.reserve_delivery(
        instance_id="instance-opaque-16",
        event_id="firestore-shared-event-01",
        device_handle="device-handle-opaque-16",
    )[1] is False
    assert registry.reserve_delivery(
        instance_id="instance-opaque-16",
        event_id="firestore-shared-event-01",
        device_handle="device-handle-opaque-17",
    )[1] is False


def test_firestore_concurrent_reservation_has_one_winner():
    fake = FakeFirestore()
    registry = _registry(fake)
    registry.provision_instance("instance-opaque-14")
    registry.register_device("instance-opaque-14", "device-handle-opaque-14", "e" * 64)

    def reserve():
        return registry.reserve_delivery(
            instance_id="instance-opaque-14",
            event_id="firestore-event-id-05",
            device_handle="device-handle-opaque-14",
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _index: reserve(), range(8)))
    assert sum(not duplicate for _token, duplicate in results) == 1
    assert sum(duplicate for _token, duplicate in results) == 7


def test_production_selection_fails_closed_without_sqlite_fallback(monkeypatch, tmp_path):
    sentinel = object()
    monkeypatch.setattr(relay_app, "FirestoreRelayRegistry", lambda project_id=None: sentinel)
    with pytest.raises(RuntimeError):
        relay_app.create_registry_from_environment(
            {"K_SERVICE": "relay", "RELAY_BACKEND": "sqlite", "RELAY_DB_PATH": str(tmp_path / "x")}
        )
    assert (
        relay_app.create_registry_from_environment(
            {"K_SERVICE": "relay", "GOOGLE_CLOUD_PROJECT": "project-opaque"}
        )
        is sentinel
    )
