import httpx
import pytest

from hermes_cli.mobile_push import MobilePushEvent, MobilePushRelayClient


def test_push_client_can_send_only_fixed_events_and_never_notification_text():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, request=request)

    client = MobilePushRelayClient(
        base_url="https://relay.example.com",
        credential="c" * 32,
        transport=httpx.MockTransport(handler),
        clock=lambda: 100,
    )

    client.notify(
        event_type=MobilePushEvent.RUN_COMPLETED,
        event_id="event-opaque-id-01",
        device_handle="device-handle-opaque-01",
        ttl_seconds=60,
    )

    body = requests[0].content.decode()
    assert requests[0].url.path == "/v1/push"
    assert '"event_type":"run_completed"' in body
    assert "title" not in body
    assert "body" not in body


def test_push_client_registers_and_revokes_with_relay_only_credential():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(204, request=request)

    client = MobilePushRelayClient(
        base_url="https://relay.example.com",
        credential="c" * 32,
        transport=httpx.MockTransport(handler),
    )
    client.register_device("device-handle-opaque-01", "f" * 64)
    client.revoke_device("device-handle-opaque-01")

    assert [(request.method, request.url.path) for request in requests] == [
        ("PUT", "/v1/devices/device-handle-opaque-01"),
        ("DELETE", "/v1/devices/device-handle-opaque-01"),
    ]


@pytest.mark.parametrize(
    "base_url,credential",
    [
        ("https://user:password@relay.example.com", "c" * 32),
        ("https://relay.example.com/relay", "c" * 32),
        ("https://relay.example.com", "c" * 31),
        ("https://relay.example.com", "c" * 31 + "\n"),
    ],
)
def test_push_client_rejects_unsafe_operator_coordinates(base_url, credential):
    with pytest.raises(ValueError):
        MobilePushRelayClient(base_url=base_url, credential=credential)
