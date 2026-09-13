from types import SimpleNamespace

import httpx

from hermes_cli import mobile_cmd


class _Store:
    def __init__(self):
        self.revoked = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def revoke_device(self, device_id):
        self.revoked.append(device_id)
        return SimpleNamespace(device_id=device_id, device_label="Owner phone", push_handle="push-handle-opaque-01")


def _args(device_id="device-opaque-01"):
    return SimpleNamespace(
        mobile_action="devices",
        device_action="revoke",
        device_id=device_id,
    )


def test_cli_revoke_keeps_local_revocation_when_relay_is_unavailable(monkeypatch, capsys):
    store = _Store()

    class _Relay:
        def revoke_device(self, _handle):
            raise httpx.ConnectError("relay unavailable")

    monkeypatch.setattr(mobile_cmd, "_configured_store", lambda: store)
    monkeypatch.setattr(mobile_cmd, "_configured_relay", lambda: _Relay())

    assert mobile_cmd.cmd_mobile(_args()) == 0
    assert store.revoked == ["device-opaque-01"]
    output = capsys.readouterr()
    assert "local revocation succeeded" in output.err
    assert "Revoked Hermes Mobile device device-opaque-01" in output.out


def test_cli_revoke_does_not_require_a_push_relay(monkeypatch, capsys):
    store = _Store()
    monkeypatch.setattr(mobile_cmd, "_configured_store", lambda: store)
    monkeypatch.setattr(mobile_cmd, "_configured_relay", lambda: None)

    assert mobile_cmd.cmd_mobile(_args("device-opaque-02")) == 0
    assert store.revoked == ["device-opaque-02"]
    output = capsys.readouterr()
    assert output.err == ""


def test_configured_relay_rejects_non_mapping_push_config(monkeypatch):
    monkeypatch.setattr(mobile_cmd, "load_config", lambda: {"mobile": {"push_relay": []}})

    try:
        mobile_cmd._configured_relay()
    except SystemExit as exc:
        assert str(exc) == "Configure mobile.push_relay as a mapping"
    else:
        raise AssertionError("malformed push relay config was accepted")
