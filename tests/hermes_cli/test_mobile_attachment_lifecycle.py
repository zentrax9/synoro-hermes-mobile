"""Lifecycle tests for the mobile attachment retention hook."""

from __future__ import annotations

from hashlib import sha256
from threading import Event
import time

import httpx
import pytest

from hermes_cli.mobile_attachments import (
    AttachmentNotFound,
    MobileAttachmentStore,
    UPLOAD_ABANDONED_AFTER_SECONDS,
)
from hermes_cli.mobile_server import running_mobile_listener


class _SlowCleanup:
    def __init__(self) -> None:
        self.started = Event()
        self.release = Event()

    def cleanup(self) -> None:
        self.started.set()
        assert self.release.wait(5), "test cleanup did not receive its release signal"


class _FailingCleanup:
    def __init__(self) -> None:
        self.finished = Event()

    def cleanup(self) -> None:
        self.finished.set()
        raise RuntimeError("synthetic cleanup failure")


class _CountingCleanup:
    def __init__(self) -> None:
        self.calls = 0
        self.second_call = Event()

    def cleanup(self) -> None:
        self.calls += 1
        if self.calls >= 2:
            self.second_call.set()


def test_listener_starts_cleanup_off_request_and_event_loop_path() -> None:
    cleanup = _SlowCleanup()
    try:
        with running_mobile_listener(
            host="127.0.0.1",
            port=0,
            authorize=lambda _request: None,
            attachments=cleanup,  # type: ignore[arg-type]
        ) as listener:
            assert cleanup.started.wait(2)
            response = httpx.get(
                f"http://127.0.0.1:{listener.port}/mobile/v1/capabilities",
                timeout=2,
            )
            assert response.status_code == 200
            cleanup.release.set()
    finally:
        cleanup.release.set()


def test_cleanup_failure_does_not_take_down_listener(caplog: pytest.LogCaptureFixture) -> None:
    cleanup = _FailingCleanup()
    with running_mobile_listener(
        host="127.0.0.1",
        port=0,
        authorize=lambda _request: None,
        attachments=cleanup,  # type: ignore[arg-type]
    ) as listener:
        assert cleanup.finished.wait(2)
        response = httpx.get(
            f"http://127.0.0.1:{listener.port}/mobile/v1/capabilities",
            timeout=2,
        )
        assert response.status_code == 200
    assert "Mobile attachment cleanup failed (RuntimeError)" in caplog.text


def test_listener_reaps_again_while_it_remains_running(monkeypatch: pytest.MonkeyPatch) -> None:
    import hermes_cli.mobile_server as mobile_server

    monkeypatch.setattr(mobile_server, "_ATTACHMENT_CLEANUP_INTERVAL_SECONDS", 0.01)
    cleanup = _CountingCleanup()
    with running_mobile_listener(
        host="127.0.0.1",
        port=0,
        authorize=lambda _request: None,
        attachments=cleanup,  # type: ignore[arg-type]
    ):
        assert cleanup.second_call.wait(2)
        assert cleanup.calls >= 2


def test_listener_cleanup_reaps_only_stale_uploads_and_keeps_unknown_files(tmp_path) -> None:
    store = MobileAttachmentStore(tmp_path / "attachments")
    now = time.time()
    fresh = store.declare_upload(
        owner_id="owner",
        device_id="fresh-device",
        conversation_id="conversation",
        expected_size=5,
        expected_sha256=sha256(b"fresh").hexdigest(),
        mime_type="text/plain",
        display_name="fresh.txt",
        now=now,
    )
    stale = store.declare_upload(
        owner_id="owner",
        device_id="stale-device",
        conversation_id="conversation",
        expected_size=6,
        expected_sha256=sha256(b"stale!").hexdigest(),
        mime_type="text/plain",
        display_name="stale.txt",
        now=now - UPLOAD_ABANDONED_AFTER_SECONDS - 1,
    )
    orphan = store.uploads_root / "untracked.part"
    orphan.write_bytes(b"must remain untouched")

    try:
        with running_mobile_listener(
            host="127.0.0.1",
            port=0,
            authorize=lambda _request: None,
            attachments=store,
        ):
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    store.get_upload(
                        stale.upload_id,
                        owner_id="owner",
                        device_id="stale-device",
                        conversation_id="conversation",
                    )
                except AttachmentNotFound:
                    break
                time.sleep(0.01)
            else:
                pytest.fail("listener cleanup did not reap the stale upload")

            assert store.get_upload(
                fresh.upload_id,
                owner_id="owner",
                device_id="fresh-device",
                conversation_id="conversation",
            ).upload_id == fresh.upload_id
            assert orphan.read_bytes() == b"must remain untouched"
    finally:
        store.close()
