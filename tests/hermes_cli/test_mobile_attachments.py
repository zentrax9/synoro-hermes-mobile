"""Behavioral tests for the isolated mobile attachment backend."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from struct import pack
from threading import Barrier, Thread
from uuid import UUID, uuid4

import pytest

from hermes_cli.mobile_attachments import (
    AttachmentNotFound,
    AttachmentOwnershipError,
    AttachmentQuotaExceeded,
    AttachmentStorageError,
    AttachmentStore,
    InvalidAttachment,
    InvalidChunk,
    MAX_ATTACHMENT_BYTES,
    MAX_ATTACHMENT_REFS_PER_MESSAGE,
    MAX_AUDIO_SECONDS,
    MAX_UNFINISHED_BYTES_PER_DEVICE,
    MAX_UNFINISHED_UPLOADS_PER_DEVICE,
    UPLOAD_ABANDONED_AFTER_SECONDS,
    COMPLETED_UNATTACHED_AFTER_SECONDS,
    validate_attachment_refs,
)


OWNER = "access-subject"
DEVICE = "device-opaque-1"
CONVERSATION = "conversation-opaque-1"
MESSAGE = "message-opaque-1"


def _declare(store: AttachmentStore, *, data: bytes = b"hello", **kwargs):
    return store.declare_upload(
        owner_id=kwargs.pop("owner_id", OWNER),
        device_id=kwargs.pop("device_id", DEVICE),
        conversation_id=kwargs.pop("conversation_id", CONVERSATION),
        expected_size=kwargs.pop("expected_size", len(data)),
        expected_sha256=kwargs.pop("expected_sha256", sha256(data).hexdigest()),
        mime_type=kwargs.pop("mime_type", "text/plain"),
        display_name=kwargs.pop("display_name", "notes.txt"),
        now=kwargs.pop("now", 1000.0),
        **kwargs,
    )


def _put(store: AttachmentStore, upload_id: str, data: bytes, *, now: float = 1000.0, **kwargs):
    return store.upload_chunk(
        upload_id,
        f"bytes 0-{len(data) - 1}/{len(data)}",
        data,
        owner_id=kwargs.pop("owner_id", OWNER),
        device_id=kwargs.pop("device_id", DEVICE),
        conversation_id=kwargs.pop("conversation_id", CONVERSATION),
        now=now,
        **kwargs,
    )


def _iso_box(box_type: bytes, payload: bytes) -> bytes:
    return pack(">I4s", len(payload) + 8, box_type) + payload


def _m4a_payload(*, duration: int | None, timescale: int = 1000) -> bytes:
    ftyp = _iso_box(b"ftyp", b"M4A " + b"\x00" * 4 + b"M4A ")
    if duration is None:
        return ftyp + _iso_box(b"moov", b"")
    mvhd = (
        b"\x00" * 4
        + b"\x00" * 8
        + timescale.to_bytes(4, "big")
        + duration.to_bytes(4, "big")
    )
    return ftyp + _iso_box(b"moov", _iso_box(b"mvhd", mvhd))


def test_post_declare_uses_opaque_ids_and_sanitizes_display_name(tmp_path: Path):
    store = AttachmentStore(tmp_path)

    declared = _declare(
        store,
        display_name="../../private\\original.txt",
    )

    UUID(declared.upload_id)
    assert declared.upload_id not in str(declared.display_name)
    assert declared.display_name == "____private_original.txt"
    assert "/" not in declared.display_name
    assert "\\" not in declared.display_name
    assert ".." not in declared.display_name
    assert "original" in declared.display_name
    assert not (tmp_path / "private").exists()


def test_fixed_ordered_chunks_finalize_atomically_and_preserve_bytes(tmp_path: Path):
    data = b"a" * 8 + b"b" * 3
    store = AttachmentStore(tmp_path, chunk_size=8)
    declared = _declare(store, data=data)

    first = store.upload_chunk(
        declared.upload_id,
        "bytes 0-7/11",
        data[:8],
        owner_id=OWNER,
        device_id=DEVICE,
        conversation_id=CONVERSATION,
        now=1001.0,
    )
    assert first.next_offset == 8
    second = store.upload_chunk(
        declared.upload_id,
        "bytes 8-10/11",
        data[8:],
        owner_id=OWNER,
        device_id=DEVICE,
        conversation_id=CONVERSATION,
        now=1002.0,
    )
    assert second.next_offset == len(data)

    attachment = store.finalize_upload(
        declared.upload_id,
        owner_id=OWNER,
        device_id=DEVICE,
        conversation_id=CONVERSATION,
        now=1003.0,
    )
    assert attachment.attachment_id != declared.upload_id
    assert attachment.size == len(data)
    assert attachment.sha256 == sha256(data).hexdigest()
    assert store.read_attachment(
        attachment.attachment_id,
        owner_id=OWNER,
        device_id=DEVICE,
        conversation_id=CONVERSATION,
    ) == data
    assert not any(path.suffix == ".part" for path in (tmp_path / "uploads").iterdir())


def test_ranges_paths_and_mime_spoofing_fail_closed(tmp_path: Path):
    store = AttachmentStore(tmp_path, chunk_size=4)
    declared = _declare(store, data=b"abcdefgh", mime_type="text/plain")

    with pytest.raises(InvalidChunk):
        store.upload_chunk(
            declared.upload_id,
            "bytes 1-4/8",
            b"bcde",
            owner_id=OWNER,
            device_id=DEVICE,
            conversation_id=CONVERSATION,
        )
    with pytest.raises(InvalidChunk):
        store.upload_chunk(
            declared.upload_id,
            "bytes 0-3/9",
            b"abcd",
            owner_id=OWNER,
            device_id=DEVICE,
            conversation_id=CONVERSATION,
        )

    spoof_store = AttachmentStore(tmp_path / "spoof")
    spoof = _declare(spoof_store, data=b"not png", mime_type="image/png")
    _put(spoof_store, spoof.upload_id, b"not png")
    with pytest.raises(InvalidAttachment):
        spoof_store.finalize_upload(
            spoof.upload_id,
            owner_id=OWNER,
            device_id=DEVICE,
            conversation_id=CONVERSATION,
        )


def test_m4a_voice_container_matches_audio_mp4(tmp_path: Path):
    # MediaRecorder's AAC-LC/M4A output is an ISO-BMFF file branded ``M4A ``.
    payload = _m4a_payload(duration=5)
    store = AttachmentStore(tmp_path)
    upload = _declare(store, data=payload, mime_type="audio/mp4", display_name="voice.m4a")
    _put(store, upload.upload_id, payload)
    attachment = store.finalize_upload(
        upload.upload_id,
        owner_id=OWNER,
        device_id=DEVICE,
        conversation_id=CONVERSATION,
    )
    assert attachment.mime_type == "audio/mp4"


def test_m4a_duration_limit_is_enforced(tmp_path: Path):
    payload = _m4a_payload(duration=MAX_AUDIO_SECONDS * 1000 + 1)
    store = AttachmentStore(tmp_path)
    upload = _declare(store, data=payload, mime_type="audio/mp4", display_name="voice.m4a")
    _put(store, upload.upload_id, payload)

    with pytest.raises(InvalidAttachment, match="duration"):
        store.finalize_upload(
            upload.upload_id,
            owner_id=OWNER,
            device_id=DEVICE,
            conversation_id=CONVERSATION,
        )


@pytest.mark.parametrize(
    "payload",
    [
        _m4a_payload(duration=None),
        _iso_box(b"ftyp", b"M4A " + b"\x00" * 4 + b"M4A ")
        + pack(">I4s", 12, b"moov")
        + b"\x00" * 4,
    ],
    ids=["unknown-duration", "malformed-moov"],
)
def test_m4a_duration_must_be_verifiable(tmp_path: Path, payload: bytes):
    store = AttachmentStore(tmp_path)
    upload = _declare(store, data=payload, mime_type="audio/mp4", display_name="voice.m4a")
    _put(store, upload.upload_id, payload)

    with pytest.raises(InvalidAttachment, match="duration"):
        store.finalize_upload(
            upload.upload_id,
            owner_id=OWNER,
            device_id=DEVICE,
            conversation_id=CONVERSATION,
        )


def test_symlinked_staging_file_is_rejected_without_following_it(tmp_path: Path):
    store = AttachmentStore(tmp_path)
    declared = _declare(store, data=b"hello")
    staging = next((tmp_path / "uploads").glob("*.part"))
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"must remain untouched")
    staging.unlink()
    try:
        staging.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this host")

    with pytest.raises(AttachmentStorageError):
        _put(store, declared.upload_id, b"hello")
    assert outside.read_bytes() == b"must remain untouched"


def test_hash_size_and_scope_are_verified(tmp_path: Path):
    store = AttachmentStore(tmp_path)
    declared = _declare(store, data=b"hello", expected_sha256="0" * 64)
    _put(store, declared.upload_id, b"hello")

    with pytest.raises(AttachmentOwnershipError):
        store.finalize_upload(
            declared.upload_id,
            owner_id="other-owner",
            device_id=DEVICE,
            conversation_id=CONVERSATION,
        )
    with pytest.raises(InvalidAttachment):
        store.finalize_upload(
            declared.upload_id,
            owner_id=OWNER,
            device_id=DEVICE,
            conversation_id=CONVERSATION,
        )

    wrong_conversation = _declare(store, data=b"hello", conversation_id="different-conversation")
    with pytest.raises(AttachmentOwnershipError):
        _put(store, wrong_conversation.upload_id, b"hello", conversation_id=CONVERSATION)


def test_quota_limits_two_unfinished_uploads_per_device(tmp_path: Path):
    store = AttachmentStore(tmp_path)
    first = _declare(store, data=b"a")
    second = _declare(store, data=b"b")
    assert first.upload_id != second.upload_id

    with pytest.raises(AttachmentQuotaExceeded):
        _declare(store, data=b"c")

    assert MAX_UNFINISHED_UPLOADS_PER_DEVICE == 2
    assert MAX_ATTACHMENT_BYTES == 25 * 1024 * 1024


def test_unfinished_byte_quota_is_enforced_independently(monkeypatch, tmp_path: Path):
    import hermes_cli.mobile_attachments as module

    monkeypatch.setattr(module, "MAX_UNFINISHED_UPLOADS_PER_DEVICE", 10)
    store = AttachmentStore(tmp_path)
    digest = "0" * 64
    for _ in range(4):
        store.declare_upload(
            OWNER,
            DEVICE,
            CONVERSATION,
            MAX_ATTACHMENT_BYTES,
            digest,
            "application/octet-stream",
            "large.bin",
        )
    assert 4 * MAX_ATTACHMENT_BYTES <= MAX_UNFINISHED_BYTES_PER_DEVICE
    with pytest.raises(AttachmentQuotaExceeded):
        store.declare_upload(
            OWNER,
            DEVICE,
            CONVERSATION,
            MAX_ATTACHMENT_BYTES,
            digest,
            "application/octet-stream",
            "too-large.bin",
        )


def test_message_attachment_contract_and_cleanup(tmp_path: Path):
    store = AttachmentStore(tmp_path)
    attachment_ids = []
    for index in range(MAX_ATTACHMENT_REFS_PER_MESSAGE):
        payload = f"attachment-{index}".encode()
        upload = _declare(store, data=payload, display_name=f"{index}.txt")
        _put(store, upload.upload_id, payload)
        attachment = store.finalize_upload(
            upload.upload_id,
            owner_id=OWNER,
            device_id=DEVICE,
            conversation_id=CONVERSATION,
            now=1100.0,
        )
        attachment_ids.append(attachment.attachment_id)

    assert validate_attachment_refs(attachment_ids) == tuple(attachment_ids)
    with pytest.raises(InvalidAttachment):
        validate_attachment_refs(attachment_ids + [str(uuid4())])
    store.attach_to_message(
        attachment_ids,
        owner_id=OWNER,
        device_id=DEVICE,
        conversation_id=CONVERSATION,
        message_id=MESSAGE,
        now=1101.0,
    )
    with pytest.raises(InvalidAttachment):
        store.attach_to_message(
            attachment_ids + [attachment_ids[0]],
            owner_id=OWNER,
            device_id=DEVICE,
            conversation_id=CONVERSATION,
            message_id=MESSAGE,
        )

    abandoned = _declare(store, data=b"abandoned", now=2000.0)
    removed = store.cleanup(now=2000.0 + UPLOAD_ABANDONED_AFTER_SECONDS + 1)
    assert removed.unfinished_uploads >= 1
    with pytest.raises(AttachmentNotFound):
        store.get_upload(
            abandoned.upload_id,
            owner_id=OWNER,
            device_id=DEVICE,
            conversation_id=CONVERSATION,
        )

    unattached = _declare(store, data=b"old")
    _put(store, unattached.upload_id, b"old")
    completed = store.finalize_upload(
        unattached.upload_id,
        owner_id=OWNER,
        device_id=DEVICE,
        conversation_id=CONVERSATION,
        now=3000.0,
    )
    removed = store.cleanup(now=3000.0 + COMPLETED_UNATTACHED_AFTER_SECONDS + 1)
    assert removed.completed_attachments >= 1
    with pytest.raises(AttachmentNotFound):
        store.read_attachment(
            completed.attachment_id,
            owner_id=OWNER,
            device_id=DEVICE,
            conversation_id=CONVERSATION,
        )


def test_concurrent_declarations_cannot_bypass_device_quota(tmp_path: Path):
    store = AttachmentStore(tmp_path)
    barrier = Barrier(2)
    results: list[object] = []

    def declare() -> None:
        barrier.wait()
        try:
            results.append(_declare(store, data=b"x"))
        except Exception as exc:  # the result is asserted below
            results.append(exc)

    threads = [Thread(target=declare) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert len(results) == 2
    assert sum(isinstance(result, Exception) for result in results) == 0
    with pytest.raises(AttachmentQuotaExceeded):
        _declare(store, data=b"third")


def test_concurrent_finalization_returns_one_atomic_attachment(tmp_path: Path):
    store = AttachmentStore(tmp_path)
    payload = b"atomic-finalization"
    declared = _declare(store, data=payload)
    _put(store, declared.upload_id, payload)
    barrier = Barrier(2)
    results: list[object] = []

    def finalize() -> None:
        barrier.wait()
        try:
            results.append(
                store.finalize_upload(
                    declared.upload_id,
                    owner_id=OWNER,
                    device_id=DEVICE,
                    conversation_id=CONVERSATION,
                )
            )
        except Exception as exc:  # the result is asserted below
            results.append(exc)

    threads = [Thread(target=finalize) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert len(results) == 2
    assert all(not isinstance(result, Exception) for result in results)
    assert {result.attachment_id for result in results if not isinstance(result, Exception)}.__len__() == 1
