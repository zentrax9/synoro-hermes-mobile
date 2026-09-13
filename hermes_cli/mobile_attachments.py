"""Private, resumable attachment storage for the isolated Hermes mobile API.

This module deliberately owns only the storage primitive.  HTTP routes and message
dispatchers should authenticate the caller and pass the resulting device, owner, and
conversation scope to every method here.  No client supplied path is ever accepted;
the store creates opaque UUID names below its private root.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
import hashlib
import hmac
from io import BytesIO
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
import unicodedata
from uuid import UUID, uuid4
import wave

from hermes_constants import get_hermes_home


MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024
MAX_ATTACHMENT_REFS_PER_MESSAGE = 6
MAX_UNFINISHED_UPLOADS_PER_DEVICE = 2
MAX_UNFINISHED_BYTES_PER_DEVICE = 100 * 1024 * 1024
MAX_PDF_PAGES = 25
MAX_IMAGE_PIXELS = 40_000_000
MAX_AUDIO_SECONDS = 10 * 60
UPLOAD_ABANDONED_AFTER_SECONDS = 60 * 60
COMPLETED_UNATTACHED_AFTER_SECONDS = 24 * 60 * 60
DEFAULT_CHUNK_SIZE = 1024 * 1024
CHUNK_SIZE = DEFAULT_CHUNK_SIZE

_UPLOAD_STATE = "uploading"
_COMPLETED_STATE = "completed"
_REJECTED_STATE = "rejected"
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_CONTENT_RANGE_RE = re.compile(r"^bytes ([0-9]+)-([0-9]+)/([0-9]+)$")
_MIME_RE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
_SCOPE_MAX_LENGTH = 256
_MAX_ISO_BMFF_BOXES = 4096
_MAX_ISO_BMFF_DEPTH = 8
_ISO_BMFF_CONTAINERS = frozenset({b"trak", b"mdia"})
_ISO_BMFF_DURATION_BOXES = frozenset({b"mvhd", b"mdhd"})
_ISO_BMFF_DURATION_ERROR = "audio duration could not be verified"


class MobileAttachmentError(RuntimeError):
    """Base class for fail-closed attachment errors."""


class InvalidAttachment(MobileAttachmentError, ValueError):
    """The declaration or completed bytes violate the attachment contract."""


class InvalidChunk(MobileAttachmentError, ValueError):
    """A chunk or Content-Range is not the next fixed-size chunk."""


class AttachmentNotFound(MobileAttachmentError, LookupError):
    """The opaque upload or attachment identifier is unknown."""


class AttachmentOwnershipError(MobileAttachmentError, PermissionError):
    """The supplied owner, device, or conversation does not match the row."""


class AttachmentQuotaExceeded(MobileAttachmentError, ValueError):
    """A per-device upload or message-reference quota would be exceeded."""


class AttachmentStorageError(MobileAttachmentError):
    """The private storage root cannot safely be used."""


@dataclass(frozen=True, slots=True)
class UploadStatus:
    upload_id: str
    owner_id: str
    device_id: str
    conversation_id: str
    expected_size: int
    expected_sha256: str
    mime_type: str
    display_name: str
    chunk_size: int
    received_bytes: int
    next_offset: int
    state: str
    created_at: float
    updated_at: float
    completed_at: float | None = None
    attachment_id: str | None = None

    @property
    def size(self) -> int:
        return self.expected_size

    @property
    def total_size(self) -> int:
        return self.expected_size

    @property
    def received(self) -> int:
        return self.received_bytes

    @property
    def sha256(self) -> str:
        return self.expected_sha256

    @property
    def complete(self) -> bool:
        return self.state == _COMPLETED_STATE

    @property
    def status(self) -> str:
        return self.state

    @property
    def id(self) -> str:
        return self.upload_id


@dataclass(frozen=True, slots=True)
class AttachmentRecord:
    attachment_id: str
    upload_id: str
    owner_id: str
    device_id: str
    conversation_id: str
    size: int
    sha256: str
    mime_type: str
    display_name: str
    created_at: float
    completed_at: float

    @property
    def filename(self) -> str:
        return self.display_name

    @property
    def id(self) -> str:
        return self.attachment_id


@dataclass(frozen=True, slots=True)
class CleanupResult:
    unfinished_uploads: int = 0
    completed_attachments: int = 0
    bytes_reclaimed: int = 0

    @property
    def uploads(self) -> int:
        return self.unfinished_uploads

    @property
    def attachments(self) -> int:
        return self.completed_attachments


# These names are useful to callers that prefer the resource-oriented spelling.
AttachmentUpload = UploadStatus
MobileAttachment = AttachmentRecord


def _validate_scope(value: str, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _SCOPE_MAX_LENGTH
        or value in {".", ".."}
        or any(ord(character) < 0x20 for character in value)
        or "/" in value
        or "\\" in value
    ):
        raise InvalidAttachment(f"{field} must be a non-empty opaque scope value")
    return value


def _resolve_owner(owner_id: str | None, access_subject: str | None) -> str:
    if access_subject is not None:
        if owner_id is not None and owner_id != access_subject:
            raise InvalidAttachment("owner_id and access_subject disagree")
        owner_id = access_subject
    return _validate_scope(owner_id, "owner_id")


def _canonical_uuid(value: str | UUID, field: str) -> str:
    try:
        canonical = str(UUID(str(value)))
    except (AttributeError, TypeError, ValueError) as exc:
        raise InvalidAttachment(f"{field} must be an opaque UUID") from exc
    if not _UUID_RE.fullmatch(canonical):
        raise InvalidAttachment(f"{field} must be an opaque UUID")
    return canonical


def validate_attachment_refs(
    attachment_ids: Iterable[str | UUID],
    *,
    max_refs: int = MAX_ATTACHMENT_REFS_PER_MESSAGE,
) -> tuple[str, ...]:
    """Validate and canonicalize the bounded attachment-reference contract."""

    if isinstance(attachment_ids, (str, bytes, UUID)):
        values = (attachment_ids,)
    else:
        try:
            values = tuple(attachment_ids)
        except TypeError as exc:
            raise InvalidAttachment("attachment references must be a sequence") from exc
    if max_refs < 0 or len(values) > max_refs:
        raise InvalidAttachment("a message may reference at most six attachments")
    result = tuple(_canonical_uuid(value, "attachment_id") for value in values)
    if len(set(result)) != len(result):
        raise InvalidAttachment("attachment references must be unique")
    return result


def validate_message_attachment_refs(
    attachment_ids: Iterable[str | UUID],
) -> tuple[str, ...]:
    """Alias used by message-contract code."""

    return validate_attachment_refs(attachment_ids)


def _normalize_sha256(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise InvalidAttachment("sha256 must be a 64-character hexadecimal digest")
    return value.lower()


def _normalize_mime(value: str) -> str:
    if not isinstance(value, str):
        raise InvalidAttachment("mime_type must be a MIME type")
    mime = value.split(";", 1)[0].strip().lower()
    if len(mime) > 128 or not _MIME_RE.fullmatch(mime):
        raise InvalidAttachment("mime_type must be a valid MIME type")
    return mime


def sanitize_display_filename(value: str) -> str:
    """Return a safe display-only name; the client supplied original is discarded."""

    if not isinstance(value, str) or not value:
        raise InvalidAttachment("display_name is required")
    normalized = unicodedata.normalize("NFKC", value)
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in normalized):
        raise InvalidAttachment("display_name contains a control character")
    normalized = normalized.replace("/", "_").replace("\\", "_")
    normalized = re.sub(r"\.{2,}", "_", normalized)
    normalized = re.sub(r"[^A-Za-z0-9._ -]", "_", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip(" .")
    normalized = normalized[:128]
    if not normalized or normalized in {".", ".."}:
        return "attachment"
    return normalized


def parse_content_range(value: str) -> tuple[int, int, int]:
    """Parse a strict byte Content-Range, rejecting open-ended or malformed ranges."""

    if not isinstance(value, str):
        raise InvalidChunk("Content-Range must be a byte range")
    match = _CONTENT_RANGE_RE.fullmatch(value.strip())
    if match is None:
        raise InvalidChunk("Content-Range must use bytes start-end/total")
    start, end, total = (int(part) for part in match.groups())
    if start < 0 or end < start or total <= 0 or end >= total:
        raise InvalidChunk("Content-Range is outside the declared upload")
    return start, end, total


def _signature_mime(data: bytes) -> str | None:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data.startswith(b"%PDF-"):
        return "application/pdf"
    if data.startswith(b"\x1f\x8b"):
        return "application/gzip"
    if data.startswith(b"PK\x03\x04"):
        return "application/zip"
    if data.startswith((b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2")):
        return "audio/mpeg"
    if data.startswith(b"OggS"):
        return "audio/ogg"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        # AAC-LC/M4A voice notes use the ISO-BMFF container too.  Distinguish
        # the audio brands so a declared ``audio/mp4`` upload is not rejected
        # as a video merely because both share the ``ftyp`` header.
        brand = data[8:12].lower()
        if brand in {b"m4a ", b"m4b ", b"m4p "}:
            return "audio/mp4"
        return "video/mp4"
    return None


def _mime_matches(data: bytes, declared: str) -> bool:
    signature = _signature_mime(data[:4096])
    if declared == "application/octet-stream":
        return True
    if declared == "application/json":
        if signature is not None:
            return False
        try:
            json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
        return True
    if declared.startswith("text/"):
        if signature is not None:
            return False
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return "\x00" not in text
    if declared == "image/svg+xml":
        if signature is not None:
            return False
        try:
            text = data.decode("utf-8", errors="strict").lstrip("\ufeff \t\r\n")
        except UnicodeDecodeError:
            return False
        return "<svg" in text[:4096].lower()
    return signature == declared


def _iso_bmff_box_bounds(data: bytes, offset: int, end: int) -> tuple[bytes, int, int]:
    """Return one ISO-BMFF box type and payload bounds, rejecting bad sizes."""

    if end - offset < 8:
        raise InvalidAttachment(_ISO_BMFF_DURATION_ERROR)
    size = int.from_bytes(data[offset:offset + 4], "big")
    box_type = data[offset + 4:offset + 8]
    header_size = 8
    if size == 1:
        if end - offset < 16:
            raise InvalidAttachment(_ISO_BMFF_DURATION_ERROR)
        size = int.from_bytes(data[offset + 8:offset + 16], "big")
        header_size = 16
    elif size == 0:
        size = end - offset
    if size < header_size or size > end - offset:
        raise InvalidAttachment(_ISO_BMFF_DURATION_ERROR)
    payload_start = offset + header_size
    return box_type, payload_start, offset + size


def _iso_bmff_duration(payload: bytes) -> tuple[int, int]:
    """Read a versioned ``mvhd`` or ``mdhd`` duration and timescale."""

    if not payload:
        raise InvalidAttachment(_ISO_BMFF_DURATION_ERROR)
    version = payload[0]
    if version == 0:
        if len(payload) < 20:
            raise InvalidAttachment(_ISO_BMFF_DURATION_ERROR)
        timescale = int.from_bytes(payload[12:16], "big")
        duration = int.from_bytes(payload[16:20], "big")
    elif version == 1:
        if len(payload) < 32:
            raise InvalidAttachment(_ISO_BMFF_DURATION_ERROR)
        timescale = int.from_bytes(payload[20:24], "big")
        duration = int.from_bytes(payload[24:32], "big")
    else:
        raise InvalidAttachment(_ISO_BMFF_DURATION_ERROR)
    if timescale <= 0 or duration <= 0:
        raise InvalidAttachment(_ISO_BMFF_DURATION_ERROR)
    return duration, timescale


def _validate_iso_bmff_audio_duration(data: bytes) -> None:
    """Verify a bounded ISO-BMFF audio duration using standard header boxes."""

    box_count = 0
    saw_ftyp = False
    saw_moov = False
    durations: list[tuple[int, int]] = []

    def walk(start: int, end: int, depth: int) -> None:
        nonlocal box_count, saw_ftyp, saw_moov
        if depth > _MAX_ISO_BMFF_DEPTH:
            raise InvalidAttachment(_ISO_BMFF_DURATION_ERROR)
        offset = start
        while offset < end:
            box_count += 1
            if box_count > _MAX_ISO_BMFF_BOXES:
                raise InvalidAttachment(_ISO_BMFF_DURATION_ERROR)
            box_type, payload_start, box_end = _iso_bmff_box_bounds(data, offset, end)
            if depth == 0 and box_type == b"ftyp":
                if box_end - payload_start < 8 or data[payload_start:payload_start + 4] not in {
                    b"M4A ",
                    b"M4B ",
                    b"M4P ",
                }:
                    raise InvalidAttachment(_ISO_BMFF_DURATION_ERROR)
                saw_ftyp = True
            elif depth == 0 and box_type == b"moov":
                if saw_moov:
                    raise InvalidAttachment(_ISO_BMFF_DURATION_ERROR)
                saw_moov = True
                walk(payload_start, box_end, depth + 1)
            elif depth > 0 and box_type in _ISO_BMFF_DURATION_BOXES:
                durations.append(_iso_bmff_duration(data[payload_start:box_end]))
            elif depth > 0 and box_type in _ISO_BMFF_CONTAINERS:
                walk(payload_start, box_end, depth + 1)
            offset = box_end

    walk(0, len(data), 0)
    if not saw_ftyp or not saw_moov or not durations:
        raise InvalidAttachment(_ISO_BMFF_DURATION_ERROR)
    for duration, timescale in durations:
        if duration > MAX_AUDIO_SECONDS * timescale:
            raise InvalidAttachment("audio duration limit exceeded")


def _validate_parser_limits(data: bytes, mime_type: str) -> None:
    """Apply bounded media sanity checks without extracting or previewing content."""

    if mime_type == "application/pdf":
        # This is deliberately a conservative lexical page count.  Rendering is
        # not performed by the mobile listener, so malformed PDFs remain opaque.
        if data.count(b"/Type /Page") > MAX_PDF_PAGES:
            raise InvalidAttachment("PDF page limit exceeded")
        return
    if mime_type == "image/png" and len(data) >= 24 and data.startswith(b"\x89PNG\r\n\x1a\n"):
        width = int.from_bytes(data[16:20], "big")
        height = int.from_bytes(data[20:24], "big")
        if width <= 0 or height <= 0 or width * height > MAX_IMAGE_PIXELS:
            raise InvalidAttachment("image pixel limit exceeded")
        return
    if mime_type in {"image/jpeg", "image/jpg"} and data.startswith(b"\xff\xd8"):
        index = 2
        while index + 9 < len(data):
            if data[index] != 0xFF:
                index += 1
                continue
            marker = data[index + 1]
            index += 2
            if marker in {0xD8, 0xD9}:
                continue
            if index + 2 > len(data):
                break
            segment_length = int.from_bytes(data[index:index + 2], "big")
            if segment_length < 2 or index + segment_length > len(data):
                break
            if marker in set(range(0xC0, 0xC4)) | set(range(0xC5, 0xC8)) | set(range(0xC9, 0xCC)) | set(range(0xCD, 0xD0)):
                height = int.from_bytes(data[index + 3:index + 5], "big")
                width = int.from_bytes(data[index + 5:index + 7], "big")
                if width <= 0 or height <= 0 or width * height > MAX_IMAGE_PIXELS:
                    raise InvalidAttachment("image pixel limit exceeded")
                return
            index += segment_length
        return
    if mime_type in {"audio/wav", "audio/x-wav"}:
        try:
            with wave.open(BytesIO(data), "rb") as stream:
                rate = stream.getframerate()
                frames = stream.getnframes()
                if rate <= 0 or frames / rate > MAX_AUDIO_SECONDS:
                    raise InvalidAttachment("audio duration limit exceeded")
        except (wave.Error, EOFError):
            # Parser failure leaves the encrypted blob opaque; it never triggers
            # preview or decoder execution in this service.
            return
    if mime_type == "audio/mp4":
        _validate_iso_bmff_audio_duration(data)


class MobileAttachmentStore:
    """SQLite metadata plus private UUID-named staging/final attachment files."""

    def __init__(
        self,
        storage_root: str | Path | None = None,
        *,
        root: str | Path | None = None,
        hermes_home: str | Path | None = None,
        db_path: str | Path | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        clock=time.time,
    ) -> None:
        if storage_root is not None and root is not None:
            raise ValueError("storage_root and root are aliases; provide one")
        selected_root = storage_root if storage_root is not None else root
        if selected_root is None:
            selected_root = Path(hermes_home) if hermes_home is not None else get_hermes_home()
            selected_root = Path(selected_root) / "mobile-attachments"
        self.storage_root = Path(selected_root)
        for ancestor in (self.storage_root, *self.storage_root.parents):
            if ancestor.exists() and ancestor.is_symlink():
                raise AttachmentStorageError("attachment storage root must not contain symlinks")
        try:
            self.storage_root.mkdir(parents=True, exist_ok=True)
            self.storage_root = self.storage_root.resolve(strict=True)
            self._make_private(self.storage_root, 0o700)
            self.uploads_root = self.storage_root / "uploads"
            self.attachments_root = self.storage_root / "attachments"
            for directory in (self.uploads_root, self.attachments_root):
                if directory.exists() and directory.is_symlink():
                    raise AttachmentStorageError("attachment storage directory must not be a symlink")
                directory.mkdir(mode=0o700, exist_ok=True)
                self._make_private(directory, 0o700)
        except OSError as exc:
            raise AttachmentStorageError("attachment storage root is unavailable") from exc

        if not isinstance(chunk_size, int) or isinstance(chunk_size, bool) or not 1 <= chunk_size <= MAX_ATTACHMENT_BYTES:
            raise ValueError("chunk_size must be between one byte and the attachment limit")
        self.chunk_size = chunk_size
        self._clock = clock
        self.db_path = Path(db_path) if db_path is not None else self.storage_root / "attachments.sqlite3"
        if self.db_path.exists() and self.db_path.is_symlink():
            raise AttachmentStorageError("attachment database must not be a symlink")
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(
                str(self.db_path),
                isolation_level=None,
                timeout=10.0,
                check_same_thread=False,
            )
        except (OSError, sqlite3.Error) as exc:
            raise AttachmentStorageError("attachment database is unavailable") from exc
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        try:
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
            self._connection.execute("PRAGMA busy_timeout = 10000")
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS mobile_attachment_uploads (
                    upload_id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    conversation_id TEXT NOT NULL,
                    expected_size INTEGER NOT NULL,
                    expected_sha256 TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    chunk_size INTEGER NOT NULL,
                    staging_name TEXT NOT NULL UNIQUE,
                    received_bytes INTEGER NOT NULL DEFAULT 0,
                    next_offset INTEGER NOT NULL DEFAULT 0,
                    state TEXT NOT NULL CHECK (state IN ('uploading', 'completed', 'rejected')),
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    completed_at REAL,
                    attachment_id TEXT UNIQUE
                );
                CREATE INDEX IF NOT EXISTS mobile_attachment_uploads_device_state
                    ON mobile_attachment_uploads (device_id, state);
                CREATE TABLE IF NOT EXISTS mobile_attachments (
                    attachment_id TEXT PRIMARY KEY,
                    upload_id TEXT NOT NULL UNIQUE
                        REFERENCES mobile_attachment_uploads(upload_id) ON DELETE CASCADE,
                    owner_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    conversation_id TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    storage_name TEXT NOT NULL UNIQUE,
                    created_at REAL NOT NULL,
                    completed_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS mobile_attachments_completed
                    ON mobile_attachments (completed_at);
                CREATE TABLE IF NOT EXISTS mobile_message_attachments (
                    owner_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    conversation_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    attachment_id TEXT NOT NULL
                        REFERENCES mobile_attachments(attachment_id) ON DELETE CASCADE,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (owner_id, device_id, conversation_id, message_id, attachment_id)
                );
                CREATE INDEX IF NOT EXISTS mobile_message_attachments_lookup
                    ON mobile_message_attachments (
                        owner_id, device_id, conversation_id, message_id
                    );
                """
            )
            self._make_private(self.db_path, 0o600)
        except sqlite3.Error as exc:
            self._connection.close()
            raise AttachmentStorageError("attachment database could not be initialized") from exc

    @staticmethod
    def _make_private(path: Path, mode: int) -> None:
        if os.name != "nt":
            try:
                os.chmod(path, mode)
            except OSError as exc:
                raise AttachmentStorageError("private attachment permissions could not be set") from exc

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "MobileAttachmentStore":
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()

    def _now(self, value: float | None) -> float:
        current = self._clock() if value is None else value
        if not isinstance(current, (int, float)) or isinstance(current, bool):
            raise ValueError("now must be a finite timestamp")
        current = float(current)
        if not (-62135596800.0 < current < 4102444800.0):
            raise ValueError("now must be a finite timestamp")
        return current

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    @staticmethod
    def _rollback(connection: sqlite3.Connection) -> None:
        if connection.in_transaction:
            connection.rollback()

    def _safe_path(self, directory: Path, name: str) -> Path:
        if not name or Path(name).name != name or name in {".", ".."}:
            raise AttachmentStorageError("invalid private storage name")
        if "/" in name or "\\" in name or any(ord(character) < 0x20 for character in name):
            raise AttachmentStorageError("invalid private storage name")
        if directory.is_symlink():
            raise AttachmentStorageError("private storage directory is a symlink")
        candidate = directory / name
        try:
            resolved = candidate.resolve(strict=False)
            if resolved.parent != directory.resolve(strict=True):
                raise AttachmentStorageError("private storage path escaped its root")
        except OSError as exc:
            raise AttachmentStorageError("private storage path is unavailable") from exc
        if candidate.exists() and candidate.is_symlink():
            raise AttachmentStorageError("private storage object is a symlink")
        return candidate

    @staticmethod
    def _create_empty_file(path: Path) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(path), flags | nofollow, 0o600)
        except OSError as exc:
            raise AttachmentStorageError("private staging file could not be created") from exc
        try:
            os.close(fd)
        except OSError as exc:
            raise AttachmentStorageError("private staging file could not be created") from exc

    @staticmethod
    def _open_private(path: Path, *, writable: bool):
        """Open a generated object without following a symlink on platforms that support it."""

        flags = (os.O_RDWR if writable else os.O_RDONLY) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(str(path), flags)
        except OSError as exc:
            raise AttachmentStorageError("private attachment file is unavailable") from exc
        try:
            return os.fdopen(descriptor, "r+b" if writable else "rb")
        except OSError as exc:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise AttachmentStorageError("private attachment file is unavailable") from exc

    @staticmethod
    def _hash_private_file(path: Path) -> tuple[int, str, bytes]:
        digest = hashlib.sha256()
        total = 0
        sample = bytearray()
        try:
            with MobileAttachmentStore._open_private(path, writable=False) as handle:
                while True:
                    block = handle.read(DEFAULT_CHUNK_SIZE)
                    if not block:
                        break
                    if len(sample) < 4096:
                        sample.extend(block[: 4096 - len(sample)])
                    total += len(block)
                    digest.update(block)
        except OSError as exc:
            raise AttachmentStorageError("private attachment file could not be read") from exc
        return total, digest.hexdigest(), bytes(sample)

    @staticmethod
    def _row_upload(row: sqlite3.Row) -> UploadStatus:
        return UploadStatus(
            upload_id=str(row["upload_id"]),
            owner_id=str(row["owner_id"]),
            device_id=str(row["device_id"]),
            conversation_id=str(row["conversation_id"]),
            expected_size=int(row["expected_size"]),
            expected_sha256=str(row["expected_sha256"]),
            mime_type=str(row["mime_type"]),
            display_name=str(row["display_name"]),
            chunk_size=int(row["chunk_size"]),
            received_bytes=int(row["received_bytes"]),
            next_offset=int(row["next_offset"]),
            state=str(row["state"]),
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
            completed_at=None if row["completed_at"] is None else float(row["completed_at"]),
            attachment_id=None if row["attachment_id"] is None else str(row["attachment_id"]),
        )

    @staticmethod
    def _row_attachment(row: sqlite3.Row) -> AttachmentRecord:
        return AttachmentRecord(
            attachment_id=str(row["attachment_id"]),
            upload_id=str(row["upload_id"]),
            owner_id=str(row["owner_id"]),
            device_id=str(row["device_id"]),
            conversation_id=str(row["conversation_id"]),
            size=int(row["size"]),
            sha256=str(row["sha256"]),
            mime_type=str(row["mime_type"]),
            display_name=str(row["display_name"]),
            created_at=float(row["created_at"]),
            completed_at=float(row["completed_at"]),
        )

    def _get_upload_row(self, upload_id: str) -> sqlite3.Row:
        row = self._connection.execute(
            "SELECT * FROM mobile_attachment_uploads WHERE upload_id = ?",
            (upload_id,),
        ).fetchone()
        if row is None:
            raise AttachmentNotFound("unknown upload")
        return row

    @staticmethod
    def _check_scope(
        row: sqlite3.Row,
        *,
        owner_id: str,
        device_id: str,
        conversation_id: str,
    ) -> None:
        if (
            row["owner_id"] != owner_id
            or row["device_id"] != device_id
            or row["conversation_id"] != conversation_id
        ):
            raise AttachmentOwnershipError("attachment is not owned by this scope")

    def declare_upload(
        self,
        owner_id: str | None = None,
        device_id: str | None = None,
        conversation_id: str | None = None,
        expected_size: int | None = None,
        expected_sha256: str | None = None,
        mime_type: str | None = None,
        display_name: str | None = None,
        *,
        size: int | None = None,
        sha256: str | None = None,
        filename: str | None = None,
        access_subject: str | None = None,
        now: float | None = None,
    ) -> UploadStatus:
        """Declare one upload before any bytes are accepted (the POST primitive)."""

        if size is not None:
            if expected_size != size:
                raise InvalidAttachment("expected_size and size disagree")
            expected_size = size
        if sha256 is not None:
            if expected_sha256 != sha256:
                raise InvalidAttachment("expected_sha256 and sha256 disagree")
            expected_sha256 = sha256
        if filename is not None:
            if display_name is not None and display_name != filename:
                raise InvalidAttachment("display_name and filename disagree")
            display_name = filename
        owner_id = _resolve_owner(owner_id, access_subject)
        device_id = _validate_scope(device_id, "device_id")
        conversation_id = _validate_scope(conversation_id, "conversation_id")
        if not isinstance(expected_size, int) or isinstance(expected_size, bool):
            raise InvalidAttachment("expected_size must be an integer")
        if expected_size <= 0 or expected_size > MAX_ATTACHMENT_BYTES:
            raise InvalidAttachment("attachment size is outside the permitted limit")
        expected_sha256 = _normalize_sha256(expected_sha256)
        mime_type = _normalize_mime(mime_type)
        display_name = sanitize_display_filename(display_name or "attachment")
        timestamp = self._now(now)

        with self._lock:
            self._begin(self._connection)
            created_path: Path | None = None
            try:
                # Reap stale uploads before enforcing quotas so a crashed client cannot
                # permanently consume its device's declaration slots.
                self._cleanup_locked(timestamp, remove_files=True)
                count_row = self._connection.execute(
                    "SELECT COUNT(*) AS count, COALESCE(SUM(expected_size), 0) AS bytes "
                    "FROM mobile_attachment_uploads WHERE device_id = ? AND state = ?",
                    (device_id, _UPLOAD_STATE),
                ).fetchone()
                if int(count_row["count"]) >= MAX_UNFINISHED_UPLOADS_PER_DEVICE:
                    raise AttachmentQuotaExceeded("unfinished upload limit reached")
                if int(count_row["bytes"]) + expected_size > MAX_UNFINISHED_BYTES_PER_DEVICE:
                    raise AttachmentQuotaExceeded("unfinished upload byte quota reached")

                upload_id = str(uuid4())
                staging_name = f"{upload_id}.part"
                created_path = self._safe_path(self.uploads_root, staging_name)
                self._create_empty_file(created_path)
                self._connection.execute(
                    "INSERT INTO mobile_attachment_uploads ("
                    "upload_id, owner_id, device_id, conversation_id, expected_size, "
                    "expected_sha256, mime_type, display_name, chunk_size, staging_name, "
                    "received_bytes, next_offset, state, created_at, updated_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?)",
                    (
                        upload_id,
                        owner_id,
                        device_id,
                        conversation_id,
                        expected_size,
                        expected_sha256,
                        mime_type,
                        display_name,
                        self.chunk_size,
                        staging_name,
                        _UPLOAD_STATE,
                        timestamp,
                        timestamp,
                    ),
                )
                self._connection.commit()
                row = self._get_upload_row(upload_id)
                return self._row_upload(row)
            except Exception:
                self._rollback(self._connection)
                if created_path is not None:
                    try:
                        created_path.unlink(missing_ok=True)
                    except OSError:
                        pass
                raise

    # Names used by route implementations and callers that prefer shorter verbs.
    declare = declare_upload
    create_upload = declare_upload
    post_declare = declare_upload
    begin_upload = declare_upload

    def get_upload(
        self,
        upload_id: str | UUID,
        *,
        owner_id: str | None = None,
        device_id: str | None = None,
        conversation_id: str | None = None,
        access_subject: str | None = None,
    ) -> UploadStatus:
        upload_id = _canonical_uuid(upload_id, "upload_id")
        owner_id = _resolve_owner(owner_id, access_subject)
        device_id = _validate_scope(device_id, "device_id")
        conversation_id = _validate_scope(conversation_id, "conversation_id")
        with self._lock:
            row = self._get_upload_row(upload_id)
            self._check_scope(
                row,
                owner_id=owner_id,
                device_id=device_id,
                conversation_id=conversation_id,
            )
            return self._row_upload(row)

    upload = get_upload

    def upload_chunk(
        self,
        upload_id: str | UUID,
        content_range: str,
        data: bytes,
        *,
        owner_id: str | None = None,
        device_id: str | None = None,
        conversation_id: str | None = None,
        access_subject: str | None = None,
        now: float | None = None,
    ) -> UploadStatus:
        """Append exactly the next fixed-size Content-Range to a declared upload."""

        upload_id = _canonical_uuid(upload_id, "upload_id")
        owner_id = _resolve_owner(owner_id, access_subject)
        device_id = _validate_scope(device_id, "device_id")
        conversation_id = _validate_scope(conversation_id, "conversation_id")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise InvalidChunk("chunk body must be bytes")
        if len(data) > self.chunk_size:
            raise InvalidChunk("chunk body exceeds the fixed chunk size")
        body = bytes(data)
        start, end, total = parse_content_range(content_range)
        timestamp = self._now(now)

        with self._lock:
            self._begin(self._connection)
            try:
                row = self._get_upload_row(upload_id)
                self._check_scope(
                    row,
                    owner_id=owner_id,
                    device_id=device_id,
                    conversation_id=conversation_id,
                )
                if row["state"] != _UPLOAD_STATE:
                    raise InvalidChunk("upload is not accepting chunks")
                chunk_size = int(row["chunk_size"])
                expected_size = int(row["expected_size"])
                next_offset = int(row["next_offset"])
                if total != expected_size:
                    raise InvalidChunk("Content-Range total does not match declaration")
                if start != next_offset or end != start + len(body) - 1:
                    raise InvalidChunk("chunk is not the next ordered range")
                if not body or len(body) > chunk_size or end >= expected_size:
                    raise InvalidChunk("chunk length is outside the fixed chunk contract")
                is_final = end == expected_size - 1
                if not is_final and len(body) != chunk_size:
                    raise InvalidChunk("non-final chunks must use the fixed chunk size")
                path = self._safe_path(self.uploads_root, str(row["staging_name"]))
                if not path.exists() or path.is_symlink():
                    raise AttachmentStorageError("private staging file is unavailable")
                try:
                    with self._open_private(path, writable=True) as handle:
                        handle.seek(next_offset)
                        handle.write(body)
                        handle.flush()
                        os.fsync(handle.fileno())
                except OSError as exc:
                    raise AttachmentStorageError("private staging file could not be written") from exc
                new_offset = end + 1
                self._connection.execute(
                    "UPDATE mobile_attachment_uploads SET received_bytes = ?, next_offset = ?, "
                    "updated_at = ? WHERE upload_id = ? AND state = ?",
                    (new_offset, new_offset, timestamp, upload_id, _UPLOAD_STATE),
                )
                self._connection.commit()
                return self._row_upload(self._get_upload_row(upload_id))
            except Exception:
                self._rollback(self._connection)
                raise

    def put_chunk(
        self,
        upload_id: str | UUID,
        first: str | bytes,
        second: str | bytes,
        **kwargs,
    ) -> UploadStatus:
        """Accept either ``(range, body)`` or ``(body, range)`` route ordering."""

        if isinstance(first, str):
            content_range, data = first, second
        else:
            data, content_range = first, second
        if not isinstance(content_range, str):
            raise InvalidChunk("Content-Range must be a byte range")
        return self.upload_chunk(upload_id, content_range, data, **kwargs)

    append_chunk = put_chunk
    write_chunk = put_chunk

    def finalize_upload(
        self,
        upload_id: str | UUID,
        *,
        owner_id: str | None = None,
        device_id: str | None = None,
        conversation_id: str | None = None,
        access_subject: str | None = None,
        now: float | None = None,
    ) -> AttachmentRecord:
        """Verify and atomically promote a fully uploaded staging file."""

        upload_id = _canonical_uuid(upload_id, "upload_id")
        owner_id = _resolve_owner(owner_id, access_subject)
        device_id = _validate_scope(device_id, "device_id")
        conversation_id = _validate_scope(conversation_id, "conversation_id")
        timestamp = self._now(now)
        final_path: Path | None = None
        renamed = False
        with self._lock:
            self._begin(self._connection)
            try:
                row = self._get_upload_row(upload_id)
                self._check_scope(
                    row,
                    owner_id=owner_id,
                    device_id=device_id,
                    conversation_id=conversation_id,
                )
                if row["state"] == _COMPLETED_STATE:
                    attachment = self._connection.execute(
                        "SELECT * FROM mobile_attachments WHERE attachment_id = ?",
                        (row["attachment_id"],),
                    ).fetchone()
                    if attachment is None:
                        raise AttachmentStorageError("completed attachment metadata is missing")
                    self._connection.rollback()
                    return self._row_attachment(attachment)
                if row["state"] != _UPLOAD_STATE or int(row["next_offset"]) != int(row["expected_size"]):
                    raise InvalidAttachment("upload is incomplete")
                staging_path = self._safe_path(self.uploads_root, str(row["staging_name"]))
                if not staging_path.exists() or staging_path.is_symlink():
                    raise AttachmentStorageError("private staging file is unavailable")
                expected_size = int(row["expected_size"])
                actual_size, actual_sha256, sample = self._hash_private_file(staging_path)
                if actual_size != expected_size or not hmac.compare_digest(
                    actual_sha256, str(row["expected_sha256"])
                ):
                    self._connection.execute(
                        "UPDATE mobile_attachment_uploads SET state = ?, updated_at = ? WHERE upload_id = ?",
                        (_REJECTED_STATE, timestamp, upload_id),
                    )
                    self._connection.commit()
                    try:
                        staging_path.unlink(missing_ok=True)
                    except OSError:
                        pass
                    raise InvalidAttachment("attachment size or hash verification failed")
                if not _mime_matches(sample, str(row["mime_type"])):
                    self._connection.execute(
                        "UPDATE mobile_attachment_uploads SET state = ?, updated_at = ? WHERE upload_id = ?",
                        (_REJECTED_STATE, timestamp, upload_id),
                    )
                    self._connection.commit()
                    try:
                        staging_path.unlink(missing_ok=True)
                    except OSError:
                        pass
                    raise InvalidAttachment("attachment MIME verification failed")
                if str(row["mime_type"]) in {
                    "application/pdf",
                    "image/png",
                    "image/jpeg",
                    "image/jpg",
                    "audio/wav",
                    "audio/x-wav",
                    "audio/mp4",
                }:
                    try:
                        with self._open_private(staging_path, writable=False) as handle:
                            parser_bytes = handle.read(MAX_ATTACHMENT_BYTES + 1)
                    except OSError as exc:
                        raise AttachmentStorageError("attachment parser input unavailable") from exc
                    if len(parser_bytes) > MAX_ATTACHMENT_BYTES:
                        raise InvalidAttachment("attachment is too large")
                    _validate_parser_limits(parser_bytes, str(row["mime_type"]))

                attachment_id = str(uuid4())
                storage_name = f"{attachment_id}.blob"
                final_path = self._safe_path(self.attachments_root, storage_name)
                if final_path.exists() or final_path.is_symlink():
                    raise AttachmentStorageError("private final path already exists")
                try:
                    os.replace(staging_path, final_path)
                    renamed = True
                    self._make_private(final_path, 0o600)
                except OSError as exc:
                    raise AttachmentStorageError("attachment finalization failed") from exc
                self._connection.execute(
                    "INSERT INTO mobile_attachments ("
                    "attachment_id, upload_id, owner_id, device_id, conversation_id, size, sha256, "
                    "mime_type, display_name, storage_name, created_at, completed_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        attachment_id,
                        upload_id,
                        owner_id,
                        device_id,
                        conversation_id,
                        expected_size,
                        str(row["expected_sha256"]),
                        str(row["mime_type"]),
                        str(row["display_name"]),
                        storage_name,
                        timestamp,
                        timestamp,
                    ),
                )
                self._connection.execute(
                    "UPDATE mobile_attachment_uploads SET state = ?, completed_at = ?, "
                    "attachment_id = ?, updated_at = ? WHERE upload_id = ?",
                    (_COMPLETED_STATE, timestamp, attachment_id, timestamp, upload_id),
                )
                self._connection.commit()
                record = self._connection.execute(
                    "SELECT * FROM mobile_attachments WHERE attachment_id = ?",
                    (attachment_id,),
                ).fetchone()
                if record is None:
                    raise AttachmentStorageError("attachment metadata was not committed")
                return self._row_attachment(record)
            except Exception:
                self._rollback(self._connection)
                if renamed and final_path is not None:
                    try:
                        final_path.unlink(missing_ok=True)
                    except OSError:
                        pass
                raise

    complete_upload = finalize_upload
    finalize = finalize_upload

    def get_attachment(
        self,
        attachment_id: str | UUID,
        *,
        owner_id: str | None = None,
        device_id: str | None = None,
        conversation_id: str | None = None,
        access_subject: str | None = None,
    ) -> AttachmentRecord:
        attachment_id = _canonical_uuid(attachment_id, "attachment_id")
        owner_id = _resolve_owner(owner_id, access_subject)
        device_id = _validate_scope(device_id, "device_id")
        conversation_id = _validate_scope(conversation_id, "conversation_id")
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM mobile_attachments WHERE attachment_id = ?",
                (attachment_id,),
            ).fetchone()
            if row is None:
                raise AttachmentNotFound("unknown attachment")
            self._check_scope(
                row,
                owner_id=owner_id,
                device_id=device_id,
                conversation_id=conversation_id,
            )
            return self._row_attachment(row)

    attachment = get_attachment

    def read_attachment(
        self,
        attachment_id: str | UUID,
        *,
        owner_id: str | None = None,
        device_id: str | None = None,
        conversation_id: str | None = None,
        access_subject: str | None = None,
    ) -> bytes:
        """Read bytes through an authorized opaque ID; no filesystem path is exposed."""

        attachment_id = _canonical_uuid(attachment_id, "attachment_id")
        owner_id = _resolve_owner(owner_id, access_subject)
        device_id = _validate_scope(device_id, "device_id")
        conversation_id = _validate_scope(conversation_id, "conversation_id")
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM mobile_attachments WHERE attachment_id = ?",
                (attachment_id,),
            ).fetchone()
            if row is None:
                raise AttachmentNotFound("unknown attachment")
            self._check_scope(
                row,
                owner_id=owner_id,
                device_id=device_id,
                conversation_id=conversation_id,
            )
            path = self._safe_path(self.attachments_root, str(row["storage_name"]))
            if not path.exists() or path.is_symlink():
                raise AttachmentStorageError("private attachment file is unavailable")
            try:
                with self._open_private(path, writable=False) as handle:
                    data = handle.read(MAX_ATTACHMENT_BYTES + 1)
            except OSError as exc:
                raise AttachmentStorageError("private attachment file could not be read") from exc
            if len(data) != int(row["size"]):
                raise AttachmentStorageError("private attachment size changed")
            if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), str(row["sha256"])):
                raise AttachmentStorageError("private attachment digest changed")
            return data

    def attach_to_message(
        self,
        attachment_ids: str | UUID | Sequence[str | UUID],
        *,
        owner_id: str | None = None,
        device_id: str | None = None,
        conversation_id: str | None = None,
        message_id: str | None = None,
        access_subject: str | None = None,
        now: float | None = None,
    ) -> tuple[AttachmentRecord, ...]:
        """Bind up to six completed references to one authorized message."""

        references = validate_attachment_refs(attachment_ids)
        owner_id = _resolve_owner(owner_id, access_subject)
        device_id = _validate_scope(device_id, "device_id")
        conversation_id = _validate_scope(conversation_id, "conversation_id")
        message_id = _validate_scope(message_id, "message_id")
        timestamp = self._now(now)
        with self._lock:
            self._begin(self._connection)
            try:
                existing = self._connection.execute(
                    "SELECT attachment_id FROM mobile_message_attachments "
                    "WHERE owner_id = ? AND device_id = ? AND conversation_id = ? AND message_id = ?",
                    (owner_id, device_id, conversation_id, message_id),
                ).fetchall()
                existing_ids = {str(row["attachment_id"]) for row in existing}
                if len(existing_ids | set(references)) > MAX_ATTACHMENT_REFS_PER_MESSAGE:
                    raise AttachmentQuotaExceeded("a message may reference at most six attachments")
                records: list[AttachmentRecord] = []
                for reference in references:
                    row = self._connection.execute(
                        "SELECT * FROM mobile_attachments WHERE attachment_id = ?",
                        (reference,),
                    ).fetchone()
                    if row is None:
                        raise AttachmentNotFound("unknown attachment")
                    self._check_scope(
                        row,
                        owner_id=owner_id,
                        device_id=device_id,
                        conversation_id=conversation_id,
                    )
                    self._connection.execute(
                        "INSERT OR IGNORE INTO mobile_message_attachments ("
                        "owner_id, device_id, conversation_id, message_id, attachment_id, created_at"
                        ") VALUES (?, ?, ?, ?, ?, ?)",
                        (owner_id, device_id, conversation_id, message_id, reference, timestamp),
                    )
                    records.append(self._row_attachment(row))
                self._connection.commit()
                return tuple(records)
            except Exception:
                self._rollback(self._connection)
                raise

    attach = attach_to_message

    def detach_from_message(
        self,
        attachment_ids: str | UUID | Sequence[str | UUID],
        *,
        owner_id: str | None = None,
        device_id: str | None = None,
        conversation_id: str | None = None,
        message_id: str | None = None,
        access_subject: str | None = None,
    ) -> int:
        references = validate_attachment_refs(attachment_ids)
        owner_id = _resolve_owner(owner_id, access_subject)
        device_id = _validate_scope(device_id, "device_id")
        conversation_id = _validate_scope(conversation_id, "conversation_id")
        message_id = _validate_scope(message_id, "message_id")
        with self._lock:
            self._begin(self._connection)
            try:
                placeholders = ",".join("?" for _ in references) or "NULL"
                cursor = self._connection.execute(
                    "DELETE FROM mobile_message_attachments WHERE owner_id = ? AND device_id = ? "
                    "AND conversation_id = ? AND message_id = ? AND attachment_id IN (" + placeholders + ")",
                    (owner_id, device_id, conversation_id, message_id, *references),
                )
                self._connection.commit()
                return int(cursor.rowcount)
            except Exception:
                self._rollback(self._connection)
                raise

    def _cleanup_locked(self, timestamp: float, *, remove_files: bool) -> CleanupResult:
        cutoff_upload = timestamp - UPLOAD_ABANDONED_AFTER_SECONDS
        cutoff_completed = timestamp - COMPLETED_UNATTACHED_AFTER_SECONDS
        stale_uploads = self._connection.execute(
            "SELECT upload_id, staging_name, expected_size FROM mobile_attachment_uploads "
            "WHERE state = ? AND updated_at <= ?",
            (_UPLOAD_STATE, cutoff_upload),
        ).fetchall()
        old_attachments = self._connection.execute(
            "SELECT a.attachment_id, a.storage_name, a.size FROM mobile_attachments AS a "
            "WHERE a.completed_at <= ? AND NOT EXISTS ("
            "SELECT 1 FROM mobile_message_attachments AS m WHERE m.attachment_id = a.attachment_id"
            ")",
            (cutoff_completed,),
        ).fetchall()
        stale_paths = [self._safe_path(self.uploads_root, str(row["staging_name"])) for row in stale_uploads]
        old_paths = [self._safe_path(self.attachments_root, str(row["storage_name"])) for row in old_attachments]
        stale_bytes = sum(int(row["expected_size"]) for row in stale_uploads)
        old_bytes = sum(int(row["size"]) for row in old_attachments)
        if old_attachments:
            self._connection.executemany(
                "DELETE FROM mobile_attachments WHERE attachment_id = ?",
                [(str(row["attachment_id"]),) for row in old_attachments],
            )
        if stale_uploads:
            self._connection.executemany(
                "DELETE FROM mobile_attachment_uploads WHERE upload_id = ?",
                [(str(row["upload_id"]),) for row in stale_uploads],
            )
        if remove_files:
            for path in (*stale_paths, *old_paths):
                try:
                    if path.is_symlink():
                        path.unlink(missing_ok=True)
                    else:
                        path.unlink(missing_ok=True)
                except OSError as exc:
                    raise AttachmentStorageError("private attachment cleanup failed") from exc
        return CleanupResult(
            unfinished_uploads=len(stale_uploads),
            completed_attachments=len(old_attachments),
            bytes_reclaimed=stale_bytes + old_bytes,
        )

    def cleanup(self, *, now: float | None = None) -> CleanupResult:
        timestamp = self._now(now)
        with self._lock:
            self._begin(self._connection)
            try:
                result = self._cleanup_locked(timestamp, remove_files=True)
                self._connection.commit()
                return result
            except Exception:
                self._rollback(self._connection)
                raise

    reap = cleanup
    cleanup_abandoned = cleanup

    validate_attachment_refs = staticmethod(validate_attachment_refs)
    validate_message_attachment_refs = staticmethod(validate_message_attachment_refs)


# Compatibility spellings are assigned after the class exists so static analyzers still see
# the actual implementation above rather than a forward declaration.
MobileAttachmentStore = MobileAttachmentStore
ResumableAttachmentStore = MobileAttachmentStore
AttachmentStore = MobileAttachmentStore
AttachmentRegistry = MobileAttachmentStore


__all__ = [
    "AttachmentNotFound",
    "AttachmentOwnershipError",
    "AttachmentQuotaExceeded",
    "AttachmentRecord",
    "AttachmentRegistry",
    "AttachmentStorageError",
    "AttachmentStore",
    "AttachmentUpload",
    "CHUNK_SIZE",
    "CleanupResult",
    "COMPLETED_UNATTACHED_AFTER_SECONDS",
    "DEFAULT_CHUNK_SIZE",
    "InvalidAttachment",
    "InvalidChunk",
    "MAX_ATTACHMENT_BYTES",
    "MAX_ATTACHMENT_REFS_PER_MESSAGE",
    "MAX_AUDIO_SECONDS",
    "MAX_IMAGE_PIXELS",
    "MAX_PDF_PAGES",
    "MAX_UNFINISHED_BYTES_PER_DEVICE",
    "MAX_UNFINISHED_UPLOADS_PER_DEVICE",
    "MobileAttachment",
    "MobileAttachmentError",
    "MobileAttachmentStore",
    "ResumableAttachmentStore",
    "UPLOAD_ABANDONED_AFTER_SECONDS",
    "UploadStatus",
    "parse_content_range",
    "sanitize_display_filename",
    "validate_attachment_refs",
    "validate_message_attachment_refs",
]
