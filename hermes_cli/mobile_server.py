"""Isolated mobile-only ASGI application.

This module intentionally owns its own FastAPI application.  It must not import
``hermes_cli.web_server`` or any dashboard/JSON-RPC router; the route table is a
security boundary, not a filtered view of the dashboard application.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import inspect
import asyncio
import hashlib
import logging
import math
import secrets
from collections.abc import Awaitable, Callable
from contextlib import contextmanager
from dataclasses import dataclass
import socket
import threading
import time
from typing import Any, Literal, Sequence
import json
from uuid import UUID

from fastapi import Body, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse
import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from hermes_cli.mobile_attachments import (
    AttachmentNotFound,
    AttachmentOwnershipError,
    AttachmentQuotaExceeded,
    AttachmentStorageError,
    InvalidAttachment,
    InvalidChunk,
    MobileAttachmentError,
    MobileAttachmentStore,
)
from hermes_cli.mobile_auth import AccessIdentity
from hermes_cli.mobile_chat import ConversationNotFound, MobileChatService
from hermes_cli.mobile_approvals import (
    ApprovalAlreadyResolved,
    ApprovalConflict,
    ApprovalContext,
    ApprovalError,
    ApprovalExpired,
    ApprovalNotFound,
    MobileApprovalStore,
    step_up_context as approval_step_up_context,
)
from hermes_cli.mobile_catalog import CatalogError, CatalogNotFound, MobileCatalog
from hermes_cli.mobile_group_execution import MobileGroupExecutionService
from hermes_cli.mobile_groups import (
    BotSelection,
    CrossInstanceGroupUnsupported,
    GroupBusy,
    GroupCapExceeded,
    GroupNotFound,
    GroupRevisionConflict,
    GroupStopped,
    ExecutionFenceLost,
    LeaseExpired,
    MemberNotFound,
    MobileGroupError,
    MobileGroupCoordinator,
    TurnIndeterminate,
    TurnNotFound,
)
from hermes_cli.mobile_devices import (
    DeviceNotAuthorized,
    InvalidEnrollment,
    MobileDeviceError,
    MobileDeviceStore,
)
from hermes_cli.mobile_event_store import (
    CursorExpired,
    EventInput,
    IdempotencyConflict,
    MobileEventStore,
    MobileEventStoreError,
    MutationResult,
    MutationStatus,
)
from hermes_cli.mobile_models import BotId
from hermes_cli.mobile_objects import MobileObjectRegistry
from hermes_cli.mobile_push import MobilePushEvent, MobilePushRelayClient
from hermes_cli.mobile_request_auth import MobileRequestAuthorizer, MobileRequestIdentity
from hermes_cli.mobile_routines import (
    MobileRoutineService,
    RoutineAlreadyRunning,
    RoutineConflict,
    RoutineError,
    RoutineNotFound,
    RoutineStepUpRequired,
)
from hermes_cli.mobile_routine_worker import MobileRoutineWorker, RoutineWorkerUnavailable
from hermes_cli.mobile_settings import (
    MobileSettingsStore,
    SettingsConflict,
    SettingsError,
    SettingsNotFound,
    StepUpRequired,
    rollback_step_up_context,
    step_up_context as settings_step_up_context,
)
from hermes_cli.mobile_step_up import MobileStepUpStore, StepUpChallenge


Authorizer = Callable[[Request], Any | Awaitable[Any]]
_LOGGER = logging.getLogger(__name__)
_ATTACHMENT_CLEANUP_JOIN_TIMEOUT_SECONDS = 1.0
_ATTACHMENT_CLEANUP_INTERVAL_SECONDS = 15 * 60.0
_MAX_ROUTINE_INPUT_BYTES = 256_000
_GROUP_LIST_PAGE_SIZE = 100
_GROUP_CURSOR_MAX_LENGTH = 1024


def _group_cursor_key(instance_id: str, secret: bytes | None = None) -> bytes:
    """Derive the installation-bound integrity key for group cursors.

    The live listener supplies bytes derived from its persisted device-token signing key.  The
    deterministic instance-ID fallback is retained for small dependency-free contract fixtures
    that construct the app without the full startup wiring; it is context binding only and is not
    used by production startup.  A cursor never grants access by itself—the owner/device
    predicates are still applied by the coordinator.
    """

    if secret is None:
        secret = f"hermes-mobile-group-cursor:{instance_id}".encode("utf-8")
    elif not isinstance(secret, bytes) or not secret:
        raise ValueError("group cursor secret is invalid")
    return hashlib.sha256(b"hermes-mobile-group-cursor:" + secret).digest()


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
        for character in value
    ):
        raise ValueError("invalid group cursor")
    try:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value + padding)
    except (binascii.Error, TypeError, ValueError) as exc:
        raise ValueError("invalid group cursor") from exc


def _encode_group_cursor(
    *,
    key: bytes,
    instance_id: str,
    owner_id: str,
    device_id: str,
    created_at: float,
    group_id: str,
) -> str:
    if not isinstance(created_at, (int, float)) or isinstance(created_at, bool) or not math.isfinite(
        float(created_at)
    ):
        raise ValueError("invalid group cursor timestamp")
    try:
        UUID(group_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid group cursor group") from exc
    payload = json.dumps(
        {
            "v": 1,
            "i": instance_id,
            "o": owner_id,
            "d": device_id,
            "c": float(created_at),
            "g": group_id,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    encoded = _b64url_encode(payload)
    signature = _b64url_encode(hmac.new(key, payload, hashlib.sha256).digest())
    result = f"{encoded}.{signature}"
    if len(result) > _GROUP_CURSOR_MAX_LENGTH:
        raise ValueError("group cursor is too long")
    return result


def _decode_group_cursor(
    value: str | None,
    *,
    key: bytes,
    instance_id: str,
    owner_id: str,
    device_id: str,
) -> tuple[float, str] | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > _GROUP_CURSOR_MAX_LENGTH or value.count(".") != 1:
        raise ValueError("invalid group cursor")
    encoded, encoded_signature = value.split(".", 1)
    payload = _b64url_decode(encoded)
    signature = _b64url_decode(encoded_signature)
    expected = hmac.new(key, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("invalid group cursor")
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid group cursor") from exc
    if not isinstance(decoded, dict) or set(decoded) != {"v", "i", "o", "d", "c", "g"}:
        raise ValueError("invalid group cursor")
    if (
        decoded.get("v") != 1
        or decoded.get("i") != instance_id
        or decoded.get("o") != owner_id
        or decoded.get("d") != device_id
        or not isinstance(decoded.get("c"), (int, float))
        or isinstance(decoded.get("c"), bool)
        or not math.isfinite(float(decoded["c"]))
        or not isinstance(decoded.get("g"), str)
    ):
        raise ValueError("invalid group cursor")
    try:
        group_id = str(UUID(decoded["g"]))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid group cursor") from exc
    return float(decoded["c"]), group_id


class MobileCapabilities(BaseModel):
    """Versioned description of the mobile surface available on this host."""

    model_config = ConfigDict(extra="forbid")

    api_version: Literal["v1"] = "v1"
    features: tuple[str, ...] = ()


class DeviceEnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_label: str = Field(min_length=1, max_length=64)
    background_jwk: dict[str, str]
    user_presence_jwk: dict[str, str]


class DeviceEnrollmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str
    enrollment_code: str
    expires_at: float


class DeviceTokenChallengeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nonce: str
    expires_at: float


class DeviceTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nonce: str = Field(min_length=16, max_length=512)
    signature: str = Field(min_length=16, max_length=512)


class DeviceTokenResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_token: str
    token_type: Literal["DPoP"] = "DPoP"
    expires_in: Literal[300] = 300


class MobileDeviceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str
    label: str
    status: Literal["pending", "approved", "revoked"]
    profiles: tuple[BotId, ...]
    scopes: tuple[str, ...]
    created_at: float
    approved_at: float | None = None
    revoked_at: float | None = None


class MobileDevicesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    devices: tuple[MobileDeviceResponse, ...]


class SyncEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cursor: int
    event_id: str
    event_type: str
    aggregate_type: str
    aggregate_id: str
    payload: dict[str, Any]
    created_at: float
    tombstone: bool


class SyncResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instance_id: str
    after_cursor: int
    next_cursor: int
    latest_cursor: int
    retained_floor: int
    has_more: bool
    snapshot_required: bool = False
    events: tuple[SyncEventResponse, ...]


class MobileProfileResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bot: BotId
    label: str


class MobileProfilesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profiles: tuple[MobileProfileResponse, ...]


class PushRegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fcm_token: str = Field(min_length=32, max_length=4096)


class ConversationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    conversation_id: UUID
    canonical: bool
    title: str
    revision: int
    updated_at: float


class ConversationsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    conversations: tuple[ConversationResponse, ...]


class ConversationMessageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message_id: UUID
    conversation_id: UUID
    role: Literal["user", "assistant", "tool"]
    parts: tuple[dict[str, Any], ...]
    created_at: float


class ConversationHistoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    messages: tuple[ConversationMessageResponse, ...]


class ChatSendRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=200_000)
    attachment_ids: tuple[UUID, ...] = Field(default=(), max_length=6)


class ChatSendResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: UUID
    state: Literal["completed"]
    text: str


class DirectRunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: UUID
    conversation_id: UUID
    state: Literal["queued", "thinking", "completed", "failed", "cancelled", "indeterminate"]
    text: str | None = None
    error: str | None = None
    created_at: float
    updated_at: float
    cancel_requested: bool = False
    completed_external_side_effects_not_undone: bool = False


class DirectMessageStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_state: Literal["run_found", "unknown"]
    run: DirectRunResponse | None = None


class DirectRunEventsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: tuple[dict[str, Any], ...]


class AttachmentDeclarationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bot: BotId
    conversation_id: UUID
    filename: str = Field(min_length=1, max_length=512)
    size: int = Field(gt=0, le=25 * 1024 * 1024)
    mime_type: str = Field(min_length=3, max_length=128)
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")


class AttachmentCompletionRequest(BaseModel):
    """Optional client echo for the declared size and digest.

    Older Android builds completed an upload with an empty body.  The body is
    therefore optional at the HTTP boundary, but when present it is bound into
    the idempotency record and checked against the server-owned declaration.
    The server still hashes the private staging file during finalization.
    """

    model_config = ConfigDict(extra="forbid")

    total_bytes: int = Field(gt=0, le=25 * 1024 * 1024)
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")


class AttachmentUploadResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    upload_id: UUID
    chunk_size: int
    received_bytes: int
    next_offset: int
    state: Literal["uploading", "completed"]


class AttachmentCompleteResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attachment_id: UUID
    size: int
    sha256: str
    mime_type: str
    filename: str


class NewConversationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    canonical: bool = True


class GroupCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bots: tuple[BotId, ...] = Field(min_length=2, max_length=6)


class GroupMemberResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    member_id: UUID
    bot: BotId
    label: str
    ordinal: int = Field(ge=0, le=5)


class GroupResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group_id: UUID
    instance_id: UUID
    members: tuple[GroupMemberResponse, ...]
    coordinator_member_id: UUID
    state: Literal["active", "stopped"]
    authority_epoch: int = Field(ge=1)
    active_turn_id: UUID | None = None


class GroupListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    groups: tuple[GroupResponse, ...] = ()
    has_more: bool = False
    next_cursor: str | None = None


class GroupMemberAddRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bot: BotId


class GroupMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=200_000)
    mentioned_member_ids: tuple[UUID, ...] = Field(default=(), max_length=6)


class GroupMessageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: UUID
    state: Literal["completed", "cancelled", "indeterminate"]
    responses: tuple[dict[str, Any], ...]


class GroupRunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: UUID
    group_id: UUID
    state: Literal["active", "completed", "cancelled", "indeterminate"]
    response_count: int = Field(ge=0)
    cancel_requested: bool
    completed_external_side_effects_not_undone: bool


class GroupEventsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: tuple[dict[str, Any], ...]


class StepUpChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=1, max_length=128)
    context: dict[str, Any]


class StepUpChallengeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: UUID
    action: str
    context_digest: str
    nonce: str
    expires_at: float


class StepUpProofRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: UUID
    action: str = Field(min_length=1, max_length=128)
    context_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    nonce: str = Field(min_length=16, max_length=512)
    expires_at: float
    signature: str = Field(min_length=16, max_length=512)


class SettingsUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    changes: dict[str, Any]


class SensitiveSettingsUpdateRequest(SettingsUpdateRequest):
    step_up: StepUpProofRequest


class SettingsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile_id: UUID
    revision: int
    etag: str
    display_name: str
    title: str
    avatar: str
    notification_preferences: dict[str, Any]
    privacy_preferences: dict[str, Any]
    approval_policy: dict[str, str]
    persona: str = ""
    model: str = ""
    provider: str = ""
    reasoning: str = ""
    skills: tuple[str, ...] = ()


class CatalogResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revision: int
    etag: str
    entries: tuple[dict[str, Any], ...]


class RoutineResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    routine_id: UUID
    label: str
    summary: str
    paused: bool
    revision: int
    etag: str


class RoutineListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    routines: tuple[RoutineResponse, ...]


class RoutineRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input: Any = None
    step_up: StepUpProofRequest

    @field_validator("input")
    @classmethod
    def validate_input(cls, value: Any) -> Any:
        try:
            encoded = json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("routine input must be valid JSON data") from exc
        if len(encoded.encode("utf-8")) > _MAX_ROUTINE_INPUT_BYTES:
            raise ValueError("routine input is too large")
        return value


class RoutineRunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: UUID
    routine_id: UUID
    state: Literal["pending", "completed", "failed", "indeterminate", "cancelled"]
    result: Any | None = None


class RoutinePauseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    paused: bool


class ApprovalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: UUID
    summary: str
    status: Literal["pending", "approved", "denied", "consumed", "expired"]
    expires_at: float
    run_id: str
    request_id: str
    tool_call_id: str


class ApprovalsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approvals: tuple[ApprovalResponse, ...]


@dataclass
class RunningMobileListener:
    """Handle for a mobile Uvicorn server owned by the main serve process."""

    host: str
    port: int
    _server: Any
    _thread: threading.Thread
    _socket: socket.socket
    _attachment_cleanup_thread: threading.Thread | None = None
    _attachment_cleanup_stop: threading.Event | None = None
    _routine_worker: MobileRoutineWorker | None = None

    def close(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            self._server.force_exit = True
            self._thread.join(timeout=1)
        self._socket.close()
        if self._attachment_cleanup_stop is not None:
            self._attachment_cleanup_stop.set()
        if self._attachment_cleanup_thread is not None:
            self._attachment_cleanup_thread.join(timeout=_ATTACHMENT_CLEANUP_JOIN_TIMEOUT_SECONDS)
            if self._attachment_cleanup_thread.is_alive():
                _LOGGER.warning("Mobile attachment cleanup did not finish before listener shutdown")
        if self._routine_worker is not None:
            # A worker owns queued and in-flight external side effects.  Fence
            # them before the listener context releases its injected service.
            self._routine_worker.close()


def _run_mobile_attachment_cleanup(
    attachments: MobileAttachmentStore,
    stop_event: threading.Event,
) -> None:
    """Best-effort periodic retention sweeps for the listener lifecycle.

    Cleanup is deliberately isolated from Uvicorn's event loop and request
    path. The store owns the retention policy and private-path checks; this
    hook only invokes that existing bounded operation and keeps a storage
    failure from taking down an otherwise healthy listener. A first sweep is
    immediate, then later sweeps keep the one-hour/24-hour retention bounds
    effective while a long-lived listener remains up.
    """

    while not stop_event.is_set():
        try:
            attachments.cleanup()
        except Exception as exc:  # pragma: no cover - exercised through the lifecycle test
            # Do not include exception text: storage/database errors can contain
            # local paths or deployment details. The exception class is enough for
            # operator diagnostics while keeping attachment metadata out of logs.
            _LOGGER.warning("Mobile attachment cleanup failed (%s)", type(exc).__name__)
        if stop_event.wait(_ATTACHMENT_CLEANUP_INTERVAL_SECONDS):
            return


def create_mobile_app(
    *,
    authorize: Authorizer | None = None,
    sync_authorize: Authorizer | None = None,
    profiles_authorize: Authorizer | None = None,
    events_authorize: Authorizer | None = None,
    push_authorize: Authorizer | None = None,
    access_authorize: Authorizer | None = None,
    devices: MobileDeviceStore | None = None,
    events: MobileEventStore | None = None,
    objects: MobileObjectRegistry | None = None,
    allowed_profiles: tuple[str, ...] = (),
    profile_liveness: Callable[[str], bool] | None = None,
    sse_heartbeat_seconds: float = 15.0,
    sse_max_lifetime_seconds: float = 300.0,
    push_relay: MobilePushRelayClient | None = None,
    request_authorizer: MobileRequestAuthorizer | None = None,
    chat: MobileChatService | None = None,
    attachments: MobileAttachmentStore | None = None,
    groups: MobileGroupCoordinator | None = None,
    group_execution: MobileGroupExecutionService | None = None,
    settings: MobileSettingsStore | None = None,
    approvals: MobileApprovalStore | None = None,
    catalog: MobileCatalog | None = None,
    routines: MobileRoutineService | None = None,
    routine_worker: MobileRoutineWorker | None = None,
    cursor_secret: bytes | None = None,
    step_up: MobileStepUpStore | None = None,
) -> FastAPI:
    """Build the mobile app with an injected, fail-closed request authorizer."""

    app = FastAPI(
        title="Hermes Mobile API",
        version="1",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    async def require_mobile_auth(request: Request) -> None:
        if authorize is None:
            raise HTTPException(status_code=401, detail="mobile authentication required")
        result: Any = authorize(request)
        if inspect.isawaitable(result):
            await result

    async def require_sync_auth(request: Request) -> MobileRequestIdentity | None:
        if sync_authorize is None:
            raise HTTPException(status_code=401, detail="mobile authentication required")
        result: Any = sync_authorize(request)
        if inspect.isawaitable(result):
            result = await result
        # A few narrow compatibility tests use a legacy authorizer that only
        # proves the route is protected and returns None.  Production startup
        # injects the composed authorizer and therefore always returns an
        # identity, which is required before a profile-scoped stream is used.
        if result is not None and not isinstance(result, MobileRequestIdentity):
            raise HTTPException(status_code=401, detail="mobile authentication required")
        return result

    async def require_profiles_auth(request: Request) -> MobileRequestIdentity:
        if profiles_authorize is None:
            raise HTTPException(status_code=401, detail="mobile authentication required")
        result: Any = profiles_authorize(request)
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, MobileRequestIdentity):
            raise HTTPException(status_code=401, detail="mobile authentication required")
        return result

    async def require_events_auth(request: Request) -> MobileRequestIdentity:
        if events_authorize is None:
            raise HTTPException(status_code=401, detail="mobile authentication required")
        result: Any = events_authorize(request)
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, MobileRequestIdentity):
            raise HTTPException(status_code=401, detail="mobile authentication required")
        return result

    async def require_push_auth(request: Request, device_id: str) -> MobileRequestIdentity:
        if push_authorize is None:
            raise HTTPException(status_code=401, detail="mobile authentication required")
        result: Any = push_authorize(request)
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, MobileRequestIdentity):
            raise HTTPException(status_code=401, detail="mobile authentication required")
        if not secrets.compare_digest(result.device.device_id, device_id):
            raise HTTPException(status_code=404, detail="mobile device not found")
        return result

    def reconcile_live_profiles() -> tuple[str, ...]:
        """Reconcile opaque bindings against the host's live profile directories.

        The callback is injected only by production startup; contract tests and embedders that
        construct the isolated app with synthetic profile names retain their existing behavior.
        Reconciliation is delete-only, so a host rename/delete invalidates the old opaque ID
        instead of silently redirecting it to another profile.
        """

        names = tuple(allowed_profiles)
        if profile_liveness is None or objects is None:
            return names
        live: list[str] = []
        for profile_name in names:
            try:
                if profile_liveness(profile_name):
                    live.append(profile_name)
            except Exception:
                # A failed host liveness probe is fail-closed for the affected profile.  Do not
                # disclose the exception or leave its stale opaque binding usable.
                continue
        objects.reconcile_profiles(tuple(live))
        return tuple(live)

    def profile_is_live(profile_name: Any) -> bool:
        """Return whether a stored internal profile name still maps to a live host object."""

        if profile_liveness is None:
            return isinstance(profile_name, str) and bool(profile_name)
        if not isinstance(profile_name, str) or not profile_name:
            return False
        return profile_name in set(reconcile_live_profiles())

    async def resolve_profile_auth(
        request: Request,
        opaque_profile_id: UUID,
        *,
        scope: str,
        charge_profile: bool = True,
    ) -> tuple[MobileRequestIdentity, str]:
        if request_authorizer is None or objects is None:
            raise HTTPException(status_code=401, detail="mobile authentication required")
        identity = request_authorizer.authorize(request, scope=scope)
        # Do not let an unauthenticated request trigger host filesystem probes or registry
        # cleanup; authenticate first, then reconcile the profile principal it may use.
        live_profiles = reconcile_live_profiles() if profile_liveness is not None else None
        token_profiles = identity.device.token_claims.get("profiles", [])
        allowed_profile_names = (
            set(token_profiles)
            if live_profiles is None
            else set(token_profiles) & set(live_profiles)
        )
        try:
            profile_name = objects.resolve_profile(opaque_profile_id, allowed_profile_names)
        except (KeyError, TypeError) as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        # The composed production authorizer charges user/device buckets before
        # this object lookup.  Charge the opaque profile only after the lookup
        # succeeds so foreign IDs cannot mint profile principals.  Small
        # compatibility authorizers used by route contract tests predate this
        # optional hook and intentionally remain user/device-only.
        if charge_profile:
            charge_profile_rate_limit(request, identity, opaque_profile_id)
        return identity, profile_name

    def charge_profile_rate_limit(
        request: Request,
        identity: MobileRequestIdentity,
        opaque_profile_id: UUID | str,
    ) -> None:
        """Charge the profile bucket only after its opaque ID was authorized.

        The production authorizer charges user/device buckets while authenticating.  Profile
        IDs are resolved by this module because the device token stores server-side profile
        names while the mobile API exposes opaque UUIDs.  Keeping the optional hook here also
        preserves the small legacy authorizers used by route contract tests.
        """

        profile_rate_limiter = getattr(request_authorizer, "rate_limit_profile", None)
        if callable(profile_rate_limiter):
            profile_rate_limiter(request, identity, profile=str(opaque_profile_id))

    def profile_marker_for_name(profile_name: Any) -> str | None:
        """Map an authorized server profile name back to its opaque API marker."""

        if objects is None or not profile_is_live(profile_name):
            return None
        try:
            return str(objects.binding_for_profile(profile_name).opaque_profile_id)
        except (KeyError, TypeError, ValueError):
            # A stale mapping must not disclose an internal profile name or invent a
            # profile principal.  The enclosing object lookup remains authoritative.
            return None

    def resolve_sync_profile(
        identity: MobileRequestIdentity | None,
        *,
        instance_id: UUID | None,
        opaque_profile_id: UUID | None,
    ) -> UUID | None:
        """Validate the profile scope used by durable sync and SSE.

        The test-only app can still exercise the event store with its legacy
        route authorizer when no object registry is injected.  A real mobile
        listener always has an object registry, so it must receive both opaque
        coordinates and a composed identity before any event is considered.
        """

        if objects is None:
            return None
        if identity is None or instance_id is None or opaque_profile_id is None:
            raise HTTPException(status_code=401, detail="mobile authentication required")
        if instance_id != objects.instance_id:
            raise HTTPException(status_code=404, detail="mobile object not found")
        live_profiles = reconcile_live_profiles() if profile_liveness is not None else None
        token_profiles = set(identity.device.token_claims.get("profiles", []))
        allowed_profiles = (
            token_profiles
            if live_profiles is None
            else token_profiles & set(live_profiles)
        )
        try:
            objects.resolve_profile(
                opaque_profile_id,
                allowed_profiles,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        return opaque_profile_id

    def event_visible_for_profile(event: Any, opaque_profile_id: UUID | None) -> bool:
        """Return whether an event is explicitly scoped to this profile.

        Events are deliberately deny-by-default when the persistent object
        registry is active.  This prevents a newly added event type from
        accidentally turning the global event log into a cross-profile data
        channel.  The route-specific writers attach opaque profile markers;
        device/global events remain available through their dedicated APIs.
        """

        if objects is None:
            return True
        if opaque_profile_id is None:
            return False
        marker = str(opaque_profile_id)
        payload = dict(getattr(event, "payload", {}) or {})
        for key in ("profile_id", "opaque_profile_id", "profile"):
            if str(payload.get(key, "")) == marker:
                return True
        for key in ("profile_ids", "profiles"):
            values = payload.get(key)
            if isinstance(values, (list, tuple, set)) and marker in {str(value) for value in values}:
                return True
        return False

    async def require_access_auth(request: Request) -> AccessIdentity:
        if access_authorize is None or devices is None:
            raise HTTPException(status_code=401, detail="mobile authentication required")
        result: Any = access_authorize(request)
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, AccessIdentity):
            raise HTTPException(status_code=401, detail="mobile authentication required")
        return result

    async def require_device_owner(request: Request, device_id: str) -> AccessIdentity:
        identity = await require_access_auth(request)
        try:
            record = devices.get_device(device_id)
        except MobileDeviceError as exc:
            raise HTTPException(status_code=401, detail="mobile authentication required") from exc
        if record.access_subject != identity.subject:
            raise HTTPException(status_code=401, detail="mobile authentication required")
        return identity

    async def resolve_attachment_auth(
        request: Request,
        *,
        instance_id: UUID,
        opaque_profile_id: UUID,
        conversation_id: UUID,
    ) -> tuple[MobileRequestIdentity, str]:
        if objects is None or chat is None or str(instance_id) != str(objects.instance_id):
            raise HTTPException(status_code=404, detail="mobile object not found")
        identity, profile_name = await resolve_profile_auth(
            request,
            opaque_profile_id,
            scope="attachments",
            charge_profile=False,
        )
        try:
            chat.assert_conversation(profile_name, conversation_id)
        except ConversationNotFound as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        charge_profile_rate_limit(request, identity, opaque_profile_id)
        return identity, profile_name

    def visible_group(request: Request, identity: MobileRequestIdentity, group_id: UUID) -> Any:
        """Resolve a group only after its owner, device, and current profile grant match."""

        if groups is None or objects is None:
            raise HTTPException(status_code=503, detail="mobile group service unavailable")
        live_profiles = set(reconcile_live_profiles()) if profile_liveness is not None else None
        try:
            snapshot = groups.get_group(
                str(group_id),
                owner_id=identity.access.subject,
                device_id=identity.device.device_id,
            )
            token_profiles = set(identity.device.token_claims.get("profiles", []))
            opaque_profile_ids: list[str] = []
            for member in snapshot.members:
                # Stored group profile IDs are server-internal names.  They are
                # accepted only if the current device grant still contains them.
                if member.bot_id.profile_id not in token_profiles or (
                    live_profiles is not None and member.bot_id.profile_id not in live_profiles
                ):
                    raise GroupNotFound("group does not exist")
                opaque_profile_ids.append(
                    str(objects.binding_for_profile(member.bot_id.profile_id).opaque_profile_id)
                )
        except (MobileGroupError, KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        for opaque_profile_id in opaque_profile_ids:
            charge_profile_rate_limit(request, identity, opaque_profile_id)
        return identity, snapshot

    async def resolve_group_auth(
        request: Request,
        group_id: UUID,
    ) -> tuple[MobileRequestIdentity, Any]:
        """Authorize a group against both the device owner and its member scope."""

        if request_authorizer is None:
            raise HTTPException(status_code=503, detail="mobile group service unavailable")
        try:
            identity = request_authorizer.authorize(request, scope="groups")
        except HTTPException:
            raise
        return visible_group(request, identity, group_id)

    def group_response(snapshot: Any) -> GroupResponse:
        if objects is None:
            raise HTTPException(status_code=503, detail="mobile group service unavailable")
        members: list[GroupMemberResponse] = []
        try:
            for member in snapshot.members:
                binding = objects.binding_for_profile(member.bot_id.profile_id)
                members.append(
                    GroupMemberResponse(
                        member_id=UUID(member.member_id),
                        bot=BotId(
                            instance_id=binding.instance_id,
                            opaque_profile_id=binding.opaque_profile_id,
                        ),
                        label=f"Hermes bot {member.ordinal + 1}",
                        ordinal=member.ordinal,
                    )
                )
            return GroupResponse(
                group_id=UUID(snapshot.group_id),
                instance_id=UUID(snapshot.instance_id),
                members=tuple(members),
                coordinator_member_id=UUID(snapshot.coordinator_member_id),
                state=snapshot.state.value,
                authority_epoch=snapshot.authority_epoch,
                active_turn_id=(
                    None if snapshot.active_turn_id is None else UUID(snapshot.active_turn_id)
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc

    def group_profile_ids(snapshot: Any) -> tuple[str, ...]:
        """Return opaque profile markers for a group event payload."""

        if objects is None:
            return ()
        try:
            return tuple(
                str(objects.binding_for_profile(member.bot_id.profile_id).opaque_profile_id)
                for member in snapshot.members
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc

    def group_error(exc: Exception) -> HTTPException:
        if isinstance(exc, (GroupNotFound, MemberNotFound, TurnNotFound)):
            return HTTPException(status_code=404, detail="mobile object not found")
        if isinstance(exc, CrossInstanceGroupUnsupported):
            return HTTPException(status_code=422, detail=exc.code)
        if isinstance(exc, (GroupBusy, GroupStopped, TurnIndeterminate, GroupRevisionConflict,
                            ExecutionFenceLost, LeaseExpired)):
            return HTTPException(status_code=409, detail=exc.code)
        if isinstance(exc, GroupCapExceeded):
            return HTTPException(status_code=422, detail=exc.code)
        if isinstance(exc, (ValueError, MobileGroupError)):
            return HTTPException(status_code=400, detail="invalid group operation")
        return HTTPException(status_code=503, detail="mobile group service unavailable")

    def make_step_up(identity: MobileRequestIdentity, proof: StepUpProofRequest) -> StepUpChallenge:
        try:
            return StepUpChallenge(
                challenge_id=proof.challenge_id,
                device_id=identity.device.device_id,
                action=proof.action,
                context_digest=proof.context_digest,
                nonce=proof.nonce,
                expires_at=proof.expires_at,
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=403, detail="step-up authorization is invalid") from exc

    def settings_response(value: Any) -> SettingsResponse:
        if objects is None:
            raise HTTPException(status_code=503, detail="mobile settings unavailable")
        try:
            binding = objects.binding_for_profile(value.profile_id)
            return SettingsResponse(
                profile_id=binding.opaque_profile_id,
                revision=value.revision,
                etag=value.etag,
                display_name=value.display_name,
                title=value.title,
                avatar=value.avatar,
                notification_preferences=dict(value.notification_preferences),
                privacy_preferences=dict(value.privacy_preferences),
                approval_policy=dict(value.approval_policy),
                persona=value.persona,
                model=value.model,
                provider=value.provider,
                reasoning=value.reasoning,
                skills=tuple(value.skills),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc

    def routine_response(value: Any) -> RoutineResponse:
        try:
            return RoutineResponse(
                routine_id=UUID(value.routine_id),
                label=value.label,
                summary=value.summary,
                paused=value.paused,
                revision=value.revision,
                etag=value.etag,
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc

    def approval_response(value: Any) -> ApprovalResponse:
        return ApprovalResponse(
            approval_id=UUID(value.approval_id),
            summary=value.summary,
            status=value.status,
            expires_at=value.context.expires_at,
            run_id=value.context.run_id,
            request_id=value.context.request_id,
            tool_call_id=value.context.tool_call_id,
        )

    def charge_approval_profile(
        request: Request,
        identity: MobileRequestIdentity,
        value: Any,
    ) -> None:
        profile_name = getattr(value.context, "profile_id", None)
        if not profile_is_live(profile_name):
            raise HTTPException(status_code=404, detail="mobile object not found")
        opaque_profile_id = profile_marker_for_name(profile_name)
        if opaque_profile_id is None:
            raise HTTPException(status_code=404, detail="mobile object not found")
        charge_profile_rate_limit(request, identity, opaque_profile_id)

    def approval_list_response(values: Sequence[Any]) -> ApprovalsResponse:
        return ApprovalsResponse(approvals=tuple(approval_response(value) for value in values))

    def attachment_error(exc: Exception) -> HTTPException:
        if isinstance(exc, (AttachmentNotFound, AttachmentOwnershipError)):
            return HTTPException(status_code=404, detail="mobile object not found")
        if isinstance(exc, AttachmentQuotaExceeded):
            return HTTPException(
                status_code=429,
                detail="attachment quota exceeded",
                headers={"Retry-After": "60"},
            )
        if isinstance(exc, (InvalidAttachment, InvalidChunk)):
            return HTTPException(status_code=400, detail="invalid attachment operation")
        return HTTPException(status_code=503, detail="mobile attachment service unavailable")

    def replay_mutation_result(claim: Any) -> dict[str, Any] | None:
        if claim.status is MutationStatus.NEW:
            return None
        if claim.result is None:
            raise HTTPException(status_code=409, detail="mobile mutation is indeterminate")
        if claim.result.status_code >= 400:
            detail = claim.result.body.get("detail", "mobile mutation failed")
            raise HTTPException(status_code=claim.result.status_code, detail=detail)
        return dict(claim.result.body)

    def reserve_mutation(
        *,
        actor_id: str,
        action: str,
        key: str,
        body: Any,
    ) -> Any:
        """Reserve a side effect and translate body conflicts at the API edge.

        Every mobile mutation uses the same durable event-store primitive.  A
        reused key with a different canonical body is a client conflict, not a
        listener failure, so it must never escape as a 500 from an individual
        route.
        """

        if events is None:
            raise HTTPException(status_code=503, detail="mobile mutation service unavailable")
        try:
            return events.reserve_mutation(
                actor_id=actor_id,
                action=action,
                key=key,
                body=body,
            )
        except IdempotencyConflict as exc:
            raise HTTPException(status_code=409, detail="idempotency key conflict") from exc

    def push_wake_hint(
        identity: MobileRequestIdentity,
        *,
        event_type: MobilePushEvent,
        event_id: str,
        ttl_seconds: int = 300,
    ) -> None:
        """Best-effort wake hint; durable event sync remains the source of truth."""

        if push_relay is None or devices is None:
            return
        try:
            device = devices.get_device(identity.device.device_id)
            push_relay.notify(
                event_type=event_type,
                event_id=event_id,
                device_handle=device.push_handle,
                ttl_seconds=ttl_seconds,
            )
        except Exception:
            # A relay outage must not roll back a committed Hermes mutation.  The
            # next foreground/WorkManager reconciliation will recover the state.
            _LOGGER.warning("Hermes mobile push wake hint failed", exc_info=True)

    @app.get(
        "/mobile/v1/capabilities",
        response_model=MobileCapabilities,
        dependencies=[],
    )
    async def capabilities(request: Request) -> MobileCapabilities:
        await require_mobile_auth(request)
        features = ["device_enrollment", "durable_sync"]
        if chat is not None:
            features.extend(("direct_chat", "conversations"))
        if groups is not None and group_execution is not None:
            features.extend(("groups", "group_runs"))
        if attachments is not None:
            features.append("attachments")
        if settings is not None:
            features.append("settings")
        if catalog is not None:
            features.append("catalog")
        if routines is not None:
            features.append("routines")
            if routine_worker is not None:
                features.append("routine_runs")
        if approvals is not None:
            features.append("approvals")
        return MobileCapabilities(features=tuple(features))

    @app.get("/mobile/v1/sync", response_model=SyncResponse)
    async def sync_events(
        request: Request,
        cursor: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=1000),
        instance_id: UUID | None = Query(default=None),
        profile_id: UUID | None = Query(default=None),
        snapshot: bool = Query(default=False),
    ) -> SyncResponse:
        if snapshot:
            cursor = 0
        identity = await require_sync_auth(request)
        scoped_profile_id = resolve_sync_profile(
            identity,
            instance_id=instance_id,
            opaque_profile_id=profile_id,
        )
        if identity is not None and scoped_profile_id is not None:
            charge_profile_rate_limit(request, identity, scoped_profile_id)
        if events is None:
            raise HTTPException(status_code=503, detail="mobile sync unavailable")
        try:
            backlog = (
                events.snapshot_events_since(after_cursor=cursor, limit=limit)
                if snapshot
                else events.events_since(after_cursor=cursor, limit=limit)
            )
        except CursorExpired as exc:
            raise HTTPException(
                status_code=410,
                detail={
                    "code": exc.code,
                    "retained_floor": exc.retained_floor,
                    "latest_cursor": exc.latest_cursor,
                },
            ) from exc
        except MobileEventStoreError as exc:
            raise HTTPException(status_code=503, detail="mobile sync unavailable") from exc
        visible_events = tuple(
            event for event in backlog.events
            if event_visible_for_profile(event, scoped_profile_id)
        )
        # Advance over the complete instance cursor page, not only the events
        # visible to this profile.  Otherwise a page containing another
        # profile's event would be fetched forever by the mobile client.
        next_cursor = backlog.events[-1].cursor if backlog.events else cursor
        return SyncResponse(
            instance_id=events.instance_id,
            after_cursor=backlog.after_cursor,
            next_cursor=next_cursor,
            latest_cursor=backlog.latest_cursor,
            retained_floor=backlog.retained_floor,
            has_more=backlog.has_more,
            snapshot_required=False,
            events=tuple(
                SyncEventResponse(
                    cursor=event.cursor,
                    event_id=event.event_id,
                    event_type=event.event_type,
                    aggregate_type=event.aggregate_type,
                    aggregate_id=event.aggregate_id,
                    payload=dict(event.payload),
                    created_at=event.created_at,
                    tombstone=event.tombstone,
                )
                for event in visible_events
            ),
        )

    @app.get("/mobile/v1/profiles", response_model=MobileProfilesResponse)
    async def list_mobile_profiles(request: Request) -> MobileProfilesResponse:
        identity = await require_profiles_auth(request)
        if objects is None:
            raise HTTPException(status_code=503, detail="mobile profile service unavailable")
        token_profiles = identity.device.token_claims.get("profiles", [])
        live_profiles = reconcile_live_profiles()
        effective = tuple(
            profile
            for profile in live_profiles
            if isinstance(profile, str) and profile in token_profiles
        )
        bindings = objects.profiles(effective)
        for binding in bindings:
            charge_profile_rate_limit(request, identity, binding.opaque_profile_id)
        return MobileProfilesResponse(
            profiles=tuple(
                MobileProfileResponse(
                    bot=BotId(
                        instance_id=binding.instance_id,
                        opaque_profile_id=binding.opaque_profile_id,
                    ),
                    label=f"Hermes bot {index}",
                )
                for index, binding in enumerate(bindings, start=1)
            )
        )

    @app.get(
        "/mobile/v1/profiles/{opaque_profile_id}/settings",
        response_model=SettingsResponse,
    )
    async def get_profile_settings(
        opaque_profile_id: UUID,
        request: Request,
    ) -> SettingsResponse:
        _, profile_name = await resolve_profile_auth(request, opaque_profile_id, scope="settings:read")
        if settings is None:
            raise HTTPException(status_code=503, detail="mobile settings unavailable")
        try:
            value = await asyncio.to_thread(settings.get, profile_name)
        except SettingsNotFound as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        except SettingsError as exc:
            raise HTTPException(status_code=503, detail="mobile settings unavailable") from exc
        return settings_response(value)

    @app.post(
        "/mobile/v1/profiles/{opaque_profile_id}/settings/step-up",
        response_model=StepUpChallengeResponse,
        status_code=201,
    )
    async def create_settings_step_up(
        opaque_profile_id: UUID,
        body: SettingsUpdateRequest,
        request: Request,
    ) -> StepUpChallengeResponse:
        if request_authorizer is None or settings is None or step_up is None or objects is None:
            raise HTTPException(status_code=503, detail="mobile settings unavailable")
        identity, profile_name = await resolve_profile_auth(
            request,
            opaque_profile_id,
            scope="settings:write:safe",
        )
        try:
            current = await asyncio.to_thread(settings.get, profile_name)
            context = settings_step_up_context(
                instance_id=str(objects.instance_id),
                profile_id=profile_name,
                revision=current.revision,
                changes=body.changes,
            )
            challenge = await asyncio.to_thread(
                step_up.create,
                device_id=identity.device.device_id,
                action="settings.step_up.write",
                context=context,
            )
        except (SettingsError, DeviceNotAuthorized, ValueError) as exc:
            raise HTTPException(status_code=400, detail="invalid settings step-up request") from exc
        return StepUpChallengeResponse(
            challenge_id=challenge.challenge_id,
            action=challenge.action,
            context_digest=challenge.context_digest,
            nonce=challenge.nonce,
            expires_at=challenge.expires_at,
        )

    @app.patch(
        "/mobile/v1/profiles/{opaque_profile_id}/settings",
        response_model=SettingsResponse,
    )
    async def update_profile_settings(
        opaque_profile_id: UUID,
        body: SettingsUpdateRequest,
        request: Request,
        if_match: str = Header(min_length=1, max_length=128, alias="If-Match"),
        idempotency_key: str = Header(min_length=16, max_length=255, alias="Idempotency-Key"),
    ) -> SettingsResponse:
        identity, profile_name = await resolve_profile_auth(
            request,
            opaque_profile_id,
            scope="settings:write:safe",
        )
        if settings is None or events is None:
            raise HTTPException(status_code=503, detail="mobile settings unavailable")
        claim = reserve_mutation(
            actor_id=identity.device.device_id,
            action="settings.update",
            key=idempotency_key,
            body={"profile": str(opaque_profile_id), "changes": body.changes, "if_match": if_match},
        )
        replay = replay_mutation_result(claim)
        if replay is not None:
            return SettingsResponse(**replay)
        try:
            value = await asyncio.to_thread(
                settings.update,
                profile_name,
                actor_id=identity.device.device_id,
                if_match=if_match,
                changes=body.changes,
                idempotency_key=idempotency_key,
            )
            response = settings_response(value)
            result = MutationResult(status_code=200, body=response.model_dump(mode="json"))
            events.complete_mutation(
                claim.mutation_id,
                result=result,
                events=(EventInput(
                    event_type="settings.updated",
                    aggregate_type="profile",
                    aggregate_id=str(opaque_profile_id),
                    payload={
                        "profile_id": str(opaque_profile_id),
                        "revision": value.revision,
                    },
                ),),
            )
            return response
        except StepUpRequired as exc:
            http_error = HTTPException(status_code=403, detail="step-up authorization required")
        except SettingsConflict as exc:
            http_error = HTTPException(status_code=409, detail="settings_revision_conflict")
        except SettingsNotFound as exc:
            http_error = HTTPException(status_code=404, detail="mobile object not found")
        except SettingsError as exc:
            http_error = HTTPException(status_code=400, detail="invalid settings operation")
        events.fail_mutation(
            claim.mutation_id,
            result=MutationResult(status_code=http_error.status_code, body={"detail": http_error.detail}),
        )
        raise http_error from exc

    @app.patch(
        "/mobile/v1/profiles/{opaque_profile_id}/settings/sensitive",
        response_model=SettingsResponse,
    )
    async def update_sensitive_profile_settings(
        opaque_profile_id: UUID,
        body: SensitiveSettingsUpdateRequest,
        request: Request,
        if_match: str = Header(min_length=1, max_length=128, alias="If-Match"),
        idempotency_key: str = Header(min_length=16, max_length=255, alias="Idempotency-Key"),
    ) -> SettingsResponse:
        # The proof is a separate JSON body in clients that support it.  The
        # server builds the signed context from the resolved profile/revision;
        # no internal profile name is accepted from Android.
        identity, profile_name = await resolve_profile_auth(
            request,
            opaque_profile_id,
            scope="settings:write:safe",
        )
        if settings is None or events is None or objects is None:
            raise HTTPException(status_code=503, detail="mobile settings unavailable")
        try:
            current = await asyncio.to_thread(settings.get, profile_name)
            context = settings_step_up_context(
                instance_id=str(objects.instance_id),
                profile_id=profile_name,
                revision=current.revision,
                changes=body.changes,
            )
            challenge = make_step_up(identity, body.step_up)
        except (SettingsError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="invalid settings operation") from exc
        claim = reserve_mutation(
            actor_id=identity.device.device_id,
            action="settings.step_up.write",
            key=idempotency_key,
            body={"profile": str(opaque_profile_id), "changes": body.changes, "if_match": if_match},
        )
        replay = replay_mutation_result(claim)
        if replay is not None:
            return SettingsResponse(**replay)
        try:
            value = await asyncio.to_thread(
                settings.update_sensitive,
                profile_name,
                actor_id=identity.device.device_id,
                if_match=if_match,
                changes=body.changes,
                challenge=challenge,
                signature=body.step_up.signature,
                context=context,
                idempotency_key=idempotency_key,
            )
            response = settings_response(value)
            result = MutationResult(status_code=200, body=response.model_dump(mode="json"))
            events.complete_mutation(
                claim.mutation_id,
                result=result,
                events=(EventInput(
                    event_type="settings.sensitive_updated",
                    aggregate_type="profile",
                    aggregate_id=str(opaque_profile_id),
                    payload={"profile_id": str(opaque_profile_id), "revision": value.revision},
                ),),
            )
            return response
        except StepUpRequired as exc:
            events.fail_mutation(
                claim.mutation_id,
                result=MutationResult(status_code=403, body={"detail": "step-up authorization required"}),
            )
            raise HTTPException(status_code=403, detail="step-up authorization required") from exc
        except SettingsConflict as exc:
            events.fail_mutation(
                claim.mutation_id,
                result=MutationResult(status_code=409, body={"detail": "settings_revision_conflict"}),
            )
            raise HTTPException(status_code=409, detail="settings_revision_conflict") from exc
        except SettingsNotFound as exc:
            events.fail_mutation(
                claim.mutation_id,
                result=MutationResult(status_code=404, body={"detail": "mobile object not found"}),
            )
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        except SettingsError as exc:
            events.fail_mutation(
                claim.mutation_id,
                result=MutationResult(status_code=400, body={"detail": "invalid settings operation"}),
            )
            raise HTTPException(status_code=400, detail="invalid settings operation") from exc
        except Exception as exc:
            events.mark_indeterminate(
                claim.mutation_id,
                reason="settings_update_failure",
                event=EventInput(
                    event_type="mutation.indeterminate",
                    aggregate_type="mutation",
                    aggregate_id=claim.mutation_id,
                    payload={
                        "mutation_id": claim.mutation_id,
                        "action": "settings.step_up.write",
                        "reason": "settings_update_failure",
                        "profile_id": str(opaque_profile_id),
                    },
                ),
            )
            raise HTTPException(status_code=409, detail="settings update indeterminate") from exc

    @app.get(
        "/mobile/v1/profiles/{opaque_profile_id}/catalog",
        response_model=CatalogResponse,
    )
    async def list_catalog(
        opaque_profile_id: UUID,
        request: Request,
        kind: str | None = Query(default=None),
    ) -> CatalogResponse:
        _, profile_name = await resolve_profile_auth(request, opaque_profile_id, scope="settings:read")
        if catalog is None:
            raise HTTPException(status_code=503, detail="mobile catalog unavailable")
        try:
            snapshot = catalog.list(profile_name, kind=kind)
        except CatalogError as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        return CatalogResponse(
            revision=snapshot.revision,
            etag=snapshot.etag,
            entries=tuple(
                {
                    "entry_id": entry.entry_id,
                    "kind": entry.kind,
                    "key": entry.key,
                    "label": entry.label,
                    "summary": entry.summary,
                }
                for entry in snapshot.entries
            ),
        )

    @app.get(
        "/mobile/v1/profiles/{opaque_profile_id}/routines",
        response_model=RoutineListResponse,
    )
    async def list_routines(
        opaque_profile_id: UUID,
        request: Request,
    ) -> RoutineListResponse:
        _, profile_name = await resolve_profile_auth(request, opaque_profile_id, scope="routines:control")
        if routines is None:
            raise HTTPException(status_code=503, detail="mobile routines unavailable")
        try:
            snapshots = tuple(routines.get(profile_name, item.routine_id) for item in routines.routines(profile_name))
        except RoutineError as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        return RoutineListResponse(routines=tuple(routine_response(value) for value in snapshots))

    @app.patch(
        "/mobile/v1/profiles/{opaque_profile_id}/routines/{routine_id}",
        response_model=RoutineResponse,
    )
    async def set_routine_paused(
        opaque_profile_id: UUID,
        routine_id: UUID,
        body: RoutinePauseRequest,
        request: Request,
        if_match: str = Header(min_length=1, max_length=128, alias="If-Match"),
        idempotency_key: str = Header(min_length=16, max_length=255, alias="Idempotency-Key"),
    ) -> RoutineResponse:
        identity, profile_name = await resolve_profile_auth(request, opaque_profile_id, scope="routines:control")
        if routines is None or events is None:
            raise HTTPException(status_code=503, detail="mobile routines unavailable")
        claim = reserve_mutation(
            actor_id=identity.device.device_id,
            action="routine.pause" if body.paused else "routine.resume",
            key=idempotency_key,
            body={"profile": str(opaque_profile_id), "routine_id": str(routine_id), "paused": body.paused, "if_match": if_match},
        )
        replay = replay_mutation_result(claim)
        if replay is not None:
            return RoutineResponse(**replay)
        try:
            method = routines.pause if body.paused else routines.resume
            value = await asyncio.to_thread(
                method,
                profile_name,
                str(routine_id),
                actor_id=identity.device.device_id,
                if_match=if_match,
            )
            response = routine_response(value)
            result = MutationResult(status_code=200, body=response.model_dump(mode="json"))
            events.complete_mutation(
                claim.mutation_id,
                result=result,
                events=(
                    EventInput(
                        event_type="routine.updated",
                        aggregate_type="routine",
                        aggregate_id=str(routine_id),
                        payload={
                            "profile_id": str(opaque_profile_id),
                            "paused": value.paused,
                            "revision": value.revision,
                        },
                    ),
                ),
            )
            return response
        except RoutineNotFound as exc:
            http_error = HTTPException(status_code=404, detail="mobile object not found")
        except RoutineError as exc:
            http_error = HTTPException(status_code=409, detail="routine_revision_conflict")
        events.fail_mutation(
            claim.mutation_id,
            result=MutationResult(status_code=http_error.status_code, body={"detail": http_error.detail}),
        )
        raise http_error from exc

    @app.post(
        "/mobile/v1/profiles/{opaque_profile_id}/routines/{routine_id}/run",
        response_model=RoutineRunResponse,
        status_code=202,
    )
    async def run_routine(
        opaque_profile_id: UUID,
        routine_id: UUID,
        body: RoutineRunRequest,
        request: Request,
        idempotency_key: str = Header(min_length=16, max_length=255, alias="Idempotency-Key"),
    ) -> RoutineRunResponse:
        identity, profile_name = await resolve_profile_auth(request, opaque_profile_id, scope="routines:control")
        if routines is None or events is None:
            raise HTTPException(status_code=503, detail="mobile routines unavailable")
        # A reservation without a host-owned executor would remain pending forever.  Fail closed
        # before consuming the step-up proof or creating a durable mutation claim.
        if routine_worker is None:
            raise HTTPException(status_code=503, detail="mobile routine worker unavailable")
        try:
            context = await asyncio.to_thread(
                routines.run_context,
                profile_name,
                str(routine_id),
                idempotency_key,
                body=body.input,
            )
            challenge = make_step_up(identity, body.step_up)
        except RoutineError as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        claim = reserve_mutation(
            actor_id=identity.device.device_id,
            action="routine.run",
            key=idempotency_key,
            body={"profile": str(opaque_profile_id), "routine_id": str(routine_id), "input": body.input},
        )
        replay = replay_mutation_result(claim)
        if replay is not None:
            return RoutineRunResponse(**replay)
        try:
            routine = await asyncio.to_thread(
                routines.definition,
                profile_name,
                str(routine_id),
            )
            value = await asyncio.to_thread(
                routines.run,
                profile_name,
                str(routine_id),
                actor_id=identity.device.device_id,
                idempotency_key=idempotency_key,
                body=body.input,
                challenge=challenge,
                signature=body.step_up.signature,
                context=context,
            )
            if value.status == "pending":
                try:
                    routine_worker.submit(
                        value,
                        profile_name=profile_name,
                        routine=routine,
                        input=body.input,
                    )
                except Exception as exc:
                    # The reservation is already durable. It cannot be safely retried because a
                    # future worker may observe the same idempotency key, so fence it explicitly.
                    await asyncio.to_thread(
                        routines.mark_indeterminate,
                        value.run_id,
                        reason="worker_dispatch",
                    )
                    events.mark_indeterminate(
                        claim.mutation_id,
                        reason="routine_worker_dispatch",
                        event=EventInput(
                            event_type="mutation.indeterminate",
                            aggregate_type="mutation",
                            aggregate_id=claim.mutation_id,
                            payload={
                                "mutation_id": claim.mutation_id,
                                "action": "routine.run",
                                "profile_id": str(opaque_profile_id),
                                "reason": "routine_worker_dispatch",
                            },
                        ),
                    )
                    raise HTTPException(status_code=409, detail="routine execution indeterminate") from exc
            response = RoutineRunResponse(
                run_id=UUID(value.run_id),
                routine_id=UUID(value.routine_id),
                state=value.status,
                result=value.result,
            )
            result = MutationResult(status_code=202, body=response.model_dump(mode="json"))
            events.complete_mutation(
                claim.mutation_id,
                result=result,
                events=(EventInput(
                    event_type="routine.run.queued",
                    aggregate_type="routine_run",
                    aggregate_id=value.run_id,
                     payload={
                         "profile_id": str(opaque_profile_id),
                         "routine_id": value.routine_id,
                     },
                ),),
            )
            return response
        except RoutineAlreadyRunning as exc:
            events.fail_mutation(
                claim.mutation_id,
                result=MutationResult(status_code=409, body={"detail": "routine_already_running"}),
            )
            raise HTTPException(status_code=409, detail="routine_already_running") from exc
        except RoutineStepUpRequired as exc:
            events.fail_mutation(
                claim.mutation_id,
                result=MutationResult(status_code=403, body={"detail": "step-up authorization required"}),
            )
            raise HTTPException(status_code=403, detail="step-up authorization required") from exc
        except RoutineError as exc:
            events.fail_mutation(
                claim.mutation_id,
                result=MutationResult(status_code=409, body={"detail": "routine execution refused"}),
            )
            raise HTTPException(status_code=409, detail="routine execution refused") from exc

    @app.get("/mobile/v1/routine-runs/{run_id}", response_model=RoutineRunResponse)
    async def get_routine_run(run_id: UUID, request: Request) -> RoutineRunResponse:
        if request_authorizer is None or routines is None:
            raise HTTPException(status_code=503, detail="mobile routines unavailable")
        identity = request_authorizer.authorize(request, scope="routines:control")
        try:
            value = routines.get_run(str(run_id))
            if value.actor_id != identity.device.device_id:
                raise RoutineNotFound("routine run not found")
            if value.profile_id not in set(identity.device.token_claims.get("profiles", [])):
                raise RoutineNotFound("routine run not found")
            if not profile_is_live(value.profile_id):
                raise RoutineNotFound("routine run not found")
        except RoutineError as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        opaque_profile_id = profile_marker_for_name(value.profile_id)
        if opaque_profile_id is not None:
            charge_profile_rate_limit(request, identity, opaque_profile_id)
        return RoutineRunResponse(
            run_id=UUID(value.run_id),
            routine_id=UUID(value.routine_id),
            state=value.status,
            result=value.result,
        )

    @app.get("/mobile/v1/approvals", response_model=ApprovalsResponse)
    async def list_approvals(request: Request) -> ApprovalsResponse:
        if request_authorizer is None or approvals is None:
            raise HTTPException(status_code=503, detail="mobile approvals unavailable")
        identity = request_authorizer.authorize(request, scope="approvals")
        try:
            values = approvals.list_for_actor(
                actor_id=identity.device.device_id,
                profile_ids=identity.device.token_claims.get("profiles", []),
                pending_only=True,
            )
        except ApprovalError as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        for value in values:
            charge_approval_profile(request, identity, value)
        return approval_list_response(values)

    @app.get("/mobile/v1/runs/{run_id}/approval", response_model=ApprovalResponse)
    async def get_run_approval(run_id: UUID, request: Request) -> ApprovalResponse:
        if request_authorizer is None or approvals is None:
            raise HTTPException(status_code=503, detail="mobile approvals unavailable")
        identity = request_authorizer.authorize(request, scope="approvals")
        try:
            values = approvals.list_for_actor(
                actor_id=identity.device.device_id,
                profile_ids=identity.device.token_claims.get("profiles", []),
                run_id=str(run_id),
            )
        except ApprovalError as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        if not values:
            raise HTTPException(status_code=404, detail="mobile object not found")
        value = next((value for value in values if value.status == "pending"), values[0])
        charge_approval_profile(request, identity, value)
        return approval_response(value)

    @app.get("/mobile/v1/approvals/{approval_id}", response_model=ApprovalResponse)
    async def get_approval(approval_id: UUID, request: Request) -> ApprovalResponse:
        if request_authorizer is None or approvals is None:
            raise HTTPException(status_code=503, detail="mobile approvals unavailable")
        identity = request_authorizer.authorize(request, scope="approvals")
        try:
            value = approvals.get(str(approval_id))
            if value.actor_id != identity.device.device_id:
                raise ApprovalNotFound("approval not found")
            if value.context.profile_id not in set(identity.device.token_claims.get("profiles", [])):
                raise ApprovalNotFound("approval not found")
        except ApprovalError as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        charge_approval_profile(request, identity, value)
        return approval_response(value)

    @app.post(
        "/mobile/v1/approvals/{approval_id}/step-up",
        response_model=StepUpChallengeResponse,
        status_code=201,
    )
    async def create_approval_step_up(
        approval_id: UUID,
        request: Request,
    ) -> StepUpChallengeResponse:
        """Create a challenge from the server-owned approval context.

        The client receives only the opaque challenge fields; profile/session names and argument
        digests never need to be copied into an Android request body.
        """

        if request_authorizer is None or approvals is None or step_up is None:
            raise HTTPException(status_code=503, detail="mobile approvals unavailable")
        identity = request_authorizer.authorize(request, scope="approvals")
        try:
            value = approvals.get(str(approval_id))
            if (
                value.actor_id != identity.device.device_id
                or value.context.profile_id not in set(identity.device.token_claims.get("profiles", []))
            ):
                raise ApprovalNotFound("approval not found")
            charge_approval_profile(request, identity, value)
            challenge = step_up.create(
                device_id=identity.device.device_id,
                action="approvals.approve_once",
                context=approval_step_up_context(value),
            )
        except ApprovalNotFound as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        except (ApprovalError, DeviceNotAuthorized, ValueError) as exc:
            raise HTTPException(status_code=403, detail="approval step-up unavailable") from exc
        return StepUpChallengeResponse(
            challenge_id=challenge.challenge_id,
            action=challenge.action,
            context_digest=challenge.context_digest,
            nonce=challenge.nonce,
            expires_at=challenge.expires_at,
        )

    @app.post("/mobile/v1/approvals/{approval_id}/approve", response_model=ApprovalResponse)
    async def approve_once(
        approval_id: UUID,
        body: StepUpProofRequest,
        request: Request,
        idempotency_key: str = Header(min_length=16, max_length=255, alias="Idempotency-Key"),
    ) -> ApprovalResponse:
        if request_authorizer is None or approvals is None:
            raise HTTPException(status_code=503, detail="mobile approvals unavailable")
        identity = request_authorizer.authorize(request, scope="approvals")
        claim = None
        if events is not None:
            try:
                claim = events.reserve_mutation(
                    actor_id=identity.device.device_id,
                    action="approval.approve_once",
                    key=idempotency_key,
                    body={
                        "approval_id": str(approval_id),
                        "context_digest": body.context_digest,
                        "challenge_id": str(body.challenge_id),
                    },
                )
                replay = replay_mutation_result(claim)
                if replay is not None:
                    return ApprovalResponse(**replay)
            except IdempotencyConflict as exc:
                raise HTTPException(status_code=409, detail="idempotency key conflict") from exc
        try:
            value = approvals.get(str(approval_id))
            if (
                value.actor_id != identity.device.device_id
                or value.context.profile_id not in set(identity.device.token_claims.get("profiles", []))
            ):
                raise ApprovalNotFound("approval not found")
            charge_approval_profile(request, identity, value)
            challenge = make_step_up(identity, body)
            result = approvals.approve_once(
                str(approval_id),
                actor_id=identity.device.device_id,
                context=value.context,
                challenge=challenge,
                signature=body.signature,
            )
            response = approval_response(result)
            if claim is not None:
                events.complete_mutation(
                    claim.mutation_id,
                    result=MutationResult(status_code=200, body=response.model_dump(mode="json")),
                    events=(EventInput(
                        event_type="approval.approved",
                        aggregate_type="approval",
                        aggregate_id=str(approval_id),
                        payload=(
                            {
                                "profile_id": str(
                                    objects.binding_for_profile(value.context.profile_id).opaque_profile_id
                                )
                            }
                            if objects is not None
                            else {}
                        ),
                    ),),
                )
            return response
        except ApprovalNotFound as exc:
            if claim is not None:
                events.fail_mutation(
                    claim.mutation_id,
                    result=MutationResult(status_code=404, body={"detail": "mobile object not found"}),
                )
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        except (ApprovalConflict, ApprovalAlreadyResolved, ApprovalExpired) as exc:
            if claim is not None:
                events.fail_mutation(
                    claim.mutation_id,
                    result=MutationResult(status_code=409, body={"detail": "approval is no longer available"}),
                )
            raise HTTPException(status_code=409, detail="approval is no longer available") from exc
        except ApprovalError as exc:
            if claim is not None:
                events.fail_mutation(
                    claim.mutation_id,
                    result=MutationResult(status_code=403, body={"detail": "approval authorization refused"}),
                )
            raise HTTPException(status_code=403, detail="approval authorization refused") from exc
        except HTTPException as exc:
            # Profile liveness and step-up helpers can reject before the approval store is
            # touched. Preserve their precise 4xx classification instead of converting a
            # stale profile into an indeterminate side-effect outcome.
            if claim is not None:
                events.fail_mutation(
                    claim.mutation_id,
                    result=MutationResult(status_code=exc.status_code, body={"detail": exc.detail}),
                )
            raise
        except Exception as exc:
            if claim is not None:
                events.mark_indeterminate(claim.mutation_id, reason="approval_update_failure")
            raise HTTPException(status_code=409, detail="approval decision indeterminate") from exc

    @app.post("/mobile/v1/approvals/{approval_id}/deny", response_model=ApprovalResponse)
    async def deny_approval(
        approval_id: UUID,
        request: Request,
        idempotency_key: str = Header(min_length=16, max_length=255, alias="Idempotency-Key"),
    ) -> ApprovalResponse:
        if request_authorizer is None or approvals is None:
            raise HTTPException(status_code=503, detail="mobile approvals unavailable")
        identity = request_authorizer.authorize(request, scope="approvals")
        claim = None
        if events is not None:
            try:
                claim = events.reserve_mutation(
                    actor_id=identity.device.device_id,
                    action="approval.deny",
                    key=idempotency_key,
                    body={"approval_id": str(approval_id)},
                )
                replay = replay_mutation_result(claim)
                if replay is not None:
                    return ApprovalResponse(**replay)
            except IdempotencyConflict as exc:
                raise HTTPException(status_code=409, detail="idempotency key conflict") from exc
        try:
            value = approvals.get(str(approval_id))
            if (
                value.actor_id != identity.device.device_id
                or value.context.profile_id not in set(identity.device.token_claims.get("profiles", []))
            ):
                raise ApprovalNotFound("approval not found")
            charge_approval_profile(request, identity, value)
            result = approvals.deny(
                str(approval_id),
                actor_id=identity.device.device_id,
                context=value.context,
            )
            response = approval_response(result)
            if claim is not None:
                events.complete_mutation(
                    claim.mutation_id,
                    result=MutationResult(status_code=200, body=response.model_dump(mode="json")),
                    events=(EventInput(
                        event_type="approval.denied",
                        aggregate_type="approval",
                        aggregate_id=str(approval_id),
                        payload=(
                            {
                                "profile_id": str(
                                    objects.binding_for_profile(value.context.profile_id).opaque_profile_id
                                )
                            }
                            if objects is not None
                            else {}
                        ),
                    ),),
                )
            return response
        except ApprovalNotFound as exc:
            if claim is not None:
                events.fail_mutation(
                    claim.mutation_id,
                    result=MutationResult(status_code=404, body={"detail": "mobile object not found"}),
                )
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        except (ApprovalConflict, ApprovalAlreadyResolved, ApprovalExpired) as exc:
            if claim is not None:
                events.fail_mutation(
                    claim.mutation_id,
                    result=MutationResult(status_code=409, body={"detail": "approval is no longer available"}),
                )
            raise HTTPException(status_code=409, detail="approval is no longer available") from exc
        except ApprovalError as exc:
            if claim is not None:
                events.fail_mutation(
                    claim.mutation_id,
                    result=MutationResult(status_code=400, body={"detail": "approval operation refused"}),
                )
            raise HTTPException(status_code=400, detail="approval operation refused") from exc
        except HTTPException as exc:
            if claim is not None:
                events.fail_mutation(
                    claim.mutation_id,
                    result=MutationResult(status_code=exc.status_code, body={"detail": exc.detail}),
                )
            raise
        except Exception as exc:
            if claim is not None:
                events.mark_indeterminate(claim.mutation_id, reason="approval_update_failure")
            raise HTTPException(status_code=409, detail="approval decision indeterminate") from exc

    @app.get("/mobile/v1/events")
    async def stream_mobile_events(
        request: Request,
        after_cursor: int = Query(default=0, ge=0, alias="after"),
        instance_id: UUID | None = Query(default=None),
        profile_id: UUID | None = Query(default=None),
    ) -> StreamingResponse:
        identity = await require_events_auth(request)
        scoped_profile_id = resolve_sync_profile(
            identity,
            instance_id=instance_id,
            opaque_profile_id=profile_id,
        )
        if scoped_profile_id is not None:
            charge_profile_rate_limit(request, identity, scoped_profile_id)
        if events is None or devices is None:
            raise HTTPException(status_code=503, detail="mobile event stream unavailable")
        try:
            # Validate the starting cursor before headers are committed.  A
            # cursor that fell out of the 30-day retention window must be
            # repaired with a complete sync rather than looking like a clean
            # but empty SSE stream.
            events.events_since(after_cursor=after_cursor, limit=1)
        except CursorExpired as exc:
            raise HTTPException(
                status_code=410,
                detail={
                    "code": exc.code,
                    "retained_floor": exc.retained_floor,
                    "latest_cursor": exc.latest_cursor,
                },
            ) from exc
        except MobileEventStoreError as exc:
            raise HTTPException(status_code=503, detail="mobile event stream unavailable") from exc

        async def stream():
            current_cursor = after_cursor
            deadline = time.monotonic() + sse_max_lifetime_seconds
            while time.monotonic() < deadline and not await request.is_disconnected():
                try:
                    if scoped_profile_id is not None and objects is not None and profile_liveness is not None:
                        # A profile may be deleted or renamed after the stream is authorized.
                        # Reconcile on each heartbeat so the old opaque principal cannot keep
                        # receiving historical events after its host object disappears.
                        live_profiles = set(reconcile_live_profiles())
                        token_profiles = set(identity.device.token_claims.get("profiles", []))
                        objects.resolve_profile(
                            scoped_profile_id,
                            token_profiles & live_profiles,
                        )
                    if not devices.get_device(identity.device.device_id).approved:
                        return
                    backlog = events.events_since(after_cursor=current_cursor, limit=100)
                except (KeyError, TypeError, ValueError, MobileDeviceError, CursorExpired, MobileEventStoreError):
                    return
                emitted = False
                if backlog.events:
                    for event in backlog.events:
                        # Even filtered events advance the cursor.  A client
                        # must never receive another profile's payload, but it
                        # still needs to move through the shared instance log.
                        current_cursor = event.cursor
                        if not event_visible_for_profile(event, scoped_profile_id):
                            continue
                        emitted = True
                        payload = {
                            "cursor": event.cursor,
                            "event_id": event.event_id,
                            "event_type": event.event_type,
                            "aggregate_type": event.aggregate_type,
                            "aggregate_id": event.aggregate_id,
                            "payload": dict(event.payload),
                            "created_at": event.created_at,
                            "tombstone": event.tombstone,
                        }
                        yield (
                            f"id: {event.cursor}\nevent: mobile\n"
                            f"data: {json.dumps(payload, separators=(',', ':'))}\n\n"
                        )
                if not emitted:
                    yield ": heartbeat\n\n"
                await asyncio.sleep(sse_heartbeat_seconds)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-store",
                "X-Accel-Buffering": "no",
            },
        )

    @app.post(
        "/mobile/v1/devices",
        response_model=DeviceEnrollmentResponse,
        status_code=201,
    )
    async def enroll_device(
        enrollment: DeviceEnrollmentRequest,
        request: Request,
    ) -> DeviceEnrollmentResponse:
        identity = await require_access_auth(request)
        try:
            challenge = devices.create_enrollment_code(
                enrollment.background_jwk,
                enrollment.user_presence_jwk,
                access_subject=identity.subject,
                access_email=identity.email,
                device_label=enrollment.device_label,
            )
        except (InvalidEnrollment, ValueError) as exc:
            raise HTTPException(status_code=400, detail="invalid device enrollment") from exc
        except MobileDeviceError as exc:
            raise HTTPException(status_code=503, detail="mobile device service unavailable") from exc
        return DeviceEnrollmentResponse(
            device_id=challenge.device_id,
            enrollment_code=challenge.code,
            expires_at=challenge.expires_at,
        )

    @app.get("/mobile/v1/devices", response_model=MobileDevicesResponse)
    async def list_mobile_devices(request: Request) -> MobileDevicesResponse:
        identity = await require_access_auth(request)
        if devices is None:
            raise HTTPException(status_code=503, detail="mobile device service unavailable")
        result: list[MobileDeviceResponse] = []
        for record in devices.list_devices():
            if record.access_subject != identity.subject:
                continue
            opaque_profiles: list[BotId] = []
            if objects is not None:
                for profile_name in record.profile_allowlist:
                    try:
                        binding = objects.binding_for_profile(profile_name)
                    except KeyError:
                        continue
                    opaque_profiles.append(
                        BotId(
                            instance_id=binding.instance_id,
                            opaque_profile_id=binding.opaque_profile_id,
                        )
                    )
            result.append(
                MobileDeviceResponse(
                    device_id=record.device_id,
                    label=record.device_label,
                    status=record.status,
                    profiles=tuple(opaque_profiles),
                    scopes=record.scope_allowlist,
                    created_at=record.created_at,
                    approved_at=record.approved_at,
                    revoked_at=record.revoked_at,
                )
            )
        return MobileDevicesResponse(devices=tuple(result))

    @app.delete("/mobile/v1/devices/{device_id}", status_code=204)
    async def revoke_mobile_device(
        device_id: str,
        request: Request,
        idempotency_key: str | None = Header(
            default=None,
            min_length=16,
            max_length=255,
            alias="Idempotency-Key",
        ),
    ) -> Response:
        identity = await require_device_owner(request, device_id)
        if devices is None:
            raise HTTPException(status_code=503, detail="mobile device service unavailable")
        claim = None
        if events is not None:
            if idempotency_key is None:
                raise HTTPException(status_code=400, detail="Idempotency-Key is required")
            try:
                claim = events.reserve_mutation(
                    actor_id=identity.subject,
                    action="device.revoke",
                    key=idempotency_key,
                    body={"device_id": device_id},
                )
                replay = replay_mutation_result(claim)
                if replay is not None:
                    return Response(status_code=204)
            except IdempotencyConflict as exc:
                raise HTTPException(status_code=409, detail="idempotency key conflict") from exc
        try:
            record = devices.revoke_device(device_id)
        except (DeviceNotAuthorized, MobileDeviceError) as exc:
            if claim is not None:
                events.fail_mutation(
                    claim.mutation_id,
                    result=MutationResult(status_code=404, body={"detail": "mobile device not found"}),
                )
            raise HTTPException(status_code=404, detail="mobile device not found") from exc
        if push_relay is not None:
            try:
                push_relay.revoke_device(record.push_handle)
            except (httpx.HTTPError, ValueError):
                _LOGGER.warning("mobile push relay revocation failed", exc_info=True)
        if claim is not None:
            events.complete_mutation(
                claim.mutation_id,
                result=MutationResult(status_code=204, body={}),
                events=(EventInput(
                    event_type="device.revoked",
                    aggregate_type="device",
                    aggregate_id=device_id,
                    payload={},
                ),),
            )
        return Response(status_code=204)

    @app.post(
        "/mobile/v1/devices/{device_id}/token/challenge",
        response_model=DeviceTokenChallengeResponse,
    )
    async def create_device_token_challenge(
        device_id: str,
        request: Request,
    ) -> DeviceTokenChallengeResponse:
        await require_device_owner(request, device_id)
        try:
            challenge = devices.create_token_challenge(device_id)
        except (DeviceNotAuthorized, MobileDeviceError) as exc:
            raise HTTPException(status_code=401, detail="mobile authentication required") from exc
        return DeviceTokenChallengeResponse(nonce=challenge.nonce, expires_at=challenge.expires_at)

    @app.post(
        "/mobile/v1/devices/{device_id}/token",
        response_model=DeviceTokenResponse,
    )
    async def issue_device_token(
        device_id: str,
        token_request: DeviceTokenRequest,
        request: Request,
    ) -> DeviceTokenResponse:
        await require_device_owner(request, device_id)
        try:
            token = devices.complete_token_challenge(
                device_id,
                nonce=token_request.nonce,
                signature=token_request.signature,
            )
        except (DeviceNotAuthorized, MobileDeviceError, ValueError) as exc:
            raise HTTPException(status_code=401, detail="mobile authentication required") from exc
        return DeviceTokenResponse(device_token=token)

    @app.put("/mobile/v1/devices/{device_id}/push", status_code=204)
    async def register_push_token(
        device_id: str,
        registration: PushRegistrationRequest,
        request: Request,
        idempotency_key: str | None = Header(default=None, min_length=16, max_length=255, alias="Idempotency-Key"),
    ) -> None:
        await require_push_auth(request, device_id)
        if push_relay is None or devices is None:
            raise HTTPException(status_code=503, detail="mobile push unavailable")
        claim = None
        if events is not None:
            if idempotency_key is None:
                raise HTTPException(status_code=400, detail="Idempotency-Key is required")
            try:
                claim = events.reserve_mutation(
                    actor_id=device_id,
                    action="push.register",
                    key=idempotency_key,
                    body={"device_id": device_id, "fcm_token": registration.fcm_token},
                )
                replay = replay_mutation_result(claim)
                if replay is not None:
                    return None
            except IdempotencyConflict as exc:
                raise HTTPException(status_code=409, detail="idempotency key conflict") from exc
        try:
            record = devices.get_device(device_id)
            push_relay.register_device(record.push_handle, registration.fcm_token)
        except (MobileDeviceError, httpx.HTTPError) as exc:
            if claim is not None:
                events.fail_mutation(
                    claim.mutation_id,
                    result=MutationResult(status_code=503, body={"detail": "mobile push unavailable"}),
                )
            raise HTTPException(status_code=503, detail="mobile push unavailable") from exc
        if claim is not None:
            events.complete_mutation(
                claim.mutation_id,
                result=MutationResult(status_code=204, body={}),
                events=(EventInput(
                    event_type="push.registered",
                    aggregate_type="device",
                    aggregate_id=device_id,
                    payload={},
                ),),
            )

    @app.delete("/mobile/v1/devices/{device_id}/push", status_code=204)
    async def revoke_push_token(
        device_id: str,
        request: Request,
        idempotency_key: str | None = Header(default=None, min_length=16, max_length=255, alias="Idempotency-Key"),
    ) -> None:
        await require_push_auth(request, device_id)
        if push_relay is None or devices is None:
            raise HTTPException(status_code=503, detail="mobile push unavailable")
        claim = None
        if events is not None:
            if idempotency_key is None:
                raise HTTPException(status_code=400, detail="Idempotency-Key is required")
            try:
                claim = events.reserve_mutation(
                    actor_id=device_id,
                    action="push.revoke",
                    key=idempotency_key,
                    body={"device_id": device_id},
                )
                replay = replay_mutation_result(claim)
                if replay is not None:
                    return None
            except IdempotencyConflict as exc:
                raise HTTPException(status_code=409, detail="idempotency key conflict") from exc
        try:
            record = devices.get_device(device_id)
            push_relay.revoke_device(record.push_handle)
        except (MobileDeviceError, httpx.HTTPError) as exc:
            if claim is not None:
                events.fail_mutation(
                    claim.mutation_id,
                    result=MutationResult(status_code=503, body={"detail": "mobile push unavailable"}),
                )
            raise HTTPException(status_code=503, detail="mobile push unavailable") from exc
        if claim is not None:
            events.complete_mutation(
                claim.mutation_id,
                result=MutationResult(status_code=204, body={}),
                events=(EventInput(
                    event_type="push.revoked",
                    aggregate_type="device",
                    aggregate_id=device_id,
                    payload={},
                ),),
            )

    @app.post(
        "/mobile/v1/step-up/challenges",
        response_model=StepUpChallengeResponse,
        status_code=201,
    )
    async def create_step_up_challenge(
        body: StepUpChallengeRequest,
        request: Request,
    ) -> StepUpChallengeResponse:
        if request_authorizer is None or step_up is None:
            raise HTTPException(status_code=503, detail="mobile step-up unavailable")
        required_scope = {
            "settings.step_up.write": "settings:write:safe",
            "settings.rollback": "settings:write:safe",
            "approvals.approve_once": "approvals",
            "routines.run": "routines:control",
        }.get(body.action)
        if required_scope is None:
            raise HTTPException(status_code=400, detail="unsupported step-up action")
        identity = request_authorizer.authorize(request, scope=required_scope)
        try:
            challenge = step_up.create(
                device_id=identity.device.device_id,
                action=body.action,
                context=body.context,
            )
        except (DeviceNotAuthorized, ValueError) as exc:
            raise HTTPException(status_code=403, detail="step-up authorization is invalid") from exc
        return StepUpChallengeResponse(
            challenge_id=challenge.challenge_id,
            action=challenge.action,
            context_digest=challenge.context_digest,
            nonce=challenge.nonce,
            expires_at=challenge.expires_at,
        )

    @app.get(
        "/mobile/v1/profiles/{opaque_profile_id}/conversations",
        response_model=ConversationsResponse,
    )
    async def list_conversations(
        opaque_profile_id: UUID,
        request: Request,
    ) -> ConversationsResponse:
        _, profile_name = await resolve_profile_auth(request, opaque_profile_id, scope="chat")
        if chat is None:
            raise HTTPException(status_code=503, detail="mobile chat unavailable")
        conversations = await asyncio.to_thread(chat.import_conversations, profile_name)
        return ConversationsResponse(
            conversations=tuple(
                ConversationResponse(
                    conversation_id=conversation.conversation_id,
                    canonical=conversation.canonical,
                    title=conversation.title,
                    revision=conversation.revision,
                    updated_at=conversation.updated_at,
                )
                for conversation in conversations
            )
        )

    @app.post(
        "/mobile/v1/profiles/{opaque_profile_id}/conversations",
        response_model=ConversationResponse,
        status_code=201,
    )
    async def create_conversation(
        opaque_profile_id: UUID,
        body: NewConversationRequest,
        request: Request,
        idempotency_key: str = Header(
            min_length=16,
            max_length=255,
            alias="Idempotency-Key",
        ),
    ) -> ConversationResponse:
        identity, profile_name = await resolve_profile_auth(request, opaque_profile_id, scope="chat")
        if chat is None or events is None:
            raise HTTPException(status_code=503, detail="mobile chat unavailable")
        claim = reserve_mutation(
            actor_id=identity.device.device_id,
            action="conversation.create",
            key=idempotency_key,
            body={"profile": str(opaque_profile_id), "canonical": body.canonical},
        )
        replay = replay_mutation_result(claim)
        if replay is not None:
            return ConversationResponse(**replay)
        try:
            conversation = await asyncio.to_thread(
                chat.new_conversation,
                profile_name,
                canonical=body.canonical,
            )
        except BaseException:
            events.mark_indeterminate(
                claim.mutation_id,
                reason="conversation_create_failure",
                event=EventInput(
                    event_type="mutation.indeterminate",
                    aggregate_type="mutation",
                    aggregate_id=claim.mutation_id,
                    payload={
                        "mutation_id": claim.mutation_id,
                        "action": "conversation.create",
                        "reason": "conversation_create_failure",
                        "profile_id": str(opaque_profile_id),
                    },
                ),
            )
            raise
        result = MutationResult(
            status_code=201,
            body={
                "conversation_id": str(conversation.conversation_id),
                "canonical": conversation.canonical,
                "title": conversation.title,
                "revision": conversation.revision,
                "updated_at": conversation.updated_at,
            },
        )
        events.complete_mutation(
            claim.mutation_id,
            result=result,
            events=(
                EventInput(
                    event_type="conversation.created",
                    aggregate_type="conversation",
                    aggregate_id=str(conversation.conversation_id),
                    payload={"profile": str(opaque_profile_id)},
                ),
            ),
        )
        return ConversationResponse(**result.body)

    @app.get(
        "/mobile/v1/profiles/{opaque_profile_id}/conversations/{conversation_id}/messages",
        response_model=ConversationHistoryResponse,
    )
    async def conversation_history(
        opaque_profile_id: UUID,
        conversation_id: UUID,
        request: Request,
    ) -> ConversationHistoryResponse:
        _, profile_name = await resolve_profile_auth(request, opaque_profile_id, scope="chat")
        if chat is None:
            raise HTTPException(status_code=503, detail="mobile chat unavailable")
        try:
            messages = await asyncio.to_thread(chat.history, profile_name, conversation_id)
        except ConversationNotFound as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        return ConversationHistoryResponse(
            messages=tuple(
                ConversationMessageResponse(
                    message_id=message.message_id,
                    conversation_id=message.conversation_id,
                    role=message.role,
                    parts=(
                        (
                            {"type": "toolEvent", "summary": message.tool_summary}
                            if message.role == "tool"
                            else {"type": "text", "text": message.text}
                        ),
                    ),
                    created_at=message.created_at,
                )
                for message in messages
            )
        )

    @app.post(
        "/mobile/v1/profiles/{opaque_profile_id}/conversations/{conversation_id}/messages",
        response_model=ChatSendResponse,
    )
    async def send_chat_message(
        opaque_profile_id: UUID,
        conversation_id: UUID,
        body: ChatSendRequest,
        request: Request,
        idempotency_key: str = Header(
            min_length=16,
            max_length=255,
            alias="Idempotency-Key",
        ),
    ) -> ChatSendResponse:
        identity, profile_name = await resolve_profile_auth(request, opaque_profile_id, scope="chat")
        if chat is None:
            raise HTTPException(status_code=503, detail="mobile chat unavailable")
        attachment_ids = tuple(str(value) for value in body.attachment_ids)
        if attachment_ids and (attachments is None or events is None):
            raise HTTPException(status_code=503, detail="mobile attachment service unavailable")
        try:
            # Reserve the durable message mutation before any attachment
            # binding.  A conflicting retry therefore fails before it can
            # leave a new message-to-file association behind.
            claim = await asyncio.to_thread(
                chat.reserve_send_mutation,
                profile_name=profile_name,
                conversation_id=conversation_id,
                device_id=identity.device.device_id,
                idempotency_key=idempotency_key,
                text=body.text,
                attachment_ids=attachment_ids,
            )
        except ConversationNotFound as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        except IdempotencyConflict as exc:
            raise HTTPException(status_code=409, detail="idempotency key conflict") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid mobile message") from exc
        except RuntimeError as exc:
            status = 503 if "executor is unavailable" in str(exc) else 409
            raise HTTPException(status_code=status, detail="mobile message unavailable") from exc

        replay = replay_mutation_result(claim)
        if replay is not None:
            if replay.get("state") != "completed":
                state = str(replay.get("state") or "indeterminate")
                raise HTTPException(status_code=409, detail=f"mobile_message_{state}")
            return ChatSendResponse(**replay)

        attachments_bound = False

        def rollback_attachment_bindings() -> None:
            if not attachments_bound or attachments is None:
                return
            try:
                attachments.detach_from_message(
                    attachment_ids,
                    access_subject=identity.access.subject,
                    device_id=identity.device.device_id,
                    conversation_id=str(conversation_id),
                    message_id=idempotency_key,
                )
            except Exception:
                # A failed rollback must not hide the original deterministic
                # error; the attachment cleanup job can reap the binding once
                # the mutation is durably marked failed.
                _LOGGER.warning("Hermes mobile attachment rollback failed", exc_info=True)

        if attachment_ids:
            if attachments is None:
                if events is not None:
                    events.fail_mutation(
                        claim.mutation_id,
                        result=MutationResult(status_code=503, body={"detail": "mobile attachment service unavailable"}),
                    )
                raise HTTPException(status_code=503, detail="mobile attachment service unavailable")
            try:
                for attachment_id in attachment_ids:
                    attachments.get_attachment(
                        attachment_id,
                        access_subject=identity.access.subject,
                        device_id=identity.device.device_id,
                        conversation_id=str(conversation_id),
                    )
                # Bind the completed files before invoking Hermes.  The
                # idempotency key is an opaque durable message binding, so a
                # retry cannot create a second attachment association.
                attachments.attach_to_message(
                    attachment_ids,
                    access_subject=identity.access.subject,
                    device_id=identity.device.device_id,
                    conversation_id=str(conversation_id),
                    message_id=idempotency_key,
                )
                attachments_bound = True
            except MobileAttachmentError as exc:
                http_error = attachment_error(exc)
                if events is not None:
                    events.fail_mutation(
                        claim.mutation_id,
                        result=MutationResult(status_code=http_error.status_code, body={"detail": http_error.detail}),
                    )
                raise http_error from exc
        try:
            result = await asyncio.to_thread(
                chat.send,
                profile_name=profile_name,
                opaque_profile_id=str(opaque_profile_id),
                conversation_id=conversation_id,
                device_id=identity.device.device_id,
                access_subject=identity.access.subject,
                idempotency_key=idempotency_key,
                text=body.text,
                attachment_ids=attachment_ids,
                claim=claim,
            )
        except ConversationNotFound as exc:
            rollback_attachment_bindings()
            if events is not None:
                events.fail_mutation(
                    claim.mutation_id,
                    result=MutationResult(status_code=404, body={"detail": "mobile object not found"}),
                )
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        except IdempotencyConflict as exc:
            rollback_attachment_bindings()
            raise HTTPException(status_code=409, detail="idempotency key conflict") from exc
        except (ValueError, RuntimeError) as exc:
            # ``MobileChatService.send`` fences every failure after the durable
            # run row is created as indeterminate.  The attachment binding is
            # intentionally retained because an external tool may already have
            # observed it; the caller must inspect the run and retry explicitly
            # with a new idempotency key rather than resubmitting implicitly.
            raise HTTPException(status_code=409, detail="mobile_message_indeterminate") from exc
        if result.status_code != 200 or result.body.get("state") != "completed":
            state = str(result.body.get("state") or "indeterminate")
            raise HTTPException(status_code=409, detail=f"mobile_message_{state}")
        push_wake_hint(
            identity,
            event_type=MobilePushEvent.RUN_COMPLETED,
            event_id=str(result.body["run_id"]),
        )
        return ChatSendResponse(**result.body)

    @app.post("/mobile/v1/groups", response_model=GroupResponse, status_code=201)
    async def create_group(
        body: GroupCreateRequest,
        request: Request,
        idempotency_key: str = Header(min_length=16, max_length=255, alias="Idempotency-Key"),
    ) -> GroupResponse:
        if request_authorizer is None or objects is None or groups is None or events is None:
            raise HTTPException(status_code=503, detail="mobile group service unavailable")
        identity = request_authorizer.authorize(request, scope="groups")
        token_profiles = set(identity.device.token_claims.get("profiles", []))
        selections: list[BotSelection] = []
        opaque_profile_ids: list[str] = []
        try:
            for bot in body.bots:
                if bot.instance_id != objects.instance_id:
                    raise CrossInstanceGroupUnsupported("group members must belong to this Hermes instance")
                profile_name = objects.resolve_profile(bot.opaque_profile_id, token_profiles)
                selections.append(
                    BotSelection(
                        instance_id=str(objects.instance_id),
                        profile_id=profile_name,
                        display_name=f"Hermes bot {len(selections) + 1}",
                    )
                )
                opaque_profile_ids.append(str(objects.binding_for_profile(profile_name).opaque_profile_id))
        except HTTPException:
            raise
        except BaseException as exc:
            raise group_error(exc) from exc
        for opaque_profile_id in opaque_profile_ids:
            charge_profile_rate_limit(request, identity, opaque_profile_id)
        body_value = body.model_dump(mode="json")
        claim = reserve_mutation(
            actor_id=identity.device.device_id,
            action="group.create",
            key=idempotency_key,
            body=body_value,
        )
        replay = replay_mutation_result(claim)
        if replay is not None:
            return GroupResponse(**replay)
        try:
            snapshot = await asyncio.to_thread(
                groups.create_group,
                selections,
                owner_id=identity.access.subject,
                device_id=identity.device.device_id,
            )
            response = group_response(snapshot)
            result = MutationResult(status_code=201, body=response.model_dump(mode="json"))
            events.complete_mutation(
                claim.mutation_id,
                result=result,
                events=(
                    EventInput(
                        event_type="group.created",
                        aggregate_type="group",
                        aggregate_id=snapshot.group_id,
                        payload={
                            "profile_ids": list(group_profile_ids(snapshot)),
                            "member_count": len(snapshot.members),
                        },
                    ),
                ),
            )
            return response
        except HTTPException:
            events.fail_mutation(
                claim.mutation_id,
                result=MutationResult(status_code=404, body={"detail": "mobile object not found"}),
            )
            raise
        except BaseException as exc:
            http_error = group_error(exc)
            events.fail_mutation(
                claim.mutation_id,
                result=MutationResult(status_code=http_error.status_code, body={"detail": http_error.detail}),
            )
            raise http_error from exc

    @app.get("/mobile/v1/groups", response_model=GroupListResponse)
    async def list_groups(
        request: Request,
        cursor: str | None = Query(default=None, max_length=_GROUP_CURSOR_MAX_LENGTH),
    ) -> GroupListResponse:
        """Return only groups still owned by this device and profile grant.

        The coordinator query is owner/device scoped, then each snapshot is passed through the
        same member/profile authorization used by ``GET /groups/{id}``.  A group whose grant was
        narrowed or whose host profile disappeared is omitted as a whole rather than returned
        with a misleading partial membership list.
        """

        if request_authorizer is None or groups is None or objects is None:
            raise HTTPException(status_code=503, detail="mobile group service unavailable")
        identity = request_authorizer.authorize(request, scope="groups")
        page_size = _GROUP_LIST_PAGE_SIZE
        instance_id = str(objects.instance_id)
        try:
            after = _decode_group_cursor(
                cursor,
                key=_group_cursor_key(instance_id, cursor_secret),
                instance_id=instance_id,
                owner_id=identity.access.subject,
                device_id=identity.device.device_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid group cursor") from exc
        try:
            page = await asyncio.to_thread(
                groups.list_groups_page,
                owner_id=identity.access.subject,
                device_id=identity.device.device_id,
                after_created_at=None if after is None else after[0],
                after_group_id=None if after is None else after[1],
                limit=page_size,
            )
        except (MobileGroupError, ValueError) as exc:
            raise HTTPException(status_code=503, detail="mobile group service unavailable") from exc
        snapshots = page.groups
        visible: list[GroupResponse] = []
        for snapshot in snapshots:
            try:
                _, authorized = visible_group(request, identity, UUID(snapshot.group_id))
            except HTTPException as exc:
                if exc.status_code == 404:
                    continue
                raise
            try:
                visible.append(group_response(authorized))
            except (KeyError, TypeError, ValueError):
                # A host profile can disappear between the authorization lookup and response
                # serialization.  Omit the whole group rather than disclose a stale member.
                continue
        next_cursor = None
        if page.has_more:
            if page.next_created_at is None or page.next_group_id is None:
                raise HTTPException(status_code=503, detail="mobile group service unavailable")
            try:
                next_cursor = _encode_group_cursor(
                    key=_group_cursor_key(instance_id, cursor_secret),
                    instance_id=instance_id,
                    owner_id=identity.access.subject,
                    device_id=identity.device.device_id,
                    created_at=page.next_created_at,
                    group_id=page.next_group_id,
                )
            except ValueError as exc:
                raise HTTPException(status_code=503, detail="mobile group service unavailable") from exc
        return GroupListResponse(
            groups=tuple(visible),
            has_more=page.has_more,
            next_cursor=next_cursor,
        )

    @app.get("/mobile/v1/groups/{group_id}", response_model=GroupResponse)
    async def get_group(group_id: UUID, request: Request) -> GroupResponse:
        _, snapshot = await resolve_group_auth(request, group_id)
        return group_response(snapshot)

    @app.post("/mobile/v1/groups/{group_id}/stop", response_model=GroupResponse)
    async def stop_group(
        group_id: UUID,
        request: Request,
        idempotency_key: str = Header(min_length=16, max_length=255, alias="Idempotency-Key"),
    ) -> GroupResponse:
        identity, snapshot = await resolve_group_auth(request, group_id)
        if groups is None or events is None:
            raise HTTPException(status_code=503, detail="mobile group service unavailable")
        claim = reserve_mutation(
            actor_id=identity.device.device_id,
            action="group.stop",
            key=idempotency_key,
            body={"group_id": str(group_id)},
        )
        replay = replay_mutation_result(claim)
        if replay is not None:
            return GroupResponse(**replay)
        try:
            stopped = await asyncio.to_thread(groups.stop_group, str(group_id))
            response = group_response(stopped)
            result = MutationResult(status_code=200, body=response.model_dump(mode="json"))
            events.complete_mutation(
                claim.mutation_id,
                result=result,
                events=(EventInput(
                    event_type="group.stopped",
                    aggregate_type="group",
                    aggregate_id=str(group_id),
                    payload={
                        "profile_ids": list(group_profile_ids(snapshot)),
                        "reason": "user_stop",
                    },
                ),),
            )
            return response
        except BaseException as exc:
            http_error = group_error(exc)
            events.fail_mutation(
                claim.mutation_id,
                result=MutationResult(status_code=http_error.status_code, body={"detail": http_error.detail}),
            )
            raise http_error from exc

    @app.post("/mobile/v1/groups/{group_id}/members", response_model=GroupResponse)
    async def add_group_member(
        group_id: UUID,
        body: GroupMemberAddRequest,
        request: Request,
        if_match: str = Header(min_length=1, max_length=128, alias="If-Match"),
        idempotency_key: str = Header(min_length=16, max_length=255, alias="Idempotency-Key"),
    ) -> GroupResponse:
        identity, snapshot = await resolve_group_auth(request, group_id)
        if groups is None or objects is None or events is None:
            raise HTTPException(status_code=503, detail="mobile group service unavailable")
        if if_match != f'"group-{snapshot.authority_epoch}"':
            raise HTTPException(status_code=409, detail="group_revision_conflict")
        if body.bot.instance_id != objects.instance_id:
            raise HTTPException(status_code=422, detail="cross_instance_group_unsupported")
        try:
            profile_name = objects.resolve_profile(
                body.bot.opaque_profile_id,
                set(identity.device.token_claims.get("profiles", [])),
            )
        except (KeyError, TypeError) as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        opaque_profile_id = profile_marker_for_name(profile_name)
        if opaque_profile_id is not None:
            charge_profile_rate_limit(request, identity, opaque_profile_id)
        claim = reserve_mutation(
            actor_id=identity.device.device_id,
            action="group.member.add",
            key=idempotency_key,
            body={"group_id": str(group_id), "bot": body.model_dump(mode="json"), "if_match": if_match},
        )
        replay = replay_mutation_result(claim)
        if replay is not None:
            return GroupResponse(**replay)
        try:
            updated = await asyncio.to_thread(
                groups.add_member,
                str(group_id),
                BotSelection(str(objects.instance_id), profile_name, f"Hermes bot {len(snapshot.members) + 1}"),
                if_match=if_match,
            )
            response = group_response(updated)
            result = MutationResult(status_code=200, body=response.model_dump(mode="json"))
            events.complete_mutation(
                claim.mutation_id,
                result=result,
                events=(EventInput(
                    event_type="group.member_added",
                    aggregate_type="group",
                    aggregate_id=str(group_id),
                    payload={
                        "profile_ids": list(group_profile_ids(updated)),
                        "member_count": len(updated.members),
                    },
                ),),
            )
            return response
        except BaseException as exc:
            http_error = group_error(exc)
            events.fail_mutation(
                claim.mutation_id,
                result=MutationResult(status_code=http_error.status_code, body={"detail": http_error.detail}),
            )
            raise http_error from exc

    @app.delete("/mobile/v1/groups/{group_id}/members/{member_id}", response_model=GroupResponse)
    async def remove_group_member(
        group_id: UUID,
        member_id: UUID,
        request: Request,
        if_match: str = Header(min_length=1, max_length=128, alias="If-Match"),
        idempotency_key: str = Header(min_length=16, max_length=255, alias="Idempotency-Key"),
    ) -> GroupResponse:
        identity, snapshot = await resolve_group_auth(request, group_id)
        if groups is None or events is None:
            raise HTTPException(status_code=503, detail="mobile group service unavailable")
        if if_match != f'"group-{snapshot.authority_epoch}"':
            raise HTTPException(status_code=409, detail="group_revision_conflict")
        claim = reserve_mutation(
            actor_id=identity.device.device_id,
            action="group.member.remove",
            key=idempotency_key,
            body={"group_id": str(group_id), "member_id": str(member_id), "if_match": if_match},
        )
        replay = replay_mutation_result(claim)
        if replay is not None:
            return GroupResponse(**replay)
        try:
            updated = await asyncio.to_thread(
                groups.remove_member,
                str(group_id),
                str(member_id),
                if_match=if_match,
            )
            response = group_response(updated)
            result = MutationResult(status_code=200, body=response.model_dump(mode="json"))
            events.complete_mutation(
                claim.mutation_id,
                result=result,
                events=(EventInput(
                    event_type="group.member_removed",
                    aggregate_type="group",
                    aggregate_id=str(group_id),
                    payload={
                        "profile_ids": list(group_profile_ids(updated)),
                        "member_count": len(updated.members),
                    },
                ),),
            )
            return response
        except BaseException as exc:
            http_error = group_error(exc)
            events.fail_mutation(
                claim.mutation_id,
                result=MutationResult(status_code=http_error.status_code, body={"detail": http_error.detail}),
            )
            raise http_error from exc

    @app.post("/mobile/v1/groups/{group_id}/messages", response_model=GroupMessageResponse)
    async def send_group_message(
        group_id: UUID,
        body: GroupMessageRequest,
        request: Request,
        idempotency_key: str = Header(min_length=16, max_length=255, alias="Idempotency-Key"),
    ) -> GroupMessageResponse:
        identity, snapshot = await resolve_group_auth(request, group_id)
        if group_execution is None or events is None:
            raise HTTPException(status_code=503, detail="mobile group service unavailable")
        # Resolve event principals before the host turn begins. If a profile is deleted while
        # an external response is in flight, uncertainty handling must still be able to record
        # an opaque, profile-scoped event rather than failing while looking up a stale binding.
        event_profile_ids = group_profile_ids(snapshot)
        claim = reserve_mutation(
            actor_id=identity.device.device_id,
            action="group.message.send",
            key=idempotency_key,
            body=body.model_dump(mode="json") | {"group_id": str(group_id)},
        )
        replay = replay_mutation_result(claim)
        if replay is not None:
            return GroupMessageResponse(**replay)
        try:
            execution = await asyncio.to_thread(
                group_execution.run_turn,
                str(group_id),
                text=body.text,
                access_subject=identity.access.subject,
                mentioned_member_ids=tuple(str(value) for value in body.mentioned_member_ids),
            )
            execution_state = execution.turn.state.value
            if execution_state not in {"completed", "cancelled"}:
                # A group turn can already have been fenced by cancellation, lease
                # recovery, or another worker before this request observes it.  Do
                # not commit an indeterminate outcome as a successful idempotency
                # result: a client must inspect the durable run and choose any retry
                # explicitly with a new key.
                events.mark_indeterminate(
                    claim.mutation_id,
                    reason="group_execution_indeterminate",
                    event=EventInput(
                        event_type="group.turn.indeterminate",
                        aggregate_type="group",
                        aggregate_id=str(group_id),
                        payload={
                            "profile_ids": list(event_profile_ids),
                            "run_id": str(execution.turn.turn_id),
                            "response_count": len(execution.responses),
                            "reason": "group_execution_indeterminate",
                        },
                    ),
                )
                raise HTTPException(status_code=409, detail="turn_indeterminate")
            response = GroupMessageResponse(
                run_id=UUID(execution.turn.turn_id),
                state=execution_state,
                responses=tuple(
                    {"member_id": value.member_id, "text": value.text}
                    for value in execution.responses
                ),
            )
            result = MutationResult(status_code=200, body=response.model_dump(mode="json"))
            events.complete_mutation(
                claim.mutation_id,
                result=result,
                events=(EventInput(
                    event_type="group.turn.completed" if execution_state == "completed" else "group.turn.cancelled",
                    aggregate_type="group",
                    aggregate_id=str(group_id),
                    payload={
                        "profile_ids": list(event_profile_ids),
                        "run_id": str(execution.turn.turn_id),
                        "response_count": len(execution.responses),
                    },
                ),),
            )
            push_wake_hint(
                identity,
                event_type=(
                    MobilePushEvent.RUN_COMPLETED
                    if execution.turn.state.value == "completed"
                    else MobilePushEvent.RUN_FAILED
                ),
                event_id=str(execution.turn.turn_id),
            )
            return response
        except (ExecutionFenceLost, LeaseExpired) as exc:
            # A response claim may have crossed the host boundary before its lease/fence
            # became stale.  The turn executor already fenced the durable turn; keep the
            # HTTP mutation indeterminate so an idempotent retry cannot resubmit a possibly
            # completed external side effect.
            events.mark_indeterminate(
                claim.mutation_id,
                reason=exc.code,
                event=EventInput(
                    event_type="group.turn.indeterminate",
                    aggregate_type="group",
                    aggregate_id=str(group_id),
                    payload={
                        "profile_ids": list(event_profile_ids),
                        "reason": exc.code,
                    },
                ),
            )
            raise HTTPException(status_code=409, detail="turn_indeterminate") from exc
        except (ValueError, MobileGroupError) as exc:
            http_error = group_error(exc)
            events.fail_mutation(
                claim.mutation_id,
                result=MutationResult(status_code=http_error.status_code, body={"detail": http_error.detail}),
            )
            raise http_error from exc
        except HTTPException:
            # The route itself has already fenced a durable indeterminate result;
            # do not run the generic uncertainty handler a second time.
            raise
        except BaseException as exc:
            events.mark_indeterminate(claim.mutation_id, reason="group_execution_failure")
            raise HTTPException(status_code=409, detail="turn_indeterminate") from exc

    def identity_has_scope(identity: MobileRequestIdentity, required: str) -> bool:
        granted = set()
        if identity.device.scope:
            granted.add(identity.device.scope)
        raw_scope = identity.device.token_claims.get("scope")
        if isinstance(raw_scope, str):
            granted.update(raw_scope.split())
        elif isinstance(raw_scope, (tuple, list, set, frozenset)):
            granted.update(value for value in raw_scope if isinstance(value, str))
        return required in granted

    def direct_run_response(run: Any) -> DirectRunResponse:
        return DirectRunResponse(
            run_id=run.run_id,
            conversation_id=run.conversation_id,
            state=run.state,
            text=run.text,
            error=run.error,
            created_at=run.created_at,
            updated_at=run.updated_at,
            cancel_requested=bool(getattr(run, "cancel_requested", False)),
            completed_external_side_effects_not_undone=bool(
                getattr(run, "completed_external_side_effects_not_undone", False)
            ),
        )

    def direct_run_profile_marker(run: Any) -> str | None:
        """Recover the opaque profile marker for profile-scoped run events."""

        if objects is None:
            return None
        profile_name = getattr(run, "profile_name", None)
        if not isinstance(profile_name, str) or not profile_name:
            return None
        try:
            return str(objects.binding_for_profile(profile_name).opaque_profile_id)
        except (KeyError, TypeError, ValueError):
            # A stale mapping must not turn a cancellation response into a
            # broader profile disclosure.  The run itself remains authorized
            # by the device-scoped lookup above.
            return None

    def direct_run_visible(identity: MobileRequestIdentity, run: Any) -> bool:
        """Require a direct run's profile to remain in the current token grant."""

        profile_name = getattr(run, "profile_name", None)
        token_profiles = identity.device.token_claims.get("profiles", ())
        if not isinstance(profile_name, str) or not isinstance(
            token_profiles,
            (list, tuple, set, frozenset),
        ):
            return False
        if profile_name not in token_profiles or not profile_is_live(profile_name):
            return False
        if objects is not None:
            try:
                objects.binding_for_profile(profile_name)
            except (KeyError, TypeError, ValueError):
                return False
        return True

    @app.get(
        "/mobile/v1/profiles/{opaque_profile_id}/conversations/{conversation_id}/message-status",
        response_model=DirectMessageStatusResponse,
    )
    async def get_message_status(
        opaque_profile_id: UUID,
        conversation_id: UUID,
        request: Request,
        response: Response,
        idempotency_key: str = Header(min_length=16, max_length=255, alias="Idempotency-Key"),
    ) -> DirectMessageStatusResponse:
        """Read the direct-send run associated with an original request key."""

        if chat is None:
            raise HTTPException(status_code=503, detail="mobile chat service unavailable")
        identity, profile_name = await resolve_profile_auth(
            request,
            opaque_profile_id,
            scope="chat",
        )
        # A status lookup is a recovery aid and must never be cached: an older
        # unknown response must not hide a run that was created shortly after.
        response.headers["Cache-Control"] = "no-store"
        try:
            run = await asyncio.to_thread(
                chat.message_status,
                profile_name,
                conversation_id,
                device_id=identity.device.device_id,
                access_subject=identity.access.subject,
                idempotency_key=idempotency_key,
            )
        except ConversationNotFound as exc:
            raise HTTPException(status_code=404, detail="mobile object not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid mobile message status request") from exc
        if run is None:
            return DirectMessageStatusResponse(request_state="unknown", run=None)
        if not direct_run_visible(identity, run):
            raise HTTPException(status_code=404, detail="mobile object not found")
        return DirectMessageStatusResponse(
            request_state="run_found",
            run=direct_run_response(run),
        )

    @app.get(
        "/mobile/v1/runs/{run_id}",
        response_model=GroupRunResponse | DirectRunResponse,
    )
    async def get_run(run_id: UUID, request: Request) -> GroupRunResponse | DirectRunResponse:
        if request_authorizer is None:
            raise HTTPException(status_code=503, detail="mobile run service unavailable")
        # Authenticate once without a scope so a DPoP proof is never consumed twice while
        # dispatching between the direct and group run stores.
        identity = request_authorizer.authorize(request)
        if chat is not None and identity_has_scope(identity, "chat"):
            try:
                run = await asyncio.to_thread(
                    chat.get_run,
                    run_id,
                    device_id=identity.device.device_id,
                    access_subject=identity.access.subject,
                )
            except ConversationNotFound:
                pass
            else:
                # A device token can outlive a host profile deletion.  Do not return a
                # previously authorized run once its profile binding has been invalidated.
                if not direct_run_visible(identity, run):
                    raise HTTPException(status_code=404, detail="mobile object not found")
                opaque_profile_id = direct_run_profile_marker(run)
                if opaque_profile_id is not None:
                    charge_profile_rate_limit(request, identity, opaque_profile_id)
                return direct_run_response(run)
        if groups is not None and identity_has_scope(identity, "groups"):
            try:
                turn = groups.get_turn(str(run_id))
                visible_group(request, identity, UUID(turn.group_id))
            except (MobileGroupError, ValueError) as exc:
                raise group_error(exc) from exc
            return GroupRunResponse(
                run_id=UUID(turn.turn_id),
                group_id=UUID(turn.group_id),
                state=turn.state.value,
                response_count=turn.response_count,
                cancel_requested=turn.cancel_requested,
                completed_external_side_effects_not_undone=turn.completed_side_effects_not_undone,
            )
        raise HTTPException(status_code=404, detail="mobile object not found")

    @app.get(
        "/mobile/v1/runs/{run_id}/events",
        response_model=GroupEventsResponse | DirectRunEventsResponse,
    )
    async def get_run_events(run_id: UUID, request: Request) -> GroupEventsResponse | DirectRunEventsResponse:
        if request_authorizer is None:
            raise HTTPException(status_code=503, detail="mobile run service unavailable")
        identity = request_authorizer.authorize(request)
        if chat is not None and identity_has_scope(identity, "chat"):
            try:
                chat_run = await asyncio.to_thread(
                    chat.get_run,
                    run_id,
                    device_id=identity.device.device_id,
                    access_subject=identity.access.subject,
                )
            except ConversationNotFound:
                pass
            else:
                if not direct_run_visible(identity, chat_run):
                    raise HTTPException(status_code=404, detail="mobile object not found")
                opaque_profile_id = direct_run_profile_marker(chat_run)
                if opaque_profile_id is not None:
                    charge_profile_rate_limit(request, identity, opaque_profile_id)
                try:
                    rows = await asyncio.to_thread(chat.events_for_run, run_id)
                except (ConversationNotFound, MobileEventStoreError) as exc:
                    raise HTTPException(status_code=404, detail="mobile object not found") from exc
                return DirectRunEventsResponse(
                    events=tuple(
                        {
                            "cursor": event.cursor,
                            "event_id": event.event_id,
                            "event_type": event.event_type,
                            "aggregate_type": event.aggregate_type,
                            "aggregate_id": event.aggregate_id,
                            "payload": dict(event.payload),
                            "created_at": event.created_at,
                            "tombstone": event.tombstone,
                        }
                        for event in rows
                    )
                )
        if groups is not None and identity_has_scope(identity, "groups"):
            try:
                turn = groups.get_turn(str(run_id))
                visible_group(request, identity, UUID(turn.group_id))
                rows = groups.list_events(turn.group_id, turn_id=turn.turn_id)
            except (MobileGroupError, ValueError) as exc:
                raise group_error(exc) from exc
            return GroupEventsResponse(
                events=tuple(
                    {
                        "event_id": event.event_id,
                        "event_type": event.event_type,
                        "payload": dict(event.payload),
                        "provenance": event.provenance.value,
                        "created_at": event.created_at,
                    }
                    for event in rows
                )
            )
        raise HTTPException(status_code=404, detail="mobile object not found")

    @app.post(
        "/mobile/v1/runs/{run_id}/cancel",
        response_model=GroupRunResponse | DirectRunResponse | RoutineRunResponse,
    )
    async def cancel_group_run(
        run_id: UUID,
        request: Request,
        idempotency_key: str = Header(min_length=16, max_length=255, alias="Idempotency-Key"),
    ) -> GroupRunResponse | DirectRunResponse | RoutineRunResponse:
        if request_authorizer is None or events is None:
            raise HTTPException(status_code=503, detail="mobile run service unavailable")
        identity = request_authorizer.authorize(request)
        if chat is not None and identity_has_scope(identity, "chat"):
            try:
                direct = await asyncio.to_thread(
                    chat.get_run,
                    run_id,
                    device_id=identity.device.device_id,
                    access_subject=identity.access.subject,
                )
            except ConversationNotFound:
                pass
            else:
                # A direct run may already have reached a terminal state by
                # the time the cancellation request arrives.  It is still
                # owned by this device and must not fall through to the group
                # lookup (which would incorrectly return 404).
                if not direct_run_visible(identity, direct):
                    raise HTTPException(status_code=404, detail="mobile object not found")
                opaque_profile_id = direct_run_profile_marker(direct)
                if opaque_profile_id is not None:
                    charge_profile_rate_limit(request, identity, opaque_profile_id)
                if direct.state not in {"queued", "thinking"}:
                    return direct_run_response(direct)
                if direct.state in {"queued", "thinking"}:
                    claim = reserve_mutation(
                        actor_id=identity.device.device_id,
                        action="direct.run.cancel",
                        key=idempotency_key,
                        body={"run_id": str(run_id)},
                    )
                    replay = replay_mutation_result(claim)
                    if replay is not None:
                        return DirectRunResponse(**replay)
                    try:
                        direct = await asyncio.to_thread(
                            chat.cancel_run,
                            run_id,
                            device_id=identity.device.device_id,
                            access_subject=identity.access.subject,
                            opaque_profile_id=direct_run_profile_marker(direct),
                        )
                        response = direct_run_response(direct)
                        events.complete_mutation(
                            claim.mutation_id,
                            result=MutationResult(
                                status_code=200,
                                body=response.model_dump(mode="json"),
                            ),
                        )
                        push_wake_hint(
                            identity,
                            event_type=MobilePushEvent.RUN_FAILED,
                            event_id=str(run_id),
                        )
                        return response
                    except ConversationNotFound as exc:
                        events.mark_indeterminate(
                            claim.mutation_id,
                            reason="direct_cancel_lookup_failure",
                        )
                        raise HTTPException(status_code=409, detail="direct_run_indeterminate") from exc
                    except BaseException as exc:
                        events.fail_mutation(
                            claim.mutation_id,
                            result=MutationResult(
                                status_code=409,
                                body={"detail": "direct_run_cancellation_failed"},
                            ),
                        )
                        raise HTTPException(
                            status_code=409,
                            detail="direct_run_cancellation_failed",
                        ) from exc
                return direct_run_response(direct)
        if routines is not None and identity_has_scope(identity, "routines:control"):
            try:
                routine_run = await asyncio.to_thread(routines.get_run, str(run_id))
            except RoutineNotFound:
                pass
            else:
                # A routine run may share the UUID shape used by direct/group
                # runs. Once found, never fall through to another store: an
                # unauthorized routine must remain a 404 and cannot be
                # confused with a different run type.
                if (
                    routine_run.actor_id != identity.device.device_id
                    or routine_run.profile_id not in set(identity.device.token_claims.get("profiles", []))
                    or not profile_is_live(routine_run.profile_id)
                ):
                    raise HTTPException(status_code=404, detail="mobile object not found")
                if routine_run.status != "pending":
                    return RoutineRunResponse(
                        run_id=UUID(routine_run.run_id),
                        routine_id=UUID(routine_run.routine_id),
                        state=routine_run.status,
                        result=routine_run.result,
                    )
                opaque_profile_id = profile_marker_for_name(routine_run.profile_id)
                if opaque_profile_id is not None:
                    charge_profile_rate_limit(request, identity, opaque_profile_id)
                claim = reserve_mutation(
                    actor_id=identity.device.device_id,
                    action="routine.run.cancel",
                    key=idempotency_key,
                    body={"run_id": str(run_id)},
                )
                replay = replay_mutation_result(claim)
                if replay is not None:
                    return RoutineRunResponse(**replay)
                try:
                    routine_run = await asyncio.to_thread(
                        routines.cancel,
                        str(run_id),
                        actor_id=identity.device.device_id,
                    )
                    response = RoutineRunResponse(
                        run_id=UUID(routine_run.run_id),
                        routine_id=UUID(routine_run.routine_id),
                        state=routine_run.status,
                        result=routine_run.result,
                    )
                    events.complete_mutation(
                        claim.mutation_id,
                        result=MutationResult(
                            status_code=200,
                            body=response.model_dump(mode="json"),
                        ),
                        events=(EventInput(
                            event_type=(
                                "routine.run.cancelled"
                                if routine_run.status == "cancelled"
                                else "routine.run.indeterminate"
                            ),
                            aggregate_type="routine_run",
                            aggregate_id=str(run_id),
                            payload={
                                "profile_id": str(opaque_profile_id) if opaque_profile_id else "",
                                "routine_id": str(routine_run.routine_id),
                                "state": routine_run.status,
                            },
                        ),),
                    )
                    push_wake_hint(
                        identity,
                        event_type=MobilePushEvent.RUN_FAILED,
                        event_id=str(run_id),
                    )
                    return response
                except RoutineNotFound as exc:
                    events.mark_indeterminate(
                        claim.mutation_id,
                        reason="routine_cancel_lookup_failure",
                    )
                    raise HTTPException(status_code=409, detail="routine_run_indeterminate") from exc
                except RoutineConflict as exc:
                    # A worker may have won the pending->terminal race. The
                    # cancellation itself is a deterministic conflict, not an
                    # uncertain external side effect.
                    events.fail_mutation(
                        claim.mutation_id,
                        result=MutationResult(
                            status_code=409,
                            body={"detail": "routine_run_conflict"},
                        ),
                    )
                    raise HTTPException(status_code=409, detail="routine_run_conflict") from exc
                except BaseException as exc:
                    events.fail_mutation(
                        claim.mutation_id,
                        result=MutationResult(
                            status_code=409,
                            body={"detail": "routine_run_cancellation_failed"},
                        ),
                    )
                    raise HTTPException(
                        status_code=409,
                        detail="routine_run_cancellation_failed",
                    ) from exc
        if groups is None or not identity_has_scope(identity, "groups"):
            raise HTTPException(status_code=404, detail="mobile object not found")
        try:
            current = groups.get_turn(str(run_id))
            _, group_snapshot = visible_group(request, identity, UUID(current.group_id))
        except (MobileGroupError, ValueError) as exc:
            raise group_error(exc) from exc
        claim = reserve_mutation(
            actor_id=identity.device.device_id,
            action="group.run.cancel",
            key=idempotency_key,
            body={"run_id": str(run_id)},
        )
        replay = replay_mutation_result(claim)
        if replay is not None:
            return GroupRunResponse(**replay)
        try:
            turn = await asyncio.to_thread(groups.cancel_turn, str(run_id))
            response = GroupRunResponse(
                run_id=UUID(turn.turn_id),
                group_id=UUID(turn.group_id),
                state=turn.state.value,
                response_count=turn.response_count,
                cancel_requested=turn.cancel_requested,
                completed_external_side_effects_not_undone=turn.completed_side_effects_not_undone,
            )
            result = MutationResult(status_code=200, body=response.model_dump(mode="json"))
            events.complete_mutation(
                claim.mutation_id,
                result=result,
                events=(EventInput(
                    event_type=(
                        "run.cancelled"
                        if turn.state.value == "cancelled"
                        else "run.indeterminate"
                        if turn.state.value == "indeterminate"
                        else "run.completed"
                    ),
                    aggregate_type="run",
                    aggregate_id=str(run_id),
                    payload={
                        "profile_ids": list(group_profile_ids(group_snapshot)),
                        "group_id": str(turn.group_id),
                        "state": turn.state.value,
                    },
                ),),
            )
            push_wake_hint(
                identity,
                event_type=MobilePushEvent.RUN_FAILED,
                event_id=str(run_id),
            )
            return response
        except BaseException as exc:
            http_error = group_error(exc)
            events.fail_mutation(
                claim.mutation_id,
                result=MutationResult(status_code=http_error.status_code, body={"detail": http_error.detail}),
            )
            raise http_error from exc

    @app.post(
        "/mobile/v1/attachments",
        response_model=AttachmentUploadResponse,
        status_code=201,
    )
    async def declare_attachment(
        body: AttachmentDeclarationRequest,
        request: Request,
        idempotency_key: str = Header(min_length=16, max_length=255, alias="Idempotency-Key"),
    ) -> AttachmentUploadResponse:
        if attachments is None or events is None:
            raise HTTPException(status_code=503, detail="mobile attachment service unavailable")
        identity, _ = await resolve_attachment_auth(
            request,
            instance_id=body.bot.instance_id,
            opaque_profile_id=body.bot.opaque_profile_id,
            conversation_id=body.conversation_id,
        )
        request_body = body.model_dump(mode="json")
        claim = reserve_mutation(
            actor_id=identity.device.device_id,
            action="attachment.declare",
            key=idempotency_key,
            body=request_body,
        )
        replay = replay_mutation_result(claim)
        if replay is not None:
            return AttachmentUploadResponse(**replay)
        try:
            upload = await asyncio.to_thread(
                attachments.declare_upload,
                access_subject=identity.access.subject,
                device_id=identity.device.device_id,
                conversation_id=str(body.conversation_id),
                expected_size=body.size,
                expected_sha256=body.sha256,
                mime_type=body.mime_type,
                display_name=body.filename,
            )
        except MobileAttachmentError as exc:
            http_error = attachment_error(exc)
            events.fail_mutation(
                claim.mutation_id,
                result=MutationResult(
                    status_code=http_error.status_code,
                    body={"detail": http_error.detail},
                ),
            )
            raise http_error from exc
        result = MutationResult(
            status_code=201,
            body={
                "upload_id": upload.upload_id,
                "chunk_size": upload.chunk_size,
                "received_bytes": upload.received_bytes,
                "next_offset": upload.next_offset,
                "state": upload.state,
            },
        )
        events.complete_mutation(
            claim.mutation_id,
            result=result,
            events=(
                EventInput(
                    event_type="attachment.upload_declared",
                    aggregate_type="attachment_upload",
                    aggregate_id=upload.upload_id,
                    payload={
                        "profile_id": str(body.bot.opaque_profile_id),
                        "conversation_id": str(body.conversation_id),
                    },
                ),
            ),
        )
        return AttachmentUploadResponse(**result.body)

    @app.put(
        "/mobile/v1/attachments/{upload_id}",
        response_model=AttachmentUploadResponse,
    )
    async def put_attachment_chunk(
        upload_id: UUID,
        request: Request,
        content_range: str = Header(alias="Content-Range"),
        instance_id: UUID = Header(alias="X-Hermes-Instance-Id"),
        opaque_profile_id: UUID = Header(alias="X-Hermes-Profile-Id"),
        conversation_id: UUID = Header(alias="X-Hermes-Conversation-Id"),
        idempotency_key: str = Header(min_length=16, max_length=255, alias="Idempotency-Key"),
    ) -> AttachmentUploadResponse:
        if attachments is None or events is None:
            raise HTTPException(status_code=503, detail="mobile attachment service unavailable")
        identity, _ = await resolve_attachment_auth(
            request,
            instance_id=instance_id,
            opaque_profile_id=opaque_profile_id,
            conversation_id=conversation_id,
        )
        payload = bytearray()
        async for chunk in request.stream():
            # Check before extending the buffer so a malicious client cannot
            # force one oversized ASGI chunk into memory before the 413 path.
            if len(payload) + len(chunk) > attachments.chunk_size:
                raise HTTPException(status_code=413, detail="attachment chunk is too large")
            payload.extend(chunk)
        claim = reserve_mutation(
            actor_id=identity.device.device_id,
            action=f"attachment.chunk.{upload_id}",
            key=idempotency_key,
            body={
                "content_range": content_range,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "conversation_id": str(conversation_id),
            },
        )
        replay = replay_mutation_result(claim)
        if replay is not None:
            return AttachmentUploadResponse(**replay)
        try:
            upload = await asyncio.to_thread(
                attachments.upload_chunk,
                upload_id,
                content_range,
                bytes(payload),
                access_subject=identity.access.subject,
                device_id=identity.device.device_id,
                conversation_id=str(conversation_id),
            )
        except MobileAttachmentError as exc:
            http_error = attachment_error(exc)
            events.fail_mutation(
                claim.mutation_id,
                result=MutationResult(status_code=http_error.status_code, body={"detail": http_error.detail}),
            )
            raise http_error from exc
        result = MutationResult(
            status_code=200,
            body={
                "upload_id": upload.upload_id,
                "chunk_size": upload.chunk_size,
                "received_bytes": upload.received_bytes,
                "next_offset": upload.next_offset,
                "state": upload.state,
            },
        )
        events.complete_mutation(claim.mutation_id, result=result)
        return AttachmentUploadResponse(**result.body)

    @app.post(
        "/mobile/v1/attachments/{upload_id}/complete",
        response_model=AttachmentCompleteResponse,
    )
    async def complete_attachment(
        upload_id: UUID,
        request: Request,
        body: AttachmentCompletionRequest | None = Body(default=None),
        instance_id: UUID = Header(alias="X-Hermes-Instance-Id"),
        opaque_profile_id: UUID = Header(alias="X-Hermes-Profile-Id"),
        conversation_id: UUID = Header(alias="X-Hermes-Conversation-Id"),
        idempotency_key: str = Header(min_length=16, max_length=255, alias="Idempotency-Key"),
    ) -> AttachmentCompleteResponse:
        if attachments is None or events is None:
            raise HTTPException(status_code=503, detail="mobile attachment service unavailable")
        identity, _ = await resolve_attachment_auth(
            request,
            instance_id=instance_id,
            opaque_profile_id=opaque_profile_id,
            conversation_id=conversation_id,
        )
        completion_body: dict[str, Any] = {
            "upload_id": str(upload_id),
            "conversation_id": str(conversation_id),
            "total_bytes": None,
            "sha256": None,
        }
        if body is not None:
            try:
                declared = await asyncio.to_thread(
                    attachments.get_upload,
                    upload_id,
                    access_subject=identity.access.subject,
                    device_id=identity.device.device_id,
                    conversation_id=str(conversation_id),
                )
            except MobileAttachmentError as exc:
                raise attachment_error(exc) from exc
            if body.total_bytes != declared.expected_size or body.sha256.lower() != declared.expected_sha256:
                raise HTTPException(status_code=409, detail="attachment_declaration_conflict")
            completion_body.update(
                total_bytes=body.total_bytes,
                sha256=body.sha256.lower(),
            )
        claim = reserve_mutation(
            actor_id=identity.device.device_id,
            action=f"attachment.complete.{upload_id}",
            key=idempotency_key,
            body=completion_body,
        )
        replay = replay_mutation_result(claim)
        if replay is not None:
            return AttachmentCompleteResponse(**replay)
        try:
            attachment = await asyncio.to_thread(
                attachments.finalize_upload,
                upload_id,
                access_subject=identity.access.subject,
                device_id=identity.device.device_id,
                conversation_id=str(conversation_id),
            )
        except MobileAttachmentError as exc:
            http_error = attachment_error(exc)
            events.fail_mutation(
                claim.mutation_id,
                result=MutationResult(status_code=http_error.status_code, body={"detail": http_error.detail}),
            )
            raise http_error from exc
        result = MutationResult(
            status_code=200,
            body={
                "attachment_id": attachment.attachment_id,
                "size": attachment.size,
                "sha256": attachment.sha256,
                "mime_type": attachment.mime_type,
                "filename": attachment.display_name,
            },
        )
        events.complete_mutation(
            claim.mutation_id,
            result=result,
            events=(
                EventInput(
                    event_type="attachment.completed",
                    aggregate_type="attachment",
                    aggregate_id=attachment.attachment_id,
                    payload={
                        "profile_id": str(opaque_profile_id),
                        "conversation_id": str(conversation_id),
                    },
                ),
            ),
        )
        return AttachmentCompleteResponse(**result.body)

    return app


@contextmanager
def running_mobile_listener(
    *,
    host: str,
    port: int,
    authorize: Authorizer | None = None,
    sync_authorize: Authorizer | None = None,
    profiles_authorize: Authorizer | None = None,
    events_authorize: Authorizer | None = None,
    push_authorize: Authorizer | None = None,
    access_authorize: Authorizer | None = None,
    devices: MobileDeviceStore | None = None,
    events: MobileEventStore | None = None,
    objects: MobileObjectRegistry | None = None,
    allowed_profiles: tuple[str, ...] = (),
    profile_liveness: Callable[[str], bool] | None = None,
    sse_heartbeat_seconds: float = 15.0,
    sse_max_lifetime_seconds: float = 300.0,
    push_relay: MobilePushRelayClient | None = None,
    request_authorizer: MobileRequestAuthorizer | None = None,
    chat: MobileChatService | None = None,
    attachments: MobileAttachmentStore | None = None,
    groups: MobileGroupCoordinator | None = None,
    group_execution: MobileGroupExecutionService | None = None,
    settings: MobileSettingsStore | None = None,
    approvals: MobileApprovalStore | None = None,
    catalog: MobileCatalog | None = None,
    routines: MobileRoutineService | None = None,
    routine_worker: MobileRoutineWorker | None = None,
    cursor_secret: bytes | None = None,
    step_up: MobileStepUpStore | None = None,
):
    """Run the isolated app in a sibling thread for the lifetime of ``serve``."""

    import uvicorn

    app = create_mobile_app(
        authorize=authorize,
        sync_authorize=sync_authorize,
        profiles_authorize=profiles_authorize,
        events_authorize=events_authorize,
        push_authorize=push_authorize,
        access_authorize=access_authorize,
        devices=devices,
        events=events,
        objects=objects,
        allowed_profiles=allowed_profiles,
        profile_liveness=profile_liveness,
        sse_heartbeat_seconds=sse_heartbeat_seconds,
        sse_max_lifetime_seconds=sse_max_lifetime_seconds,
        push_relay=push_relay,
        request_authorizer=request_authorizer,
        chat=chat,
        attachments=attachments,
        groups=groups,
        group_execution=group_execution,
        settings=settings,
        approvals=approvals,
        catalog=catalog,
        routines=routines,
        routine_worker=routine_worker,
        cursor_secret=cursor_secret,
        step_up=step_up,
    )
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="warning",
        proxy_headers=False,
        forwarded_allow_ips=None,
    )
    bound_socket = config.bind_socket()
    actual_port = int(bound_socket.getsockname()[1])
    server = uvicorn.Server(config)
    attachment_cleanup_thread = None
    attachment_cleanup_stop = None
    if attachments is not None:
        attachment_cleanup_stop = threading.Event()
        attachment_cleanup_thread = threading.Thread(
            target=_run_mobile_attachment_cleanup,
            args=(attachments, attachment_cleanup_stop),
            name="hermes-mobile-attachment-cleanup",
            daemon=True,
        )
    thread = threading.Thread(
        target=server.run,
        kwargs={"sockets": [bound_socket]},
        name="hermes-mobile-listener",
        daemon=True,
    )
    listener = RunningMobileListener(
        host,
        actual_port,
        server,
        thread,
        bound_socket,
        attachment_cleanup_thread,
        attachment_cleanup_stop,
        routine_worker,
    )
    if attachment_cleanup_thread is not None:
        attachment_cleanup_thread.start()
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        listener.close()
        raise RuntimeError("mobile listener failed to start")

    try:
        yield listener
    finally:
        listener.close()
