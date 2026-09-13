"""Stable, versioned wire models shared by Hermes mobile API services."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Union
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class ConversationKind(StrEnum):
    DIRECT = "direct"
    GROUP = "group"


class MessagePartKind(StrEnum):
    TEXT = "text"
    LINK = "link"
    IMAGE = "image"
    FILE = "file"
    AUDIO = "audio"
    TOOL_EVENT = "toolEvent"
    APPROVAL = "approval"
    ARTIFACT = "artifact"


class RunState(StrEnum):
    QUEUED = "queued"
    THINKING = "thinking"
    TOOL_RUNNING = "toolRunning"
    WAITING_FOR_USER = "waitingForUser"
    APPROVAL_REQUIRED = "approvalRequired"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INDETERMINATE = "indeterminate"


class TransportState(StrEnum):
    CONNECTED = "connected"
    STALE = "stale"
    DISCONNECTED = "disconnected"
    AUTH_EXPIRED = "authExpired"


class AttentionState(StrEnum):
    NONE = "none"
    UNREAD = "unread"
    NEEDS_APPROVAL = "needsApproval"
    NEEDS_ANSWER = "needsAnswer"
    FAILED = "failed"


class _WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class BotId(_WireModel):
    instance_id: UUID
    opaque_profile_id: UUID


class ConversationState(_WireModel):
    conversation_id: UUID
    kind: ConversationKind
    run_state: RunState
    transport_state: TransportState
    attention_state: AttentionState
    revision: int = Field(ge=0)


class TextPart(_WireModel):
    type: Literal["text"] = "text"
    text: str = Field(min_length=1, max_length=200_000)


class LinkPart(_WireModel):
    type: Literal["link"] = "link"
    url: HttpUrl


class ImagePart(_WireModel):
    type: Literal["image"] = "image"
    attachment_id: UUID


class FilePart(_WireModel):
    type: Literal["file"] = "file"
    attachment_id: UUID


class AudioPart(_WireModel):
    type: Literal["audio"] = "audio"
    attachment_id: UUID


class ToolEventPart(_WireModel):
    type: Literal["toolEvent"] = "toolEvent"
    event_id: UUID
    summary: str = Field(min_length=1, max_length=2_000)


class ApprovalPart(_WireModel):
    type: Literal["approval"] = "approval"
    approval_id: UUID
    summary: str = Field(min_length=1, max_length=2_000)


class ArtifactPart(_WireModel):
    type: Literal["artifact"] = "artifact"
    artifact_id: UUID
    label: str = Field(min_length=1, max_length=256)


MessagePart = Annotated[
    Union[
        TextPart,
        LinkPart,
        ImagePart,
        FilePart,
        AudioPart,
        ToolEventPart,
        ApprovalPart,
        ArtifactPart,
    ],
    Field(discriminator="type"),
]


class MobileMessage(_WireModel):
    message_id: UUID
    conversation_id: UUID
    parts: tuple[MessagePart, ...] = Field(min_length=1, max_length=64)
