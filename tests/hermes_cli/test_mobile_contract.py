from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError

from hermes_cli.mobile_models import (
    AttentionState,
    BotId,
    ConversationKind,
    ConversationState,
    MobileMessage,
    RunState,
    TransportState,
)


def test_bot_identity_requires_opaque_instance_and_profile_ids() -> None:
    bot = BotId(instance_id=uuid4(), opaque_profile_id=uuid4())

    assert bot.instance_id != bot.opaque_profile_id
    with pytest.raises(ValidationError):
        BotId(instance_id="my-nas", opaque_profile_id="../../default")


def test_conversation_keeps_execution_transport_and_attention_independent() -> None:
    state = ConversationState(
        conversation_id=uuid4(),
        kind=ConversationKind.DIRECT,
        run_state=RunState.TOOL_RUNNING,
        transport_state=TransportState.STALE,
        attention_state=AttentionState.NEEDS_APPROVAL,
        revision=7,
    )

    assert state.run_state is RunState.TOOL_RUNNING
    assert state.transport_state is TransportState.STALE
    assert state.attention_state is AttentionState.NEEDS_APPROVAL
    assert state.revision == 7


def test_message_parts_are_typed_and_never_accept_server_paths() -> None:
    message = MobileMessage.model_validate(
        {
            "message_id": str(uuid4()),
            "conversation_id": str(uuid4()),
            "parts": [
                {"type": "text", "text": "hello"},
                {"type": "link", "url": "https://example.test/path"},
                {"type": "file", "attachment_id": str(uuid4())},
            ],
        }
    )

    assert [part.type for part in message.parts] == ["text", "link", "file"]
    with pytest.raises(ValidationError):
        MobileMessage.model_validate(
            {
                "message_id": str(uuid4()),
                "conversation_id": str(uuid4()),
                "parts": [{"type": "file", "path": "/etc/passwd"}],
            }
        )
