package com.hermes.mobile.contract

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Server-issued identifiers are opaque. The client may display labels, but labels are never
 * accepted in place of these values for routing or authorization.
 */
object OpaqueId {
    private val allowed = Regex("^[A-Za-z0-9_-]{8,256}$")

    fun require(value: String, field: String): String {
        require(allowed.matches(value)) {
            "$field must be an opaque URL-safe identifier"
        }
        return value
    }
}

@Serializable
data class BotId(
    @SerialName("instance_id")
    val instanceId: String,
    @SerialName("opaque_profile_id")
    val opaqueProfileId: String,
) {
    init {
        OpaqueId.require(instanceId, "instanceId")
        OpaqueId.require(opaqueProfileId, "opaqueProfileId")
    }
}

@Serializable
data class ConversationId(val value: String) {
    init {
        OpaqueId.require(value, "conversationId")
    }
}

@Serializable
data class RunId(val value: String) {
    init {
        OpaqueId.require(value, "runId")
    }
}

@Serializable
data class MessageId(val value: String) {
    init {
        OpaqueId.require(value, "messageId")
    }
}

@Serializable
data class IdempotencyKey(val value: String) {
    init {
        OpaqueId.require(value, "idempotencyKey")
    }
}

@Serializable
enum class ConversationKind {
    @SerialName("direct") DIRECT,
    @SerialName("group") GROUP,
}

@Serializable
enum class RunState {
    @SerialName("queued") QUEUED,
    @SerialName("thinking") THINKING,
    @SerialName("toolRunning") TOOL_RUNNING,
    @SerialName("waitingForUser") WAITING_FOR_USER,
    @SerialName("approvalRequired") APPROVAL_REQUIRED,
    @SerialName("completed") COMPLETED,
    @SerialName("failed") FAILED,
    @SerialName("cancelled") CANCELLED,
    @SerialName("indeterminate") INDETERMINATE,
}

@Serializable
enum class TransportState {
    @SerialName("connected") CONNECTED,
    @SerialName("stale") STALE,
    @SerialName("disconnected") DISCONNECTED,
    @SerialName("authExpired") AUTH_EXPIRED,
}

@Serializable
enum class AttentionState {
    @SerialName("none") NONE,
    @SerialName("unread") UNREAD,
    @SerialName("needsApproval") NEEDS_APPROVAL,
    @SerialName("needsAnswer") NEEDS_ANSWER,
    @SerialName("failed") FAILED,
}

@Serializable
sealed class MessagePart {
    @Serializable
    @SerialName("text")
    data class Text(val text: String) : MessagePart()

    @Serializable
    @SerialName("link")
    data class Link(val url: String, val title: String? = null) : MessagePart()

    @Serializable
    @SerialName("image")
    data class Image(val attachmentId: String, val altText: String? = null) : MessagePart() {
        init {
            OpaqueId.require(attachmentId, "attachmentId")
        }
    }

    @Serializable
    @SerialName("file")
    data class File(val attachmentId: String, val displayName: String? = null) : MessagePart() {
        init {
            OpaqueId.require(attachmentId, "attachmentId")
        }
    }

    @Serializable
    @SerialName("audio")
    data class Audio(
        val attachmentId: String,
        val durationMs: Long,
        val transcript: String? = null,
    ) : MessagePart() {
        init {
            OpaqueId.require(attachmentId, "attachmentId")
            require(durationMs >= 0) { "audio duration must not be negative" }
        }
    }

    @Serializable
    @SerialName("toolEvent")
    data class ToolEvent(
        val eventId: String,
        val label: String,
        val state: String,
    ) : MessagePart() {
        init {
            OpaqueId.require(eventId, "eventId")
        }
    }

    @Serializable
    @SerialName("approval")
    data class Approval(
        val requestId: String,
        val title: String,
        val expiresAtEpochMillis: Long,
    ) : MessagePart() {
        init {
            OpaqueId.require(requestId, "requestId")
            require(expiresAtEpochMillis >= 0) { "approval expiry must not be negative" }
        }
    }

    @Serializable
    @SerialName("artifact")
    data class Artifact(
        val artifactId: String,
        val displayName: String,
        val mimeType: String,
    ) : MessagePart() {
        init {
            OpaqueId.require(artifactId, "artifactId")
        }
    }
}

@Serializable
data class ConversationSummary(
    val bot: BotId,
    val conversationId: ConversationId,
    val kind: ConversationKind,
    val title: String? = null,
    val revision: Long,
    val updatedAtEpochMillis: Long,
)

@Serializable
data class RunSummary(
    val bot: BotId,
    val conversationId: ConversationId,
    val runId: RunId,
    val state: RunState,
    val transport: TransportState,
    val attention: AttentionState,
    val revision: Long,
    val updatedAtEpochMillis: Long,
)

@Serializable
data class SyncCursor(val value: Long) {
    init {
        require(value >= 0) { "cursor must not be negative" }
    }
}
