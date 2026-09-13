package com.hermes.mobile.network

import com.hermes.mobile.contract.OpaqueId
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

/** Machine-readable error codes understood by the direct-send recovery state machine. */
object MobileApiErrorCodes {
    const val IDEMPOTENCY_KEY_CONFLICT = "idempotency_key_conflict"
    const val MESSAGE_INDETERMINATE = "mobile_message_indeterminate"
}

@Serializable
data class AttachmentBotId(
    @SerialName("instance_id") val instanceId: String,
    @SerialName("opaque_profile_id") val opaqueProfileId: String,
) {
    init {
        OpaqueId.require(instanceId, "instanceId")
        OpaqueId.require(opaqueProfileId, "opaqueProfileId")
    }
}

@Serializable
data class SyncEventWire(
    val cursor: Long,
    @SerialName("event_id")
    val eventId: String,
    @SerialName("event_type")
    val eventType: String,
    val payload: JsonElement,
    @SerialName("created_at") val createdAtEpochSeconds: Double,
    @SerialName("aggregate_type")
    val aggregateType: String = "",
    @SerialName("aggregate_id")
    val aggregateId: String = "",
    val tombstone: Boolean = false,
) {
    init {
        require(cursor >= 0) { "sync event cursor must not be negative" }
        OpaqueId.require(eventId, "eventId")
        require(eventType.isNotBlank() && eventType.length <= 128) {
            "sync event type is invalid"
        }
        require(createdAtEpochSeconds >= 0) { "sync event timestamp must not be negative" }
    }
}

@Serializable
data class SyncBatch(
    @SerialName("next_cursor") val cursor: Long,
    @SerialName("events")
    val events: List<SyncEventWire> = emptyList(),
    @SerialName("retained_floor") val retainedFloor: Long = 0,
    @SerialName("latest_cursor") val latestCursor: Long = cursor,
    @SerialName("has_more") val hasMore: Boolean = false,
    @SerialName("snapshot_required") val snapshotRequired: Boolean = false,
) {
    init {
        require(cursor >= 0) { "sync cursor must not be negative" }
        require(events.zipWithNext().all { (left, right) -> left.cursor < right.cursor }) {
            "sync events must be strictly ordered"
        }
        require(events.all { it.cursor <= cursor }) {
            "sync event exceeds response cursor"
        }
    }
}

class CursorExpiredException : IllegalStateException("sync cursor expired; full snapshot required")

@Serializable
data class AttachmentDeclaration(
    val bot: AttachmentBotId,
    @SerialName("conversation_id") val conversationId: String,
    val filename: String,
    val size: Long,
    @SerialName("mime_type") val mimeType: String,
    val sha256: String,
) {
    init {
        require(filename.isNotBlank() && filename.length <= 255 && filename.none { it.isISOControl() })
        require(size in 1..(25L * 1024L * 1024L))
        require(mimeType.isNotBlank() && mimeType.length <= 128 && mimeType.none { it.isISOControl() })
        require(sha256.matches(Regex("^[0-9a-fA-F]{64}$")))
        OpaqueId.require(conversationId, "conversationId")
    }
}

@Serializable
data class AttachmentDeclarationResponse(
    @SerialName("upload_id") val uploadId: String,
    @SerialName("chunk_size") val chunkBytes: Long,
    @SerialName("received_bytes") val receivedBytes: Long,
    @SerialName("next_offset") val nextByte: Long,
    val state: String,
)

@Serializable
data class AttachmentChunkResponse(
    @SerialName("upload_id") val uploadId: String,
    @SerialName("chunk_size") val chunkBytes: Long,
    @SerialName("received_bytes") val receivedBytes: Long,
    @SerialName("next_offset") val nextByte: Long,
    val state: String,
)

@Serializable
data class AttachmentCompletionResponse(
    @SerialName("attachment_id") val attachmentId: String,
    val size: Long,
    val sha256: String,
    @SerialName("mime_type") val mimeType: String,
    val filename: String,
)

@Serializable
data class FcmRegistrationRequest(
    @SerialName("fcm_token")
    val token: String,
)

@Serializable
data class MobileProfileWire(
    val bot: AttachmentBotId,
    val label: String,
)

@Serializable
data class MobileProfilesResponse(
    val profiles: List<MobileProfileWire> = emptyList(),
)

@Serializable
data class ConversationWire(
    @SerialName("conversation_id") val conversationId: String,
    val canonical: Boolean,
    val title: String,
    val revision: Long,
    @SerialName("updated_at") val updatedAtEpochSeconds: Double,
)

@Serializable
data class ConversationsResponse(
    val conversations: List<ConversationWire> = emptyList(),
)

@Serializable
data class ConversationMessageWire(
    @SerialName("message_id") val messageId: String,
    @SerialName("conversation_id") val conversationId: String,
    val role: String,
    val parts: List<JsonElement> = emptyList(),
    @SerialName("created_at") val createdAtEpochSeconds: Double,
)

@Serializable
data class ConversationHistoryResponse(
    val messages: List<ConversationMessageWire> = emptyList(),
)

@Serializable
data class MessageStatusResponse(
    @SerialName("request_state") val requestState: String,
    val run: RunWire? = null,
) {
    init {
        require(requestState == "unknown" || requestState == "run_found") {
            "message status request state is invalid"
        }
    }
}

@Serializable
data class ChatSendRequest(
    val text: String,
    @SerialName("attachment_ids") val attachmentIds: List<String> = emptyList(),
) {
    init {
        require(text.isNotBlank() && text.length <= 32_000)
        require(attachmentIds.size <= 6)
        attachmentIds.forEach { OpaqueId.require(it, "attachmentId") }
        require(attachmentIds.distinct().size == attachmentIds.size) {
            "attachment IDs must be unique"
        }
    }
}

@Serializable
data class ChatSendResponse(
    @SerialName("run_id") val runId: String,
    val state: String,
    val text: String,
)

@Serializable
data class GroupCreateRequest(
    val bots: List<AttachmentBotId>,
) {
    init {
        require(bots.size in 2..6) { "a group must contain between 2 and 6 bots" }
        require(bots.distinct().size == bots.size) { "group bots must be unique" }
        require(bots.map { it.instanceId }.distinct().size == 1) {
            "group bots must belong to one Hermes instance"
        }
    }
}

@Serializable
data class GroupMemberWire(
    @SerialName("member_id") val memberId: String,
    val bot: AttachmentBotId,
    val label: String,
    val ordinal: Int,
) {
    init {
        OpaqueId.require(memberId, "memberId")
        require(label.isNotBlank() && label.length <= 256 && label.none { it.isISOControl() }) {
            "group member label is invalid"
        }
        require(ordinal in 0..5) { "group member ordinal is invalid" }
    }
}

@Serializable
data class GroupResponse(
    @SerialName("group_id") val groupId: String,
    @SerialName("instance_id") val instanceId: String,
    val members: List<GroupMemberWire>,
    @SerialName("coordinator_member_id") val coordinatorMemberId: String,
    val state: String,
    @SerialName("authority_epoch") val authorityEpoch: Long,
    @SerialName("active_turn_id") val activeTurnId: String? = null,
) {
    init {
        OpaqueId.require(groupId, "groupId")
        OpaqueId.require(instanceId, "instanceId")
        require(members.size in 2..6) { "group member count is invalid" }
        OpaqueId.require(coordinatorMemberId, "coordinatorMemberId")
        require(state == "active" || state == "stopped") { "group state is invalid" }
        require(authorityEpoch >= 1) { "group authority epoch is invalid" }
        activeTurnId?.let { OpaqueId.require(it, "activeTurnId") }
        require(members.map { it.memberId }.distinct().size == members.size) {
            "group member IDs must be unique"
        }
        require(members.map { it.bot }.distinct().size == members.size) {
            "group bot identities must be unique"
        }
        require(members.map { it.ordinal }.distinct().size == members.size) {
            "group member ordinals must be unique"
        }
        require(members.map { it.ordinal }.sorted() == (0 until members.size).toList()) {
            "group member ordinals must be contiguous"
        }
        require(members.any { it.memberId == coordinatorMemberId }) {
            "group coordinator must be a member"
        }
        require(members.all { it.bot.instanceId == instanceId }) {
            "group members must belong to the group instance"
        }
    }
}

@Serializable
data class GroupListResponse(
    val groups: List<GroupResponse> = emptyList(),
    @SerialName("has_more") val hasMore: Boolean = false,
    @SerialName("next_cursor") val nextCursor: String? = null,
)

@Serializable
data class GroupMemberAddRequest(val bot: AttachmentBotId)

@Serializable
data class GroupMessageRequest(
    val text: String,
    @SerialName("mentioned_member_ids") val mentionedMemberIds: List<String> = emptyList(),
) {
    init {
        require(text.isNotBlank() && text.length <= 200_000) {
            "group message text is invalid"
        }
        require(mentionedMemberIds.size <= 6) { "too many mentioned group members" }
        mentionedMemberIds.forEach { OpaqueId.require(it, "mentionedMemberId") }
        require(mentionedMemberIds.distinct().size == mentionedMemberIds.size) {
            "mentioned member IDs must be unique"
        }
    }
}

@Serializable
data class GroupBotResponseWire(
    @SerialName("member_id") val memberId: String,
    val text: String,
) {
    init {
        OpaqueId.require(memberId, "memberId")
        require(text.isNotBlank() && text.length <= 200_000) {
            "group response text is invalid"
        }
    }
}

@Serializable
data class GroupMessageResponse(
    @SerialName("run_id") val runId: String,
    val state: String,
    val responses: List<GroupBotResponseWire> = emptyList(),
) {
    init {
        OpaqueId.require(runId, "runId")
        require(state == "completed" || state == "cancelled" || state == "indeterminate") {
            "group message state is invalid"
        }
        require(responses.size <= 10) { "group response count exceeds the host limit" }
    }
}

@Serializable
data class RunWire(
    @SerialName("run_id") val runId: String,
    @SerialName("group_id") val groupId: String? = null,
    @SerialName("conversation_id") val conversationId: String? = null,
    val state: String,
    @SerialName("response_count") val responseCount: Int = 0,
    @SerialName("cancel_requested") val cancelRequested: Boolean = false,
    @SerialName("completed_external_side_effects_not_undone")
    val completedExternalSideEffectsNotUndone: Boolean = false,
    val text: String? = null,
    val error: String? = null,
    @SerialName("created_at") val createdAtEpochSeconds: Double? = null,
    @SerialName("updated_at") val updatedAtEpochSeconds: Double? = null,
)

@Serializable
data class RunEventsResponse(
    val events: List<JsonElement> = emptyList(),
)

@Serializable
data class SettingsResponse(
    @SerialName("profile_id") val profileId: String,
    val revision: Long,
    val etag: String,
    @SerialName("display_name") val displayName: String,
    val title: String,
    val avatar: String,
    @SerialName("notification_preferences") val notificationPreferences: JsonElement,
    @SerialName("privacy_preferences") val privacyPreferences: JsonElement,
    @SerialName("approval_policy") val approvalPolicy: JsonElement,
    val persona: String = "",
    val model: String = "",
    val provider: String = "",
    val reasoning: String = "",
    val skills: List<String> = emptyList(),
)

@Serializable
data class SettingsUpdateRequest(val changes: JsonElement)

/** Wire shape for the sensitive settings endpoint. */
@Serializable
data class SensitiveSettingsUpdateRequest(
    val changes: JsonElement,
    @SerialName("step_up") val stepUp: StepUpProofWire,
)

@Serializable
data class CatalogResponse(
    val revision: Long,
    val etag: String,
    val entries: List<JsonElement> = emptyList(),
)

@Serializable
data class RoutineWire(
    @SerialName("routine_id") val routineId: String,
    val label: String,
    val summary: String,
    val paused: Boolean,
    val revision: Long,
    val etag: String,
) {
    init {
        OpaqueId.require(routineId, "routineId")
        require(label.isNotBlank() && label.length <= 160 && label.none { it.isISOControl() }) {
            "routine label is invalid"
        }
        require(summary.length <= 512 && summary.none { it.isISOControl() }) {
            "routine summary is invalid"
        }
        require(revision >= 1) { "routine revision is invalid" }
        require(etag.isNotBlank() && etag.length <= 128 && etag.none { it.isISOControl() }) {
            "routine etag is invalid"
        }
    }
}

@Serializable
data class RoutineListResponse(val routines: List<RoutineWire> = emptyList())

@Serializable
data class RoutinePauseRequest(val paused: Boolean)

@Serializable
data class RoutineRunRequest(
    val input: JsonElement? = null,
    @SerialName("step_up") val stepUp: StepUpProofWire,
)

@Serializable
data class RoutineRunResponse(
    @SerialName("run_id") val runId: String,
    @SerialName("routine_id") val routineId: String,
    val state: String,
    val result: JsonElement? = null,
) {
    init {
        OpaqueId.require(runId, "runId")
        OpaqueId.require(routineId, "routineId")
        require(
            state == "pending" || state == "completed" || state == "failed" ||
                state == "indeterminate" || state == "cancelled",
        ) { "routine run state is invalid" }
    }
}

@Serializable
data class StepUpProofWire(
    @SerialName("challenge_id") val challengeId: String,
    val action: String,
    @SerialName("context_digest") val contextDigest: String,
    val nonce: String,
    @SerialName("expires_at") val expiresAtEpochSeconds: Double,
    val signature: String,
)

@Serializable
data class StepUpChallengeRequest(
    val action: String,
    val context: JsonElement,
)

@Serializable
data class StepUpChallengeResponse(
    @SerialName("challenge_id") val challengeId: String,
    val action: String,
    @SerialName("context_digest") val contextDigest: String,
    val nonce: String,
    @SerialName("expires_at") val expiresAtEpochSeconds: Double,
)

@Serializable
data class ApprovalWire(
    @SerialName("approval_id") val approvalId: String,
    val summary: String,
    val status: String,
    @SerialName("expires_at") val expiresAtEpochSeconds: Double,
    @SerialName("run_id") val runId: String,
    @SerialName("request_id") val requestId: String,
    @SerialName("tool_call_id") val toolCallId: String,
)

@Serializable
data class ApprovalsResponse(
    val approvals: List<ApprovalWire> = emptyList(),
)

@Serializable
data class DeviceEnrollmentRequest(
    @SerialName("device_label") val deviceLabel: String,
    @SerialName("background_jwk") val backgroundJwk: Map<String, String>,
    @SerialName("user_presence_jwk") val userPresenceJwk: Map<String, String>,
)

@Serializable
data class DeviceEnrollmentResponse(
    @SerialName("device_id") val deviceId: String,
    @SerialName("enrollment_code") val enrollmentCode: String,
    @SerialName("expires_at") val expiresAtEpochSeconds: Double,
)

@Serializable
data class DeviceTokenChallengeResponse(
    val nonce: String,
    @SerialName("expires_at") val expiresAtEpochSeconds: Double,
)

@Serializable
data class DeviceTokenRequest(
    val nonce: String,
    val signature: String,
)

@Serializable
data class DeviceTokenResponse(
    @SerialName("device_token") val deviceToken: String,
    @SerialName("expires_in") val expiresInSeconds: Int,
)

@Serializable
data class MobileDeviceWire(
    @SerialName("device_id") val deviceId: String,
    val label: String,
    val status: String,
    val profiles: List<AttachmentBotId> = emptyList(),
    val scopes: List<String> = emptyList(),
    @SerialName("created_at") val createdAtEpochSeconds: Double,
    @SerialName("approved_at") val approvedAtEpochSeconds: Double? = null,
    @SerialName("revoked_at") val revokedAtEpochSeconds: Double? = null,
)

@Serializable
data class MobileDevicesResponse(val devices: List<MobileDeviceWire> = emptyList())

data class ContentRange(
    val start: Long,
    val endInclusive: Long,
    val total: Long,
) {
    init {
        require(start >= 0 && endInclusive >= start && total > endInclusive) {
            "content range is invalid"
        }
    }

    val length: Long get() = endInclusive - start + 1

    fun headerValue(): String = "bytes $start-$endInclusive/$total"

    companion object {
        fun forChunk(start: Long, length: Long, total: Long): ContentRange {
            require(length > 0)
            require(start <= Long.MAX_VALUE - length + 1)
            return ContentRange(start, start + length - 1, total)
        }
    }
}
