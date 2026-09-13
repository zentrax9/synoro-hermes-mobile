package com.hermes.mobile.data

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index

/** IDs and revisions stay queryable; user text and filenames are encrypted blobs. */
@Entity(
    tableName = "conversations",
    primaryKeys = ["instanceId", "opaqueProfileId", "conversationId"],
)
data class ConversationEntity(
    val instanceId: String,
    val opaqueProfileId: String,
    val conversationId: String,
    val kind: String,
    @ColumnInfo(defaultValue = "0") val canonical: Boolean,
    val titleCiphertext: ByteArray?,
    val revision: Long,
    val updatedAtEpochMillis: Long,
)

@Entity(
    tableName = "messages",
    primaryKeys = ["instanceId", "opaqueProfileId", "conversationId", "messageId"],
)
data class MessageEntity(
    val instanceId: String,
    val opaqueProfileId: String,
    val conversationId: String,
    val messageId: String,
    val partsCiphertext: ByteArray,
    val deliveryState: String,
    val revision: Long,
    val createdAtEpochMillis: Long,
)

@Entity(
    tableName = "runs",
    primaryKeys = ["instanceId", "opaqueProfileId", "conversationId", "runId"],
)
data class RunEntity(
    val instanceId: String,
    val opaqueProfileId: String,
    val conversationId: String,
    val runId: String,
    val state: String,
    val transportState: String,
    val attentionState: String,
    val revision: Long,
    val updatedAtEpochMillis: Long,
    @ColumnInfo(defaultValue = "0") val cancelRequested: Boolean,
    @ColumnInfo(defaultValue = "0") val completedExternalSideEffectsNotUndone: Boolean,
)

/**
 * Prevents an older API/SSE observation from reopening a terminal run in the local projection.
 * Event cursors and host timestamps are monotonic inputs, but the foreground status fallback can
 * complete out of order, so the merge is performed inside the caller's Room transaction.
 */
internal fun mergeRunProjection(
    current: RunEntity,
    requested: RunEntity,
): RunEntity {
    require(current.instanceId == requested.instanceId)
    require(current.opaqueProfileId == requested.opaqueProfileId)
    require(current.conversationId == requested.conversationId)
    require(current.runId == requested.runId)

    val currentState = current.state.lowercase()
    val requestedState = requested.state.lowercase()
    val currentTerminal = currentState in RUN_TERMINAL_STATES
    val requestedTerminal = requestedState in RUN_TERMINAL_STATES
    val resolvesIndeterminate = currentState == "indeterminate" &&
        requestedState != "indeterminate" &&
        (requested.revision > current.revision ||
            requested.updatedAtEpochMillis > current.updatedAtEpochMillis)
    val applyState = when {
        currentTerminal && !resolvesIndeterminate -> false
        resolvesIndeterminate -> true
        requestedTerminal -> true
        current.cancelRequested -> false
        requestedStateRank(requestedState) > requestedStateRank(currentState) -> true
        requestedStateRank(requestedState) == requestedStateRank(currentState) &&
            requested.revision >= current.revision -> true
        else -> false
    }
    return current.copy(
        state = if (applyState) requested.state else current.state,
        transportState = if (applyState) requested.transportState else current.transportState,
        attentionState = if (applyState) requested.attentionState else current.attentionState,
        revision = maxOf(current.revision, requested.revision),
        updatedAtEpochMillis = maxOf(current.updatedAtEpochMillis, requested.updatedAtEpochMillis),
        cancelRequested = current.cancelRequested || requested.cancelRequested,
        completedExternalSideEffectsNotUndone =
            current.completedExternalSideEffectsNotUndone ||
                requested.completedExternalSideEffectsNotUndone,
    )
}

private val RUN_TERMINAL_STATES = setOf(
    "completed",
    "failed",
    "cancelled",
    "canceled",
    "indeterminate",
)

private fun requestedStateRank(state: String): Int = when (state) {
    "queued" -> 0
    "thinking" -> 1
    "tool_running", "toolrunning", "tool-running" -> 2
    "waiting_for_user", "waitingforuser", "waiting-for-user" -> 3
    "approval_required", "approvalrequired", "approval-required" -> 4
    else -> -1
}

@Entity(
    tableName = "drafts",
    primaryKeys = ["instanceId", "opaqueProfileId", "conversationId"],
)
data class DraftEntity(
    val instanceId: String,
    val opaqueProfileId: String,
    val conversationId: String,
    val draftCiphertext: ByteArray,
    val revision: Long,
    val updatedAtEpochMillis: Long,
)

@Entity(
    tableName = "idempotency_keys",
    primaryKeys = ["instanceId", "opaqueProfileId", "conversationId", "scope", "idempotencyKey"],
)
data class IdempotencyEntity(
    val instanceId: String,
    val opaqueProfileId: String,
    val conversationId: String,
    val scope: String,
    val idempotencyKey: String,
    val requestBodyCiphertext: ByteArray,
    val createdAtEpochMillis: Long,
)

/** Account/device secrets are encrypted and intentionally not included in any backup set. */
@Entity(
    tableName = "session_secrets",
    primaryKeys = ["instanceId", "opaqueProfileId", "secretKind"],
)
data class SessionSecretEntity(
    val instanceId: String,
    val opaqueProfileId: String,
    val secretKind: String,
    val valueCiphertext: ByteArray,
    val updatedAtEpochMillis: Long,
)

@Entity(
    tableName = "auth_transactions",
    primaryKeys = ["transactionId"],
)
data class AuthenticationTransactionEntity(
    val transactionId: String,
    val payloadCiphertext: ByteArray,
    val createdAtEpochMillis: Long,
    val expiresAtEpochMillis: Long,
)

@Entity(
    tableName = "staged_attachments",
    primaryKeys = ["uploadId"],
)
data class StagedAttachmentEntity(
    val uploadId: String,
    val metadataCiphertext: ByteArray,
    val createdAtEpochMillis: Long,
    val expiresAtEpochMillis: Long,
    val plaintextBytes: Long,
)

/** Monotonic replay cursor for one instance/profile reconciliation stream. */
@Entity(
    tableName = "sync_cursors",
    primaryKeys = ["instanceId", "opaqueProfileId"],
)
data class SyncCursorEntity(
    val instanceId: String,
    val opaqueProfileId: String,
    val cursor: Long,
    val updatedAtEpochMillis: Long,
)

/** Durable semantic events; token deltas are never persisted here. */
@Entity(
    tableName = "sync_events",
    primaryKeys = ["instanceId", "opaqueProfileId", "cursor", "eventId"],
)
data class SyncEventEntity(
    val instanceId: String,
    val opaqueProfileId: String,
    val cursor: Long,
    val eventId: String,
    val eventType: String,
    @ColumnInfo(defaultValue = "''") val aggregateType: String,
    @ColumnInfo(defaultValue = "''") val aggregateId: String,
    @ColumnInfo(defaultValue = "0") val tombstone: Boolean,
    val payloadCiphertext: ByteArray,
    val createdAtEpochMillis: Long,
)

/** The last explicitly selected conversation for one approved instance/profile. */
@Entity(
    tableName = "selected_conversations",
    primaryKeys = ["instanceId", "opaqueProfileId"],
)
data class SelectedConversationEntity(
    val instanceId: String,
    val opaqueProfileId: String,
    val conversationId: String,
    val updatedAtEpochMillis: Long,
)

/** Durable mutation metadata; request bytes and ETags remain encrypted in their source rows. */
@Entity(
    tableName = "mobile_operations",
    primaryKeys = ["instanceId", "opaqueProfileId", "operationId"],
    indices = [
        Index(
            value = ["instanceId", "opaqueProfileId", "conversationId", "kind"],
            name = "index_mobile_operations_target_conversation_kind",
        ),
        Index(
            value = ["instanceId", "opaqueProfileId", "state"],
            name = "index_mobile_operations_target_state",
        ),
    ],
)
data class MobileOperationEntity(
    val instanceId: String,
    val opaqueProfileId: String,
    val operationId: String,
    val kind: String,
    val conversationId: String,
    val resourceId: String?,
    val idempotencyScope: String,
    val idempotencyKey: String,
    val originalEtagCiphertext: ByteArray?,
    val state: String,
    val runId: String?,
    val cancelRequested: Boolean,
    val completedExternalSideEffectsNotUndone: Boolean,
    val createdAtEpochMillis: Long,
    val updatedAtEpochMillis: Long,
)

/** Upload declaration and progress survive process death; no mutation is retried implicitly. */
@Entity(tableName = "upload_sessions")
data class UploadSessionEntity(
    @androidx.room.PrimaryKey val uploadId: String,
    val instanceId: String,
    val opaqueProfileId: String,
    val conversationId: String,
    val stagedUploadId: String,
    val declarationBodyCiphertext: ByteArray,
    val declarationIdempotencyKey: String,
    val completionIdempotencyKey: String,
    val serverUploadId: String?,
    val chunkBytes: Long,
    val nextByte: Long,
    val totalBytes: Long,
    val status: String,
    val updatedAtEpochMillis: Long,
)

/** FCM token is encrypted; registrationId is a local constant, not a provider credential. */
@Entity(tableName = "fcm_registrations")
data class FcmRegistrationEntity(
    @androidx.room.PrimaryKey val registrationId: String,
    val tokenCiphertext: ByteArray,
    val updatedAtEpochMillis: Long,
)

/** Exact approval mutation material retained until the server confirms the decision. */
@Entity(
    tableName = "approval_mutations",
    primaryKeys = ["approvalId", "action"],
)
data class ApprovalMutationEntity(
    val approvalId: String,
    val action: String,
    val idempotencyKey: String,
    val proofCiphertext: ByteArray,
    val createdAtEpochMillis: Long,
)

/** Opaque group identity retained so a process restart can re-fetch server-owned membership. */
@Entity(
    tableName = "group_caches",
    primaryKeys = ["instanceId", "groupId"],
)
data class GroupCacheEntity(
    val instanceId: String,
    val groupId: String,
    val anchorProfileId: String,
    val updatedAtEpochMillis: Long,
)
