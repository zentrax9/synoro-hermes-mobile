package com.hermes.mobile.data

import androidx.room.withTransaction
import com.hermes.mobile.contract.IdempotencyKey
import com.hermes.mobile.security.EncryptedValue
import com.hermes.mobile.security.EncryptedValueStore
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/** Stable operation kinds used by the first-sprint recovery and control flows. */
object MobileOperationKinds {
    const val MESSAGE_SEND = "message.send"
    const val CONVERSATION_CREATE = "conversation.create"
    const val RUN_CANCEL = "run.cancel"
    const val ROUTINE_PAUSE = "routine.pause"
    const val ROUTINE_RESUME = "routine.resume"
}

/** Shared local lifecycle values so recovery code cannot accidentally treat an active run as final. */
object MobileOperationStates {
    const val PENDING = "pending"
    const val SENDING = "sending"
    const val QUEUED = "queued"
    const val THINKING = "thinking"
    const val TOOL_RUNNING = "tool_running"
    const val WAITING_FOR_USER = "waiting_for_user"
    const val APPROVAL_REQUIRED = "approval_required"
    const val UNCERTAIN = "uncertain"
    const val STOP_REQUESTED = "stop_requested"
    const val COMPLETED = "completed"
    const val FAILED = "failed"
    const val CANCELLED = "cancelled"
    const val INDETERMINATE = "indeterminate"
    const val REJECTED = "rejected"
    const val CONFLICT = "conflict"

    /** States that still own an encrypted request and must block a duplicate mutation. */
    val ACTIVE: Set<String> = setOf(
        PENDING,
        SENDING,
        QUEUED,
        THINKING,
        TOOL_RUNNING,
        WAITING_FOR_USER,
        APPROVAL_REQUIRED,
        UNCERTAIN,
        STOP_REQUESTED,
    )

    /** Run states that already crossed the send boundary and must never be replayed. */
    val RUN_ACTIVE: Set<String> = setOf(
        QUEUED,
        THINKING,
        TOOL_RUNNING,
        WAITING_FOR_USER,
        APPROVAL_REQUIRED,
        STOP_REQUESTED,
    )

    val TERMINAL: Set<String> = setOf(
        COMPLETED,
        FAILED,
        CANCELLED,
        "canceled",
        INDETERMINATE,
        REJECTED,
        CONFLICT,
    )

    /**
     * Durable outcomes that must remain inspectable, but must not be replayed with the old key.
     * The user can choose the separate "edit as new message" flow for these rows.
     */
    val EDITABLE_AS_NEW: Set<String> = setOf(
        INDETERMINATE,
        REJECTED,
        CONFLICT,
    )

    /** Outcomes which should remain visible after a process restart for explicit recovery. */
    val REVIEWABLE: Set<String> = setOf(
        UNCERTAIN,
        INDETERMINATE,
        REJECTED,
        CONFLICT,
    )
}

/** Raised when a second tap tries to create a side effect while its original operation is live. */
class MobileOperationInProgressException : IllegalArgumentException(
    "a mobile operation for this target is already unresolved",
)

/** Values needed to retry or inspect one exact side-effecting operation. */
data class MobileOperationHandle(
    val operation: MobileOperationEntity,
    val requestBody: String,
    val originalEtag: String? = null,
)

/**
 * Persists an operation and its existing idempotency record together. The request body is stored
 * once in the idempotency table; this row only references its scope and key plus presentation
 * state, so operation metadata never creates a second plaintext-bearing cache.
 */
@Singleton
class MobileOperationStore @Inject constructor(
    private val database: HermesDatabase,
    private val dao: HermesDao,
    private val crypto: EncryptedValueStore,
) {
    suspend fun begin(
        instanceId: String,
        opaqueProfileId: String,
        operationId: String = newOperationId(),
        kind: String,
        conversationId: String,
        resourceId: String? = null,
        idempotencyScope: String,
        idempotencyKey: IdempotencyKey,
        requestBody: String,
        originalEtag: String? = null,
        nowEpochMillis: Long,
    ): MobileOperationEntity {
        require(instanceId.isNotBlank() && opaqueProfileId.isNotBlank())
        require(operationId.isNotBlank() && kind.isNotBlank() && conversationId.isNotBlank())
        require(idempotencyScope.startsWith("mobile/v1/")) {
            "operation scope must be a typed mobile route"
        }
        require(requestBody.isNotBlank()) { "operation request body must not be blank" }
        require(nowEpochMillis >= 0)
        val operation = MobileOperationEntity(
            instanceId = instanceId,
            opaqueProfileId = opaqueProfileId,
            operationId = operationId,
            kind = kind,
            conversationId = conversationId,
            resourceId = resourceId,
            idempotencyScope = idempotencyScope,
            idempotencyKey = idempotencyKey.value,
            originalEtagCiphertext = originalEtag?.let {
                crypto.encrypt(
                    it.toByteArray(StandardCharsets.UTF_8),
                    etagAad(instanceId, opaqueProfileId, operationId),
                )
                    .toByteArray()
            },
            state = "pending",
            runId = null,
            cancelRequested = false,
            completedExternalSideEffectsNotUndone = false,
            createdAtEpochMillis = nowEpochMillis,
            updatedAtEpochMillis = nowEpochMillis,
        )
        val bodyCiphertext = crypto.encrypt(
            requestBody.toByteArray(StandardCharsets.UTF_8),
            idempotencyAad(
                instanceId,
                opaqueProfileId,
                conversationId,
                idempotencyScope,
                idempotencyKey.value,
            ).toByteArray(StandardCharsets.UTF_8),
        ).toByteArray()
        database.withTransaction {
            val existing = dao.findMobileOperation(instanceId, opaqueProfileId, operationId)
            require(existing == null) {
                "mobile operation already exists; use its operation ID for an explicit retry"
            }
            if (dao.findActiveMobileOperation(
                    instanceId = instanceId,
                    opaqueProfileId = opaqueProfileId,
                    conversationId = conversationId,
                    kind = kind,
                    activeStates = ACTIVE_STATES,
                ) != null
            ) {
                throw MobileOperationInProgressException()
            }
            dao.saveIdempotency(
                IdempotencyEntity(
                    instanceId = instanceId,
                    opaqueProfileId = opaqueProfileId,
                    conversationId = conversationId,
                    scope = idempotencyScope,
                    idempotencyKey = idempotencyKey.value,
                    requestBodyCiphertext = bodyCiphertext,
                    createdAtEpochMillis = nowEpochMillis,
                ),
            )
            dao.saveMobileOperation(operation)
        }
        return dao.findMobileOperation(instanceId, opaqueProfileId, operationId)
            ?: error("mobile operation disappeared after persistence")
    }

    suspend fun findActive(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
        kind: String,
    ): MobileOperationEntity? = dao.findActiveMobileOperation(
        instanceId = instanceId,
        opaqueProfileId = opaqueProfileId,
        conversationId = conversationId,
        kind = kind,
        activeStates = ACTIVE_STATES,
    )

    suspend fun findActiveForResource(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
        kind: String,
        resourceId: String,
    ): MobileOperationEntity? = dao.findActiveMobileOperationForResource(
        instanceId = instanceId,
        opaqueProfileId = opaqueProfileId,
        conversationId = conversationId,
        kind = kind,
        resourceId = resourceId,
        activeStates = ACTIVE_STATES,
    )

    /** Finds a durable control retry without requiring a network read for its conversation. */
    suspend fun findActiveForResourceAnyConversation(
        instanceId: String,
        opaqueProfileId: String,
        kind: String,
        resourceId: String,
    ): MobileOperationEntity? = dao.findActiveMobileOperationForAnyConversation(
        instanceId = instanceId,
        opaqueProfileId = opaqueProfileId,
        kind = kind,
        resourceId = resourceId,
        activeStates = ACTIVE_STATES,
    )

    suspend fun findForRun(
        instanceId: String,
        opaqueProfileId: String,
        runId: String,
    ): MobileOperationEntity? = dao.findMobileOperationForRun(
        instanceId = instanceId,
        opaqueProfileId = opaqueProfileId,
        runId = runId,
    )?.takeIf {
        it.state in MobileOperationStates.ACTIVE ||
            it.state == MobileOperationStates.INDETERMINATE
    }

    /** Fences mutations left before their request boundary when a new app process starts. */
    suspend fun recoverSendingOperations(
        instanceId: String,
        opaqueProfileId: String,
        nowEpochMillis: Long,
    ): Int {
        require(instanceId.isNotBlank() && opaqueProfileId.isNotBlank() && nowEpochMillis >= 0)
        // A process can die after the encrypted operation is committed but before the caller
        // advances it from pending to sending.  Treat both states as unresolved: a later
        // foreground retry may reuse the exact key/body, while startup never sends implicitly.
        val rows = dao.listInFlightMobileOperations(instanceId, opaqueProfileId)
        if (rows.isEmpty()) return 0
        database.withTransaction {
            rows.forEach { operation ->
                val current = dao.findMobileOperation(
                    operation.instanceId,
                    operation.opaqueProfileId,
                    operation.operationId,
                ) ?: return@forEach
                dao.saveMobileOperation(
                    mergeMobileOperationUpdate(
                        current = current,
                        requested = operation.copy(
                            state = MobileOperationStates.UNCERTAIN,
                            updatedAtEpochMillis = nowEpochMillis,
                        ),
                    ),
                )
            }
        }
        return rows.size
    }

    /**
     * Converts only legacy direct-send journals into explicit unresolved operations.  The
     * original encrypted body/key rows are retained and no network call is made here.
     */
    suspend fun adoptLegacySendOperations(
        instanceId: String,
        opaqueProfileId: String,
        nowEpochMillis: Long,
    ): Int {
        require(instanceId.isNotBlank() && opaqueProfileId.isNotBlank() && nowEpochMillis >= 0)
        val rows = dao.listIdempotencyForTarget(instanceId, opaqueProfileId).filter { row ->
            row.conversationId.isNotBlank() &&
                row.scope.matches(LEGACY_MESSAGE_SCOPE) &&
                row.idempotencyKey.isNotBlank()
        }
        var adopted = 0
        database.withTransaction {
            for (row in rows) {
                val operationId = legacyOperationId(row)
                if (dao.findMobileOperation(instanceId, opaqueProfileId, operationId) != null) continue
                dao.saveMobileOperation(
                    MobileOperationEntity(
                        instanceId = instanceId,
                        opaqueProfileId = opaqueProfileId,
                        operationId = operationId,
                        kind = MobileOperationKinds.MESSAGE_SEND,
                        conversationId = row.conversationId,
                        resourceId = null,
                        idempotencyScope = row.scope,
                        idempotencyKey = row.idempotencyKey,
                        originalEtagCiphertext = null,
                        state = MobileOperationStates.UNCERTAIN,
                        runId = null,
                        cancelRequested = false,
                        completedExternalSideEffectsNotUndone = false,
                        createdAtEpochMillis = row.createdAtEpochMillis,
                        updatedAtEpochMillis = nowEpochMillis,
                    ),
                )
                adopted++
            }
        }
        return adopted
    }

    suspend fun load(
        instanceId: String,
        opaqueProfileId: String,
        operationId: String,
    ): MobileOperationHandle? {
        val operation = dao.findMobileOperation(instanceId, opaqueProfileId, operationId)
            ?: return null
        val body = dao.findIdempotency(
            instanceId,
            opaqueProfileId,
            operation.conversationId,
            operation.idempotencyScope,
            operation.idempotencyKey,
        )?.let { row ->
            val plaintext = crypto.decrypt(
                EncryptedValue.fromByteArray(row.requestBodyCiphertext),
                idempotencyAad(
                    instanceId,
                    opaqueProfileId,
                    operation.conversationId,
                    operation.idempotencyScope,
                    operation.idempotencyKey,
                ).toByteArray(StandardCharsets.UTF_8),
            )
            String(plaintext, StandardCharsets.UTF_8)
        } ?: return MobileOperationHandle(operation, requestBody = "", originalEtag = decryptEtag(operation))
        return MobileOperationHandle(operation, body, decryptEtag(operation))
    }

    suspend fun update(
        operation: MobileOperationEntity,
        state: String,
        nowEpochMillis: Long,
        runId: String? = operation.runId,
        cancelRequested: Boolean = operation.cancelRequested,
        completedExternalSideEffectsNotUndone: Boolean = operation.completedExternalSideEffectsNotUndone,
    ): MobileOperationEntity {
        require(state.isNotBlank() && nowEpochMillis >= 0)
        // Status polling, a send response, and Stop can all finish concurrently.  Read and
        // merge inside one Room transaction so a response that started earlier cannot reopen a
        // terminal operation (or undo an explicit stop) after a later response has committed.
        return database.withTransaction {
            val requested = operation.copy(
                state = state,
                runId = runId,
                cancelRequested = cancelRequested,
                completedExternalSideEffectsNotUndone = completedExternalSideEffectsNotUndone,
                updatedAtEpochMillis = nowEpochMillis,
            )
            val current = dao.findMobileOperation(
                operation.instanceId,
                operation.opaqueProfileId,
                operation.operationId,
            )
            val merged = if (current == null) {
                requested
            } else {
                mergeMobileOperationUpdate(current, requested)
            }
            dao.saveMobileOperation(merged)
            merged
        }
    }

    suspend fun retire(
        operation: MobileOperationEntity,
        nowEpochMillis: Long,
        terminalState: String = "completed",
    ): MobileOperationEntity {
        require(nowEpochMillis >= 0 && terminalState.isNotBlank())
        return database.withTransaction {
            val current = dao.findMobileOperation(
                operation.instanceId,
                operation.opaqueProfileId,
                operation.operationId,
            )
            val requested = operation.copy(
                state = terminalState,
                updatedAtEpochMillis = nowEpochMillis,
            )
            // First terminal outcome wins.  A late status/cancel response may enrich the
            // monotonic safety flags, but must not change completed/cancelled/conflict into a
            // different terminal decision.
            val completed = if (current == null) {
                requested
            } else {
                mergeMobileOperationUpdate(current, requested)
            }
            dao.saveMobileOperation(completed)
            dao.deleteIdempotency(
                operation.instanceId,
                operation.opaqueProfileId,
                operation.conversationId,
                operation.idempotencyScope,
                IdempotencyKey(operation.idempotencyKey),
            )
            completed
        }
    }

    suspend fun list(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
        kind: String,
    ): List<MobileOperationEntity> = dao.listMobileOperations(
        instanceId,
        opaqueProfileId,
        conversationId,
        kind,
    )

    private fun decryptEtag(operation: MobileOperationEntity): String? =
        operation.originalEtagCiphertext?.let {
            String(
                crypto.decrypt(
                    EncryptedValue.fromByteArray(it),
                    etagAad(operation.instanceId, operation.opaqueProfileId, operation.operationId),
                ),
                StandardCharsets.UTF_8,
            )
        }

    private fun etagAad(instanceId: String, opaqueProfileId: String, operationId: String): ByteArray =
        "mobile-operation-etag:$instanceId:$opaqueProfileId:$operationId".toByteArray(StandardCharsets.UTF_8)

    private fun idempotencyAad(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
        scope: String,
        key: String,
    ): String = listOf(instanceId, opaqueProfileId, conversationId, scope, key).joinToString("\u001f")

    private fun legacyOperationId(row: IdempotencyEntity): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(
                listOf(
                    row.instanceId,
                    row.opaqueProfileId,
                    row.conversationId,
                    row.scope,
                    row.idempotencyKey,
                ).joinToString("\u001f").toByteArray(StandardCharsets.UTF_8),
            )
        return "legacy_" + digest.joinToString("") { byte -> "%02x".format(byte) }
    }

    private companion object {
        val ACTIVE_STATES = MobileOperationStates.ACTIVE.toList()
        val LEGACY_MESSAGE_SCOPE = Regex(
            "^mobile/v1/profiles/[^/]+/conversations/[^/]+/messages$",
        )
    }
}

fun newOperationId(): String = "op_${UUID.randomUUID()}".replace("-", "")

/**
 * Monotonic local merge for responses that race on one durable operation.  The server remains
 * authoritative for the actual run state; this policy only prevents an older local observation
 * from erasing a terminal decision or an explicit stop request.
 */
internal fun mergeMobileOperationUpdate(
    current: MobileOperationEntity,
    requested: MobileOperationEntity,
): MobileOperationEntity {
    require(current.instanceId == requested.instanceId)
    require(current.opaqueProfileId == requested.opaqueProfileId)
    require(current.operationId == requested.operationId)

    val currentTerminal = current.state in MobileOperationStates.TERMINAL
    val requestedTerminal = requested.state in MobileOperationStates.TERMINAL
    // An indeterminate transport result is a terminal *local* decision, not proof that Hermes
    // has no run. An explicit status read that returns a run may resolve it; rejected/conflict
    // outcomes remain blocked and cannot be reclassified by a stale lookup.
    val resolvesIndeterminate = current.state == MobileOperationStates.INDETERMINATE &&
        requested.runId != null &&
        (requested.state in MobileOperationStates.RUN_ACTIVE || requestedTerminal)
    val applyState = when {
        currentTerminal && !resolvesIndeterminate -> false
        resolvesIndeterminate -> true
        requestedTerminal -> true
        // An operation that already owns a host run cannot be downgraded by a late send-side
        // exception or by a stale pre-boundary response.
        current.state in MobileOperationStates.RUN_ACTIVE &&
            requested.state in PRE_RUN_STATES + MobileOperationStates.UNCERTAIN -> false
        current.state == MobileOperationStates.STOP_REQUESTED &&
            requested.state != MobileOperationStates.STOP_REQUESTED -> false
        current.state == MobileOperationStates.UNCERTAIN &&
            requested.state in PRE_RUN_STATES -> false
        requestedStateRank(requested.state) >= requestedStateRank(current.state) -> true
        // Wall-clock values are a useful tie-breaker for two observations at the same lifecycle
        // phase.  Equal timestamps deliberately keep the existing row deterministic.
        requested.updatedAtEpochMillis > current.updatedAtEpochMillis -> true
        else -> false
    }

    val state = if (applyState) requested.state else current.state
    val runId = requested.runId ?: current.runId
    val updatedAt = maxOf(current.updatedAtEpochMillis, requested.updatedAtEpochMillis)
    return current.copy(
        state = state,
        runId = runId,
        cancelRequested = current.cancelRequested || requested.cancelRequested,
        completedExternalSideEffectsNotUndone =
            current.completedExternalSideEffectsNotUndone ||
                requested.completedExternalSideEffectsNotUndone,
        updatedAtEpochMillis = updatedAt,
    )
}

private val PRE_RUN_STATES = setOf(
    MobileOperationStates.PENDING,
    MobileOperationStates.SENDING,
)

private fun requestedStateRank(state: String): Int = when (state) {
    MobileOperationStates.PENDING -> 0
    MobileOperationStates.SENDING -> 1
    MobileOperationStates.QUEUED -> 2
    MobileOperationStates.THINKING -> 3
    MobileOperationStates.TOOL_RUNNING -> 4
    MobileOperationStates.WAITING_FOR_USER -> 5
    MobileOperationStates.APPROVAL_REQUIRED -> 6
    MobileOperationStates.UNCERTAIN -> 2
    MobileOperationStates.STOP_REQUESTED -> 7
    else -> 0
}
