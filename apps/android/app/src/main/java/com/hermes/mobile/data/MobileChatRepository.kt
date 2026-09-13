package com.hermes.mobile.data

import com.hermes.mobile.auth.MobileEnrollmentCoordinator
import com.hermes.mobile.contract.BotId
import com.hermes.mobile.contract.MessagePart
import com.hermes.mobile.network.ChatSendRequest
import com.hermes.mobile.network.ConversationMessageWire
import com.hermes.mobile.network.ConversationWire
import com.hermes.mobile.network.HermesApiClient
import com.hermes.mobile.network.HermesEventStream
import com.hermes.mobile.network.HermesApiException
import com.hermes.mobile.network.HermesAuthExpiredException
import com.hermes.mobile.network.MobileApiErrorCodes
import com.hermes.mobile.network.MobileProfileWire
import com.hermes.mobile.network.MessageStatusResponse
import com.hermes.mobile.network.RunWire
import com.hermes.mobile.network.IdempotencyKeys
import com.hermes.mobile.security.EncryptedValue
import com.hermes.mobile.security.EncryptedValueStore
import com.hermes.mobile.sync.SyncReconciler
import com.hermes.mobile.sync.SyncTarget
import androidx.room.withTransaction
import java.nio.charset.StandardCharsets
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

data class MobileRoster(
    val profiles: List<MobileProfileWire>,
    val refreshedAtEpochMillis: Long,
)

data class MobileConversationLoad(
    val conversation: ConversationWire,
    val messages: List<ConversationMessageWire>,
    val conversations: List<ConversationWire> = emptyList(),
)

data class PreparedSend(
    val target: BotId,
    val conversationId: String,
    val text: String,
    val attachmentIds: List<String>,
    val operation: MobileOperationEntity,
)

data class PendingSend(
    val operationId: String,
    val conversationId: String,
    val text: String,
    val attachmentIds: List<String>,
    val state: String,
    val runId: String?,
)

/** Metadata for a New chat request that needs an explicit same-key retry. */
data class PendingConversationCreate(
    val operationId: String,
    val state: String,
)

/** Maps one send transport failure to the durable state that governs the next allowed action. */
fun classifyMobileSendFailure(statusCode: Int, errorCode: String?): String {
    val normalizedCode = errorCode?.trim()?.lowercase()
    return when {
        normalizedCode == MobileApiErrorCodes.IDEMPOTENCY_KEY_CONFLICT -> MobileOperationStates.CONFLICT
        normalizedCode == MobileApiErrorCodes.MESSAGE_INDETERMINATE -> MobileOperationStates.INDETERMINATE
        // A 401 means the Access/device session must be restored.  Keep the exact operation
        // retryable instead of terminally rejecting a request that may never have reached Hermes.
        statusCode == 401 -> MobileOperationStates.UNCERTAIN
        statusCode in 400..499 && statusCode !in setOf(408, 409, 429) -> MobileOperationStates.REJECTED
        else -> MobileOperationStates.UNCERTAIN
    }
}

/** Maps one create transport failure without ever making a blind second create attempt. */
fun classifyMobileConversationCreateFailure(statusCode: Int, errorCode: String?): String {
    val normalizedCode = errorCode?.trim()?.lowercase()
    return when {
        normalizedCode == MobileApiErrorCodes.IDEMPOTENCY_KEY_CONFLICT || statusCode == 409 ->
            MobileOperationStates.CONFLICT
        normalizedCode == MobileApiErrorCodes.MESSAGE_INDETERMINATE ->
            MobileOperationStates.INDETERMINATE
        // Keep authentication failures paused/retryable until the user restores the session.
        statusCode == 401 ->
            MobileOperationStates.UNCERTAIN
        statusCode in 400..499 && statusCode !in setOf(408, 429) ->
            MobileOperationStates.REJECTED
        else -> MobileOperationStates.UNCERTAIN
    }
}

@kotlinx.serialization.Serializable
private data class CachedMessageEnvelope(
    val role: String,
    val parts: List<JsonElement>,
)

/**
 * Authenticated, profile-scoped mobile operations used by the presentation layer.
 *
 * This class deliberately keeps the request factory and bearer/device material behind the
 * session/provider boundary. It restores encrypted sessions, refreshes a five-minute device
 * token with a server nonce, persists idempotency bodies before mutation attempts, and only
 * writes encrypted message/title payloads into Room.
 */
@Singleton
class MobileChatRepository @Inject constructor(
    private val api: HermesApiClient,
    private val authSession: HermesAuthSession,
    private val enrollment: MobileEnrollmentCoordinator,
    private val database: HermesDatabase,
    private val dao: HermesDao,
    private val crypto: EncryptedValueStore,
    private val idempotency: IdempotencyStore,
    private val operations: MobileOperationStore,
    private val reconciler: SyncReconciler,
) {
    suspend fun restoreAndListProfiles(nowEpochMillis: Long): MobileRoster? {
        require(nowEpochMillis >= 0)
        val sessionWasAlreadyLoaded = authSession.current() != null
        val target = restoreAnySession() ?: return null
        ensureUsableSession(target, nowEpochMillis)
        val profiles = api.listProfiles().profiles
        for (profile in profiles) {
            val profileTarget = SyncTarget(
                instanceId = profile.bot.instanceId,
                opaqueProfileId = profile.bot.opaqueProfileId,
            )
            if (dao.findSyncCursor(profileTarget.instanceId, profileTarget.opaqueProfileId) == null) {
                dao.saveSyncCursor(
                    SyncCursorEntity(
                        instanceId = profileTarget.instanceId,
                        opaqueProfileId = profileTarget.opaqueProfileId,
                        cursor = 0,
                        updatedAtEpochMillis = nowEpochMillis,
                    ),
                )
            }
            if (!sessionWasAlreadyLoaded) {
                // A process can die after persisting `sending` but before the network call
                // returns.  Fence that state before rendering retry cards; an in-process refresh
                // must not turn a live coroutine into a duplicate-send opportunity.
                operations.recoverSendingOperations(
                    instanceId = profileTarget.instanceId,
                    opaqueProfileId = profileTarget.opaqueProfileId,
                    nowEpochMillis = nowEpochMillis,
                )
            }
            // Version-5 clients only had encrypted idempotency rows.  Adopt legacy direct sends
            // as unresolved operation metadata without attempting a mutation; the user must
            // explicitly inspect/retry them after this process restores the roster.
            operations.adoptLegacySendOperations(
                instanceId = profileTarget.instanceId,
                opaqueProfileId = profileTarget.opaqueProfileId,
                nowEpochMillis = nowEpochMillis,
            )
        }
        return MobileRoster(profiles = profiles, refreshedAtEpochMillis = nowEpochMillis)
    }

    suspend fun reconcile(target: BotId, nowEpochMillis: Long, forceSnapshot: Boolean = false) =
        reconciler.reconcile(
            target = SyncTarget(target.instanceId, target.opaqueProfileId),
            nowEpochMillis = nowEpochMillis,
            forceSnapshot = forceSnapshot,
        )

    suspend fun currentSyncCursor(target: BotId): Long =
        reconciler.currentCursor(SyncTarget(target.instanceId, target.opaqueProfileId))

    suspend fun openEventStream(
        target: BotId,
        afterCursor: Long,
        nowEpochMillis: Long,
    ): HermesEventStream {
        ensureUsableSession(SyncTarget(target.instanceId, target.opaqueProfileId), nowEpochMillis)
        return api.openEventStream(
            instanceId = target.instanceId,
            opaqueProfileId = target.opaqueProfileId,
            afterCursor = afterCursor,
        )
    }

    suspend fun consumeEventStream(
        target: BotId,
        response: HermesEventStream,
        nowEpochMillis: () -> Long = { System.currentTimeMillis() },
    ): Int = reconciler.consumeEventStream(
        target = SyncTarget(target.instanceId, target.opaqueProfileId),
        stream = response,
        nowEpochMillis = nowEpochMillis,
    )

    suspend fun listConversations(target: BotId, nowEpochMillis: Long): List<ConversationWire> {
        ensureUsableSession(SyncTarget(target.instanceId, target.opaqueProfileId), nowEpochMillis)
        val conversations = api.listConversations(target.opaqueProfileId).conversations
        for (conversation in conversations) saveConversation(target, conversation, nowEpochMillis)
        return conversations
    }

    suspend fun selectedConversationId(target: BotId): String? =
        dao.findSelectedConversation(target.instanceId, target.opaqueProfileId)?.conversationId

    suspend fun selectConversation(target: BotId, conversationId: String, nowEpochMillis: Long) {
        require(conversationId.isNotBlank() && nowEpochMillis >= 0)
        dao.saveSelectedConversation(
            SelectedConversationEntity(
                instanceId = target.instanceId,
                opaqueProfileId = target.opaqueProfileId,
                conversationId = conversationId,
                updatedAtEpochMillis = nowEpochMillis,
            ),
        )
    }

    suspend fun loadConversation(
        target: BotId,
        nowEpochMillis: Long,
        requestedConversationId: String? = null,
    ): MobileConversationLoad? {
        ensureUsableSession(SyncTarget(target.instanceId, target.opaqueProfileId), nowEpochMillis)
        val conversations = api.listConversations(target.opaqueProfileId).conversations
        for (conversation in conversations) {
            saveConversation(target, conversation, nowEpochMillis)
        }
        val savedSelection = dao.findSelectedConversation(
            target.instanceId,
            target.opaqueProfileId,
        )?.conversationId
        val selected = requestedConversationId?.let { requested ->
            conversations.firstOrNull { it.conversationId == requested }
                ?: throw ConversationNotFoundException(requested)
        } ?: savedSelection?.let { saved ->
            conversations.firstOrNull { it.conversationId == saved }
        } ?: conversations.firstOrNull { it.canonical }
            ?: conversations.maxByOrNull { it.updatedAtEpochSeconds }
            ?: return null
        val messages = api.fetchConversationHistory(
            target.opaqueProfileId,
            selected.conversationId,
        ).messages
        for (message in messages) {
            saveMessage(target, message, nowEpochMillis)
        }
        selectConversation(target, selected.conversationId, nowEpochMillis)
        return MobileConversationLoad(selected, messages, conversations)
    }

    /** Returns an unresolved New chat operation without reading or mutating the host. */
    suspend fun pendingConversationCreate(target: BotId): PendingConversationCreate? =
        operations.list(
            instanceId = target.instanceId,
            opaqueProfileId = target.opaqueProfileId,
            conversationId = PENDING_CONVERSATION_ID,
            kind = MobileOperationKinds.CONVERSATION_CREATE,
        ).firstOrNull { it.state in MobileOperationStates.ACTIVE }
            ?.let { PendingConversationCreate(it.operationId, it.state) }

    /**
     * Creates one non-canonical conversation.  A second New chat tap never replays an unresolved
     * request implicitly; callers must pass the persisted operation ID for an explicit retry.
     */
    suspend fun createConversation(
        target: BotId,
        nowEpochMillis: Long,
        operationId: String? = null,
    ): ConversationWire {
        val route = "mobile/v1/profiles/${target.opaqueProfileId}/conversations"
        val body = "{\"canonical\":false}"
        var requestBody = body
        val operation = if (operationId == null) {
            val unresolved = pendingConversationCreate(target)
            if (unresolved != null) {
                throw MobileOperationInProgressException()
            }
            operations.begin(
                instanceId = target.instanceId,
                opaqueProfileId = target.opaqueProfileId,
                kind = MobileOperationKinds.CONVERSATION_CREATE,
                conversationId = PENDING_CONVERSATION_ID,
                idempotencyScope = route,
                idempotencyKey = IdempotencyKeys.generate(),
                requestBody = body,
                nowEpochMillis = nowEpochMillis,
            )
        } else {
            val handle = operations.load(target.instanceId, target.opaqueProfileId, operationId)
                ?: throw IllegalArgumentException("conversation creation operation is no longer available")
            require(handle.operation.kind == MobileOperationKinds.CONVERSATION_CREATE) {
                "operation is not a conversation creation"
            }
            require(handle.operation.conversationId == PENDING_CONVERSATION_ID) {
                "conversation creation operation has an invalid target"
            }
            require(handle.operation.idempotencyScope == route) {
                "conversation creation operation has an invalid scope"
            }
            require(handle.operation.state == MobileOperationStates.UNCERTAIN) {
                "conversation creation is not waiting for an explicit retry"
            }
            require(handle.requestBody.isNotBlank()) {
                "the original conversation creation body is unavailable"
            }
            requestBody = handle.requestBody
            handle.operation
        }
        val key = com.hermes.mobile.contract.IdempotencyKey(operation.idempotencyKey)
        var sendingOperation = operation
        return try {
            sendingOperation = operations.update(
                operation,
                state = MobileOperationStates.SENDING,
                nowEpochMillis = nowEpochMillis,
            )
            // Persist and fence the operation before auth refresh or the create POST. If the
            // process stops during either network step, startup recovery can expose this exact
            // key/body as an uncertain operation instead of allocating a second conversation.
            ensureUsableSession(SyncTarget(target.instanceId, target.opaqueProfileId), nowEpochMillis)
            val created = api.createConversationBody(target.opaqueProfileId, requestBody, key)
            saveConversation(target, created, nowEpochMillis)
            selectConversation(target, created.conversationId, nowEpochMillis)
            operations.retire(sendingOperation, nowEpochMillis)
            created
        } catch (error: HermesApiException) {
            operations.update(
                sendingOperation,
                state = classifyMobileConversationCreateFailure(error.statusCode, error.errorCode),
                nowEpochMillis = nowEpochMillis,
            )
            throw error
        } catch (error: Exception) {
            operations.update(sendingOperation, state = MobileOperationStates.UNCERTAIN, nowEpochMillis = nowEpochMillis)
            throw error
        }
    }

    /** Explicitly retries one unresolved create with its persisted key and exact request body. */
    suspend fun retryCreateConversation(
        target: BotId,
        operationId: String,
        nowEpochMillis: Long,
    ): ConversationWire = createConversation(target, nowEpochMillis, operationId)

    class ConversationNotFoundException(conversationId: String) :
        IllegalArgumentException("conversation is not available to this profile: $conversationId")

    /** Loads the encrypted local composer draft for one server-owned conversation. */
    suspend fun loadDraft(target: BotId, conversationId: String): String? {
        require(conversationId.isNotBlank())
        val row = dao.findDraft(target.instanceId, target.opaqueProfileId, conversationId)
            ?: return null
        return String(
            crypto.decrypt(
                EncryptedValue.fromByteArray(row.draftCiphertext),
                draftAad(target, conversationId),
            ),
            StandardCharsets.UTF_8,
        )
    }

    /** Persists a composer draft locally without sending it to the Hermes host. */
    suspend fun saveDraft(
        target: BotId,
        conversationId: String,
        text: String,
        nowEpochMillis: Long,
    ) {
        require(conversationId.isNotBlank())
        require(text.length <= MAX_MESSAGE_LENGTH)
        require(nowEpochMillis >= 0)
        if (text.isEmpty()) {
            dao.deleteDraft(target.instanceId, target.opaqueProfileId, conversationId)
            return
        }
        val existing = dao.findDraft(target.instanceId, target.opaqueProfileId, conversationId)
        val revision = (existing?.revision ?: 0L) + 1L
        require(revision > 0L) { "draft revision overflow" }
        dao.upsertDraft(
            DraftEntity(
                instanceId = target.instanceId,
                opaqueProfileId = target.opaqueProfileId,
                conversationId = conversationId,
                draftCiphertext = crypto.encrypt(
                    text.toByteArray(StandardCharsets.UTF_8),
                    draftAad(target, conversationId),
                ).toByteArray(),
                revision = revision,
                updatedAtEpochMillis = nowEpochMillis,
            ),
        )
    }

    /** Loads the last encrypted conversation snapshot when the authenticated host is offline. */
    suspend fun loadCachedConversation(target: BotId): MobileConversationLoad? {
        val rows = dao.observeConversations(target.instanceId, target.opaqueProfileId).first()
        val selectedId = dao.findSelectedConversation(
            target.instanceId,
            target.opaqueProfileId,
        )?.conversationId
        val row = selectedId?.let { id -> rows.firstOrNull { it.conversationId == id } }
            ?: rows.firstOrNull { it.canonical }
            ?: rows.maxByOrNull { it.updatedAtEpochMillis }
            ?: return null
        val title = String(
            crypto.decrypt(
                EncryptedValue.fromByteArray(
                    requireNotNull(row.titleCiphertext) { "cached conversation title is missing" },
                ),
                conversationAad(target, row.conversationId),
            ),
            StandardCharsets.UTF_8,
        )
        return MobileConversationLoad(
            conversation = ConversationWire(
                conversationId = row.conversationId,
                canonical = row.canonical,
                title = title,
                revision = row.revision,
                updatedAtEpochSeconds = row.updatedAtEpochMillis / 1_000.0,
            ),
            messages = loadCachedMessages(target, row.conversationId),
            conversations = rows.mapNotNull { cachedConversation ->
                decryptCachedConversation(target, cachedConversation)
            },
        )
    }

    /** Loads all locally encrypted conversation summaries for an offline picker. */
    suspend fun loadCachedConversations(target: BotId): List<ConversationWire> =
        dao.observeConversations(target.instanceId, target.opaqueProfileId)
            .first()
            .mapNotNull { decryptCachedConversation(target, it) }

    suspend fun loadCachedMessages(
        target: BotId,
        conversationId: String,
    ): List<ConversationMessageWire> {
        require(conversationId.isNotBlank())
        return dao.observeMessages(target.instanceId, target.opaqueProfileId, conversationId)
            .first()
            .mapNotNull { row ->
                val encoded = String(
                    crypto.decrypt(
                        EncryptedValue.fromByteArray(row.partsCiphertext),
                        messageAad(target, row.conversationId, row.messageId),
                    ),
                    StandardCharsets.UTF_8,
                )
                val envelope = runCatching {
                    json.decodeFromString<CachedMessageEnvelope>(encoded)
                }.getOrNull()
                val role: String
                val payload: List<JsonElement>
                if (envelope != null) {
                    role = envelope.role
                    payload = envelope.parts
                } else {
                    role = "assistant"
                    payload = runCatching {
                        json.decodeFromString<List<JsonElement>>(encoded)
                    }.getOrNull() ?: return@mapNotNull null
                }
                ConversationMessageWire(
                    messageId = row.messageId,
                    conversationId = row.conversationId,
                    role = role,
                    parts = payload,
                    createdAtEpochSeconds = row.createdAtEpochMillis / 1_000.0,
                )
            }
    }

    /** Returns unresolved direct sends so a process restart can render an explicit retry card. */
    suspend fun listPendingSends(target: BotId, conversationId: String): List<PendingSend> =
        operations.list(
            instanceId = target.instanceId,
            opaqueProfileId = target.opaqueProfileId,
            conversationId = conversationId,
            kind = MobileOperationKinds.MESSAGE_SEND,
        ).filter { it.state in MobileOperationStates.ACTIVE || it.state in MobileOperationStates.REVIEWABLE }
            .mapNotNull { operation ->
                val handle = operations.load(target.instanceId, target.opaqueProfileId, operation.operationId)
                    ?: return@mapNotNull null
                if (handle.requestBody.isBlank()) return@mapNotNull null
                val body = runCatching {
                    json.decodeFromString<ChatSendRequest>(handle.requestBody)
                }.getOrNull() ?: return@mapNotNull null
                PendingSend(
                    operationId = operation.operationId,
                    conversationId = operation.conversationId,
                    text = body.text,
                    attachmentIds = body.attachmentIds,
                    state = operation.state,
                    runId = operation.runId,
                )
            }

    /**
     * Returns one exact persisted send for the explicit "edit as new message" flow.  This is a
     * local read only; it never changes the old operation or allocates a new idempotency key.
     */
    suspend fun loadSendForEditAsNew(target: BotId, operationId: String): PendingSend? {
        val handle = operations.load(target.instanceId, target.opaqueProfileId, operationId)
            ?: return null
        if (handle.operation.kind != MobileOperationKinds.MESSAGE_SEND) return null
        if (handle.operation.state !in MobileOperationStates.EDITABLE_AS_NEW) return null
        if (handle.requestBody.isBlank()) return null
        val body = runCatching {
            json.decodeFromString<ChatSendRequest>(handle.requestBody)
        }.getOrNull() ?: return null
        return PendingSend(
            operationId = operationId,
            conversationId = handle.operation.conversationId,
            text = body.text,
            attachmentIds = body.attachmentIds,
            state = handle.operation.state,
            runId = handle.operation.runId,
        )

    }

    /** Emits the Room-projected runs for one selected conversation as its source of truth. */
    fun observeProjectedRuns(target: BotId, conversationId: String): Flow<List<RunWire>> =
        dao.observeRuns(target.instanceId, target.opaqueProfileId, conversationId)
            .map { rows -> rows.map { row -> row.toRunWire() } }
            .distinctUntilChanged()

    suspend fun sendText(
        target: BotId,
        conversationId: String?,
        text: String,
        attachmentIds: List<String> = emptyList(),
        nowEpochMillis: Long,
        operationId: String? = null,
    ): SendTextResult {
        val prepared = if (operationId == null) {
            prepareSendText(target, conversationId, text, attachmentIds, nowEpochMillis)
        } else {
            ensureUsableSession(SyncTarget(target.instanceId, target.opaqueProfileId), nowEpochMillis)
            val loaded = operations.load(target.instanceId, target.opaqueProfileId, operationId)
                ?: throw IllegalArgumentException("send operation is no longer available")
            require(loaded.operation.kind == MobileOperationKinds.MESSAGE_SEND) {
                "operation is not a direct message send"
            }
            require(loaded.requestBody.isNotBlank()) {
                "the original send body is unavailable; create a new message"
            }
            val original = json.decodeFromString<ChatSendRequest>(loaded.requestBody)
            require(conversationId == null || loaded.operation.conversationId == conversationId) {
                "send operation belongs to a different conversation"
            }
            require(text == original.text && attachmentIds == original.attachmentIds) {
                "retry payload does not match the original send"
            }
            require(loaded.operation.state in MobileOperationStates.ACTIVE) {
                "send operation is no longer retryable"
            }
            require(loaded.operation.state != MobileOperationStates.SENDING) {
                "send operation is already in flight"
            }
            require(loaded.operation.state !in MobileOperationStates.RUN_ACTIVE) {
                "send operation already has an active run"
            }
            PreparedSend(
                target = target,
                conversationId = loaded.operation.conversationId,
                text = original.text,
                attachmentIds = original.attachmentIds,
                operation = loaded.operation,
            )
        }
        val conversation = prepared.conversationId
        val body = ChatSendRequest(text = prepared.text, attachmentIds = prepared.attachmentIds)
        val requestBody = json.encodeToString(body)
        val operation = prepared.operation
        val key = com.hermes.mobile.contract.IdempotencyKey(operation.idempotencyKey)
        val sendingOperation = operations.update(
            operation,
            state = MobileOperationStates.SENDING,
            nowEpochMillis = nowEpochMillis,
        )
        val response = try {
            api.sendMessageBody(target.opaqueProfileId, conversation, requestBody, key)
        } catch (expired: HermesAuthExpiredException) {
            // The mutation has not been retried. The caller can explicitly retry with the
            // persisted key/body after token refresh; this avoids duplicate agent turns.
            operations.update(sendingOperation, state = MobileOperationStates.UNCERTAIN, nowEpochMillis = nowEpochMillis)
            throw expired
        } catch (error: HermesApiException) {
            operations.update(
                sendingOperation,
                state = classifyMobileSendFailure(error.statusCode, error.errorCode),
                nowEpochMillis = nowEpochMillis,
            )
            throw error
        } catch (error: java.io.IOException) {
            operations.update(sendingOperation, state = MobileOperationStates.UNCERTAIN, nowEpochMillis = nowEpochMillis)
            throw error
        }
        val userMessage = ConversationMessageWire(
            // The idempotency key is stable across a crash/retry, so the optimistic local row is
            // also stable and cannot duplicate when the server replays a committed mutation.
            messageId = "local-${operation.operationId}",
            conversationId = conversation,
            role = "user",
            // Preserve attachment identity in the encrypted optimistic projection.  The host may
            // later replace these generic file parts with MIME/display metadata, but a pending
            // or replayed operation must never appear to have silently lost its attachments.
            parts = buildList(prepared.attachmentIds.size + 1) {
                add(
                    JsonObject(
                        mapOf(
                            "type" to kotlinx.serialization.json.JsonPrimitive("text"),
                            "text" to kotlinx.serialization.json.JsonPrimitive(prepared.text),
                        ),
                    ),
                )
                prepared.attachmentIds.forEach { attachmentId ->
                    add(
                        JsonObject(
                            mapOf(
                                "type" to kotlinx.serialization.json.JsonPrimitive("file"),
                                "attachment_id" to kotlinx.serialization.json.JsonPrimitive(attachmentId),
                            ),
                        ),
                    )
                }
            },
            createdAtEpochSeconds = nowEpochMillis / 1_000.0,
        )
        saveMessage(target, userMessage, nowEpochMillis, deliveryState = "SENT")
        saveRun(
            target = target,
            value = RunWire(
                runId = response.runId,
                conversationId = conversation,
                state = response.state,
            ),
            nowEpochMillis = nowEpochMillis,
        )
        // Remove the pending key only after the server response and the local durable result are
        // both committed. A crash before this point leaves the exact key/body available for a
        // safe replay rather than allowing a second agent turn.
        val completed = operations.update(
            sendingOperation,
            state = response.state,
            runId = response.runId,
            nowEpochMillis = nowEpochMillis,
        )
        // The synchronous endpoint normally returns a completed run, but the typed client also
        // accepts an active acknowledgement from a compatible host.  Keep the exact operation
        // material until the run reaches an authoritative terminal state so a process restart
        // cannot lose the pending card or open a second send in the same conversation.
        // An indeterminate terminal result is deliberately retained: the original encrypted
        // body/key are still needed for a status lookup and for the explicit "edit as new"
        // decision.  Only outcomes that are authoritative and no longer need recovery material
        // retire the idempotency record here.
        if (response.state in MobileOperationStates.TERMINAL &&
            response.state !in MobileOperationStates.EDITABLE_AS_NEW
        ) {
            operations.retire(completed, nowEpochMillis, terminalState = response.state)
        }
        return SendTextResult(
            conversationId = conversation,
            runId = response.runId,
            state = response.state,
            responseText = response.text,
            operationId = operation.operationId,
        )
    }

    /** Creates the durable send operation before the caller renders an optimistic message. */
    suspend fun prepareSendText(
        target: BotId,
        conversationId: String?,
        text: String,
        attachmentIds: List<String> = emptyList(),
        nowEpochMillis: Long,
    ): PreparedSend {
        require(text.isNotBlank() && text.length <= MAX_MESSAGE_LENGTH)
        require(attachmentIds.size <= 6)
        ensureUsableSession(SyncTarget(target.instanceId, target.opaqueProfileId), nowEpochMillis)
        val conversation = conversationId?.takeIf { it.isNotBlank() }
            ?: ensureCanonicalConversation(target, nowEpochMillis).conversationId
        val body = ChatSendRequest(text = text, attachmentIds = attachmentIds)
        val route = "mobile/v1/profiles/${target.opaqueProfileId}/conversations/$conversation/messages"
        val operation = operations.begin(
            instanceId = target.instanceId,
            opaqueProfileId = target.opaqueProfileId,
            operationId = newOperationId(),
            kind = MobileOperationKinds.MESSAGE_SEND,
            conversationId = conversation,
            idempotencyScope = route,
            idempotencyKey = IdempotencyKeys.generate(),
            requestBody = json.encodeToString(body),
            nowEpochMillis = nowEpochMillis,
        )
        return PreparedSend(target, conversation, text, attachmentIds.toList(), operation)
    }

    /** Loads the exact original send payload for an explicit, user-triggered retry. */
    suspend fun retryText(
        target: BotId,
        operationId: String,
        nowEpochMillis: Long,
    ): SendTextResult {
        val handle = operations.load(target.instanceId, target.opaqueProfileId, operationId)
            ?: throw IllegalArgumentException("send operation is no longer available")
        require(handle.operation.kind == MobileOperationKinds.MESSAGE_SEND) {
            "operation is not a direct message send"
        }
        require(handle.requestBody.isNotBlank()) {
            "the original send body is unavailable; create a new message"
        }
        val body = json.decodeFromString<ChatSendRequest>(handle.requestBody)
        return sendText(
            target = target,
            conversationId = handle.operation.conversationId,
            text = body.text,
            attachmentIds = body.attachmentIds,
            nowEpochMillis = nowEpochMillis,
            operationId = operationId,
        )
    }

    /** Reads the server's durable mutation state without reserving or replaying a mutation. */
    suspend fun messageStatus(
        target: BotId,
        operationId: String,
        nowEpochMillis: Long,
    ): MessageStatusResponse? {
        ensureUsableSession(SyncTarget(target.instanceId, target.opaqueProfileId), nowEpochMillis)
        val handle = operations.load(target.instanceId, target.opaqueProfileId, operationId) ?: return null
        require(handle.operation.kind == MobileOperationKinds.MESSAGE_SEND) {
            "operation is not a direct message send"
        }
        val status = api.getMessageStatus(
            opaqueProfileId = target.opaqueProfileId,
            conversationId = handle.operation.conversationId,
            idempotencyKey = com.hermes.mobile.contract.IdempotencyKey(handle.operation.idempotencyKey),
        )
        status.run?.let { run ->
            // The status call may have started before a send-side failure was classified. Reload
            // after the network read and never let a stale run response reopen a deterministic
            // conflict/rejection decision. An indeterminate outcome is intentionally resolvable
            // when this explicit lookup returns the run that Hermes actually recorded.
            val current = operations.load(target.instanceId, target.opaqueProfileId, operationId)
                ?: return@let
            if (current.operation.state == MobileOperationStates.REJECTED ||
                current.operation.state == MobileOperationStates.CONFLICT
            ) {
                // These are deterministic local outcomes. A status response must not turn a
                // rejected/conflicting request into an unrelated run; indeterminate is allowed
                // through because an explicit lookup can discover the run that actually exists.
                return@let
            }
            saveRun(target, run, nowEpochMillis)
            val operationState = run.state
            val updated = operations.update(
                current.operation,
                state = operationState,
                runId = run.runId,
                cancelRequested = run.cancelRequested,
                completedExternalSideEffectsNotUndone = run.completedExternalSideEffectsNotUndone,
                nowEpochMillis = nowEpochMillis,
            )
            if (operationState in MobileOperationStates.TERMINAL &&
                operationState !in MobileOperationStates.EDITABLE_AS_NEW
            ) {
                operations.retire(updated, nowEpochMillis, terminalState = operationState)
            }
        }
        return status
    }

    suspend fun getRun(target: BotId, runId: String, nowEpochMillis: Long): RunWire {
        ensureUsableSession(SyncTarget(target.instanceId, target.opaqueProfileId), nowEpochMillis)
        val run = api.getRun(runId)
        saveRun(target, run, nowEpochMillis)
        operations.findForRun(target.instanceId, target.opaqueProfileId, run.runId)?.let { operation ->
            val updated = operations.update(
                operation,
                state = run.state,
                runId = run.runId,
                cancelRequested = run.cancelRequested,
                completedExternalSideEffectsNotUndone = run.completedExternalSideEffectsNotUndone,
                nowEpochMillis = nowEpochMillis,
            )
            if (run.state in MobileOperationStates.TERMINAL &&
                run.state !in MobileOperationStates.EDITABLE_AS_NEW
            ) {
                operations.retire(updated, nowEpochMillis, terminalState = run.state)
            }
        }
        return run
    }

    suspend fun loadCachedRun(target: BotId, conversationId: String): RunWire? =
        observeProjectedRuns(target, conversationId).first().firstOrNull()

    /** Cancels one direct run with a durable idempotency operation and race-safe host response. */
    suspend fun cancelRun(
        target: BotId,
        runId: String,
        nowEpochMillis: Long,
    ): RunWire {
        ensureUsableSession(SyncTarget(target.instanceId, target.opaqueProfileId), nowEpochMillis)
        val route = "mobile/v1/runs/$runId/cancel"
        // Reuse an unresolved cancellation before doing any network read.  This matters when
        // the original stop timed out: the exact key/body remain available even while the host
        // is temporarily unreachable, so a later explicit tap can retry safely.
        val operation = operations.findActiveForResourceAnyConversation(
            instanceId = target.instanceId,
            opaqueProfileId = target.opaqueProfileId,
            kind = MobileOperationKinds.RUN_CANCEL,
            resourceId = runId,
        ) ?: run {
            val current = api.getRun(runId)
            val conversation = current.conversationId ?: "run-$runId"
            operations.begin(
                instanceId = target.instanceId,
                opaqueProfileId = target.opaqueProfileId,
                kind = MobileOperationKinds.RUN_CANCEL,
                conversationId = conversation,
                resourceId = runId,
                idempotencyScope = route,
                idempotencyKey = IdempotencyKeys.generate(),
                requestBody = "{}",
                nowEpochMillis = nowEpochMillis,
            )
        }
        var activeOperation = operation
        return try {
            activeOperation = operations.update(
                activeOperation,
                state = MobileOperationStates.STOP_REQUESTED,
                runId = runId,
                cancelRequested = true,
                nowEpochMillis = nowEpochMillis,
            )
            val result = api.cancelRun(runId, com.hermes.mobile.contract.IdempotencyKey(activeOperation.idempotencyKey))
            saveRun(target, result, nowEpochMillis)
            operations.retire(activeOperation, nowEpochMillis)
            result
        } catch (error: Exception) {
            operations.update(
                activeOperation,
                state = MobileOperationStates.UNCERTAIN,
                runId = runId,
                cancelRequested = true,
                nowEpochMillis = nowEpochMillis,
            )
            throw error
        }
    }

    suspend fun ensureCanonicalConversation(target: BotId, nowEpochMillis: Long): ConversationWire {
        ensureUsableSession(SyncTarget(target.instanceId, target.opaqueProfileId), nowEpochMillis)
        val existing = api.listConversations(target.opaqueProfileId).conversations
            .firstOrNull { it.canonical }
        if (existing != null) {
            saveConversation(target, existing, nowEpochMillis)
            selectConversation(target, existing.conversationId, nowEpochMillis)
            return existing
        }
        val route = "mobile/v1/profiles/${target.opaqueProfileId}/conversations"
        val body = "{\"canonical\":true}"
        val pending = idempotency.loadLatest(
            instanceId = target.instanceId,
            opaqueProfileId = target.opaqueProfileId,
            conversationId = "pending-conversation",
            scope = route,
        )?.takeIf { it.requestBody == body }
        val key = pending?.key ?: IdempotencyKeys.generate()
        if (pending == null) {
            idempotency.persistBeforeAttempt(
                instanceId = target.instanceId,
                opaqueProfileId = target.opaqueProfileId,
                conversationId = "pending-conversation",
                scope = route,
                key = key,
                requestBody = body,
                createdAtEpochMillis = nowEpochMillis,
            )
        }
        val created = api.createConversationBody(target.opaqueProfileId, body, key)
        saveConversation(target, created, nowEpochMillis)
        selectConversation(target, created.conversationId, nowEpochMillis)
        idempotency.delete(
            instanceId = target.instanceId,
            opaqueProfileId = target.opaqueProfileId,
            conversationId = "pending-conversation",
            scope = route,
            key = key,
        )
        return created
    }

    fun messageParts(message: ConversationMessageWire): List<MessagePart> =
        message.parts.mapNotNull(::decodePart)

    private suspend fun restoreAnySession(): SyncTarget? {
        authSession.current()?.let {
            val target = dao.listSyncTargets().firstOrNull()
            if (target != null) return SyncTarget(target.instanceId, target.opaqueProfileId)
        }
        for (row in dao.listSyncTargets()) {
            if (authSession.restore(row.instanceId, row.opaqueProfileId)) {
                return SyncTarget(row.instanceId, row.opaqueProfileId)
            }
        }
        return null
    }

    private suspend fun ensureUsableSession(target: SyncTarget, nowEpochMillis: Long) {
        if (authSession.current() == null) {
            if (!authSession.restore(target.instanceId, target.opaqueProfileId)) {
                throw HermesAuthExpiredException()
            }
        }
        val material = authSession.current() ?: throw HermesAuthExpiredException()
        val nowSeconds = nowEpochMillis / 1_000
        if (material.hermesDeviceToken.isUsable(nowSeconds)) return
        val deviceId = authSession.currentDeviceId() ?: throw HermesAuthExpiredException()
        enrollment.refreshApprovedSession(
            instanceId = target.instanceId,
            opaqueProfileId = target.opaqueProfileId,
            cloudflareAccessToken = material.cloudflareAccessToken,
            deviceId = deviceId,
            nowEpochMillis = nowEpochMillis,
        )
    }

    private suspend fun saveConversation(target: BotId, value: ConversationWire, nowEpochMillis: Long) {
        require(nowEpochMillis >= 0)
        val aad = conversationAad(target, value.conversationId)
        dao.upsertConversation(
            ConversationEntity(
                instanceId = target.instanceId,
                opaqueProfileId = target.opaqueProfileId,
                conversationId = value.conversationId,
                kind = "direct",
                canonical = value.canonical,
                titleCiphertext = crypto.encrypt(
                    value.title.toByteArray(StandardCharsets.UTF_8),
                    aad,
                ).toByteArray(),
                revision = value.revision,
                // Preserve the host's ordering signal.  Clamping every server timestamp to the
                // local clock would make an offline restart choose an arbitrary conversation.
                updatedAtEpochMillis = (value.updatedAtEpochSeconds * 1_000)
                    .toLong()
                    .coerceAtLeast(0L),
            ),
        )
    }

    private fun decryptCachedConversation(
        target: BotId,
        row: ConversationEntity,
    ): ConversationWire? = runCatching {
        val title = row.titleCiphertext?.let {
            String(
                crypto.decrypt(
                    EncryptedValue.fromByteArray(it),
                    conversationAad(target, row.conversationId),
                ),
                StandardCharsets.UTF_8,
            )
        } ?: "Conversation"
        ConversationWire(
            conversationId = row.conversationId,
            canonical = row.canonical,
            title = title,
            revision = row.revision,
            updatedAtEpochSeconds = row.updatedAtEpochMillis / 1_000.0,
        )
    }.getOrNull()

    private suspend fun saveMessage(
        target: BotId,
        value: ConversationMessageWire,
        nowEpochMillis: Long,
        deliveryState: String = "SENT",
    ) {
        dao.upsertMessage(
            MessageEntity(
                instanceId = target.instanceId,
                opaqueProfileId = target.opaqueProfileId,
                conversationId = value.conversationId,
                messageId = value.messageId,
                partsCiphertext = crypto.encrypt(
                    json.encodeToString(CachedMessageEnvelope(value.role, value.parts))
                        .toByteArray(StandardCharsets.UTF_8),
                    messageAad(target, value.conversationId, value.messageId),
                ).toByteArray(),
                deliveryState = deliveryState,
                revision = 0,
                createdAtEpochMillis = (value.createdAtEpochSeconds * 1_000).toLong().coerceAtLeast(nowEpochMillis),
            ),
        )
    }

    private suspend fun saveRun(target: BotId, value: RunWire, nowEpochMillis: Long) {
        val conversationId = value.conversationId ?: return
        val requested = RunEntity(
            instanceId = target.instanceId,
            opaqueProfileId = target.opaqueProfileId,
            conversationId = conversationId,
            runId = value.runId,
            state = value.state,
            transportState = "connected",
            attentionState = if (value.state.equals("indeterminate", ignoreCase = true) ||
                value.state.equals("failed", ignoreCase = true)
            ) {
                "failed"
            } else {
                "none"
            },
            revision = (value.updatedAtEpochSeconds?.times(1_000))?.toLong() ?: nowEpochMillis,
            updatedAtEpochMillis = ((value.updatedAtEpochSeconds ?: nowEpochMillis / 1_000.0) * 1_000).toLong()
                .coerceAtLeast(nowEpochMillis),
            cancelRequested = value.cancelRequested,
            completedExternalSideEffectsNotUndone = value.completedExternalSideEffectsNotUndone,
        )
        database.withTransaction {
            val current = dao.findRun(
                instanceId = target.instanceId,
                opaqueProfileId = target.opaqueProfileId,
                conversationId = conversationId,
                runId = value.runId,
            )
            dao.upsertRun(current?.let { mergeRunProjection(it, requested) } ?: requested)
        }
    }

    private fun RunEntity.toRunWire(): RunWire = RunWire(
        runId = runId,
        conversationId = conversationId,
        state = state,
        cancelRequested = cancelRequested,
        completedExternalSideEffectsNotUndone = completedExternalSideEffectsNotUndone,
        createdAtEpochSeconds = updatedAtEpochMillis / 1_000.0,
        updatedAtEpochSeconds = updatedAtEpochMillis / 1_000.0,
    )

    private fun decodePart(element: JsonElement): MessagePart? {
        val obj = element as? JsonObject ?: return null
        val type = obj["type"]?.jsonPrimitive?.content ?: return null
        fun text(name: String): String? = obj[name]?.jsonPrimitive?.content
        return runCatching {
            when (type) {
                "text" -> text("text")?.let(MessagePart::Text)
                "link" -> text("url")?.let { MessagePart.Link(it, text("title")) }
                "image" -> text("attachment_id")?.let { MessagePart.Image(it, text("alt_text")) }
                "file" -> text("attachment_id")?.let { MessagePart.File(it, text("display_name")) }
                "audio" -> text("attachment_id")?.let {
                    MessagePart.Audio(it, text("duration_ms")?.toLongOrNull() ?: 0, text("transcript"))
                }
                "toolEvent" -> text("event_id")?.let {
                    MessagePart.ToolEvent(it, text("label") ?: "Tool", text("state") ?: "unknown")
                }
                "approval" -> text("request_id")?.let {
                    MessagePart.Approval(it, text("title") ?: "Approval", text("expires_at")?.toLongOrNull() ?: 0)
                }
                "artifact" -> text("artifact_id")?.let {
                    MessagePart.Artifact(it, text("display_name") ?: "Artifact", text("mime_type") ?: "application/octet-stream")
                }
                else -> null
            }
        }.getOrNull()
    }

    private fun conversationAad(target: BotId, conversationId: String): ByteArray =
        "conversation:${target.instanceId}:${target.opaqueProfileId}:$conversationId".toByteArray(StandardCharsets.UTF_8)

    private fun messageAad(target: BotId, conversationId: String, messageId: String): ByteArray =
        "message:${target.instanceId}:${target.opaqueProfileId}:$conversationId:$messageId".toByteArray(StandardCharsets.UTF_8)

    private fun draftAad(target: BotId, conversationId: String): ByteArray =
        "draft:${target.instanceId}:${target.opaqueProfileId}:$conversationId".toByteArray(StandardCharsets.UTF_8)

    companion object {
        private const val PENDING_CONVERSATION_ID = "pending-conversation"
        private const val MAX_MESSAGE_LENGTH = 32_000
        private val json = Json { ignoreUnknownKeys = true; explicitNulls = false }
    }
}

data class SendTextResult(
    val conversationId: String,
    val runId: String,
    val state: String,
    val responseText: String?,
    val operationId: String,
)
