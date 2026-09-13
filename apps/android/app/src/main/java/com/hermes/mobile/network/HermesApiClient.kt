package com.hermes.mobile.network

import com.hermes.mobile.contract.IdempotencyKey
import com.hermes.mobile.contract.OpaqueId
import java.io.Closeable
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.Call
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Response

class HermesApiException(
    val statusCode: Int,
    val errorCode: String? = null,
) : IOException("Hermes mobile request failed with HTTP $statusCode")

/**
 * Owns both halves of a long-lived SSE request. Closing the response releases the body; cancelling
 * the call also interrupts a blocking read when the foreground ViewModel is stopped.
 */
class HermesEventStream internal constructor(
    private val call: Call,
    val response: Response,
) : Closeable {
    override fun close() {
        call.cancel()
        response.close()
    }
}

@Serializable
private data class AttachmentCompletionRequest(
    @SerialName("total_bytes")
    val totalBytes: Long,
    val sha256: String,
)

@Serializable
private data class NewConversationRequest(val canonical: Boolean = true)

private val GROUP_REVISION = Regex("^\"group-[1-9][0-9]*\"$")
private const val MAX_ERROR_BODY_BYTES = 4_096L

/**
 * Extracts only the small allow-list of protocol codes used by direct-send recovery.  Error
 * details are intentionally not returned to callers: host error bodies can contain sensitive or
 * implementation-specific text, while the state machine only needs these two stable signals.
 */
internal fun parseMobileErrorCode(body: String): String? {
    val payload = runCatching {
        Json { ignoreUnknownKeys = true }.parseToJsonElement(body) as? JsonObject
    }.getOrNull() ?: return null
    val candidates = sequenceOf("error_code", "code", "detail")
        .mapNotNull { key ->
            runCatching { payload[key]?.jsonPrimitive?.contentOrNull }
                .getOrNull()
                ?.trim()
                ?.lowercase()
                ?.takeIf(String::isNotBlank)
        }
    for (candidate in candidates) {
        when (candidate) {
            MobileApiErrorCodes.IDEMPOTENCY_KEY_CONFLICT,
            "idempotency key conflict",
            "idempotency-key-conflict",
            "idempotency conflict",
            -> return MobileApiErrorCodes.IDEMPOTENCY_KEY_CONFLICT
            MobileApiErrorCodes.MESSAGE_INDETERMINATE,
            "mobile message indeterminate",
            "mobile mutation is indeterminate",
            -> return MobileApiErrorCodes.MESSAGE_INDETERMINATE
        }
    }
    return null
}

/** Typed, read-first mobile transport. It never retries a mutation implicitly. */
class HermesApiClient @javax.inject.Inject constructor(
    private val httpClient: OkHttpClient,
    private val requestFactory: HermesRequestFactory,
) {
    suspend fun listProfiles(): MobileProfilesResponse = executeJson(
        requestFactory.get(MobileApiPaths.PROFILES),
    )

    suspend fun enrollDevice(
        cloudflareAccessToken: String,
        request: DeviceEnrollmentRequest,
    ): DeviceEnrollmentResponse = executeJson(
        requestFactory.postJsonWithAccessToken(
            MobileApiPaths.DEVICES,
            json.encodeToString(request),
            cloudflareAccessToken,
        ),
    )

    suspend fun listDevices(cloudflareAccessToken: String): MobileDevicesResponse = executeJson(
        requestFactory.getWithAccessToken(MobileApiPaths.DEVICES, cloudflareAccessToken),
    )

    suspend fun createDeviceTokenChallenge(
        cloudflareAccessToken: String,
        deviceId: String,
    ): DeviceTokenChallengeResponse = executeJson(
        requestFactory.postJsonWithAccessToken(
            "${MobileApiPaths.DEVICES}/$deviceId/token/challenge",
            "{}",
            cloudflareAccessToken,
        ),
    )

    suspend fun issueDeviceToken(
        cloudflareAccessToken: String,
        deviceId: String,
        request: DeviceTokenRequest,
    ): DeviceTokenResponse = executeJson(
        requestFactory.postJsonWithAccessToken(
            "${MobileApiPaths.DEVICES}/$deviceId/token",
            json.encodeToString(request),
            cloudflareAccessToken,
        ),
    )

    suspend fun createConversation(
        opaqueProfileId: String,
        canonical: Boolean,
        idempotencyKey: IdempotencyKey,
    ): ConversationWire = executeJson(
        requestFactory.postJson(
            "${MobileApiPaths.PROFILES}/$opaqueProfileId/conversations",
            json.encodeToString(NewConversationRequest(canonical)),
            idempotencyKey,
        ),
    )

    suspend fun createConversationBody(
        opaqueProfileId: String,
        jsonBody: String,
        idempotencyKey: IdempotencyKey,
    ): ConversationWire = executeJson(
        requestFactory.postJson(
            "${MobileApiPaths.PROFILES}/$opaqueProfileId/conversations",
            jsonBody,
            idempotencyKey,
        ),
    )

    suspend fun listConversations(opaqueProfileId: String): ConversationsResponse = executeJson(
        requestFactory.get("${MobileApiPaths.PROFILES}/$opaqueProfileId/conversations"),
    )

    suspend fun fetchConversationHistory(
        opaqueProfileId: String,
        conversationId: String,
    ): ConversationHistoryResponse = executeJson(
        requestFactory.get(
            "${MobileApiPaths.PROFILES}/$opaqueProfileId/conversations/$conversationId/messages",
        ),
    )

    suspend fun getMessageStatus(
        opaqueProfileId: String,
        conversationId: String,
        idempotencyKey: IdempotencyKey,
    ): MessageStatusResponse = executeJson(
        requestFactory.getWithHeaders(
            "${MobileApiPaths.PROFILES}/$opaqueProfileId/conversations/$conversationId/message-status",
            headers = mapOf("Idempotency-Key" to idempotencyKey.value),
        ),
    )

    suspend fun sendMessage(
        opaqueProfileId: String,
        conversationId: String,
        request: ChatSendRequest,
        idempotencyKey: IdempotencyKey,
    ): ChatSendResponse = executeJson(
        requestFactory.postJson(
            "${MobileApiPaths.PROFILES}/$opaqueProfileId/conversations/$conversationId/messages",
            json.encodeToString(request),
            idempotencyKey,
        ),
    )

    suspend fun sendMessageBody(
        opaqueProfileId: String,
        conversationId: String,
        jsonBody: String,
        idempotencyKey: IdempotencyKey,
    ): ChatSendResponse = executeJson(
        requestFactory.postJson(
            "${MobileApiPaths.PROFILES}/$opaqueProfileId/conversations/$conversationId/messages",
            jsonBody,
            idempotencyKey,
        ),
    )

    suspend fun declareAttachmentBody(
        jsonBody: String,
        idempotencyKey: IdempotencyKey,
    ): AttachmentDeclarationResponse = executeJson(
        requestFactory.postJson(MobileApiPaths.ATTACHMENTS, jsonBody, idempotencyKey),
    )

    suspend fun createGroup(
        request: GroupCreateRequest,
        idempotencyKey: IdempotencyKey,
    ): GroupResponse = executeJson(
        requestFactory.postJson(
            MobileApiPaths.GROUPS,
            json.encodeToString(request),
            idempotencyKey,
        ),
    )

    suspend fun listGroups(cursor: String? = null): GroupListResponse = executeJson(
        requestFactory.get(
            MobileApiPaths.GROUPS,
            cursor?.let { mapOf("cursor" to it) } ?: emptyMap(),
        ),
    )

    suspend fun getGroup(groupId: String): GroupResponse {
        OpaqueId.require(groupId, "groupId")
        return executeJson(
            requestFactory.get("${MobileApiPaths.GROUPS}/$groupId"),
        )
    }

    suspend fun stopGroup(groupId: String, idempotencyKey: IdempotencyKey): GroupResponse {
        OpaqueId.require(groupId, "groupId")
        return executeJson(
            requestFactory.postJson(
                "${MobileApiPaths.GROUPS}/$groupId/stop",
                "{}",
                idempotencyKey,
            ),
        )
    }

    suspend fun addGroupMember(
        groupId: String,
        request: GroupMemberAddRequest,
        ifMatch: String,
        idempotencyKey: IdempotencyKey,
    ): GroupResponse {
        OpaqueId.require(groupId, "groupId")
        requireGroupRevision(ifMatch)
        return executeJson(
            requestFactory.postJson(
                "${MobileApiPaths.GROUPS}/$groupId/members",
                json.encodeToString(request),
                idempotencyKey,
                headers = mapOf("If-Match" to ifMatch),
            ),
        )
    }

    suspend fun removeGroupMember(
        groupId: String,
        memberId: String,
        ifMatch: String,
        idempotencyKey: IdempotencyKey,
    ): GroupResponse {
        OpaqueId.require(groupId, "groupId")
        OpaqueId.require(memberId, "memberId")
        requireGroupRevision(ifMatch)
        return executeJson(
            requestFactory.delete(
                "${MobileApiPaths.GROUPS}/$groupId/members/$memberId",
                idempotencyKey,
                headers = mapOf("If-Match" to ifMatch),
            ),
        )
    }

    suspend fun sendGroupMessage(
        groupId: String,
        request: GroupMessageRequest,
        idempotencyKey: IdempotencyKey,
    ): GroupMessageResponse {
        OpaqueId.require(groupId, "groupId")
        return executeJson(
            requestFactory.postJson(
                "${MobileApiPaths.GROUPS}/$groupId/messages",
                json.encodeToString(request),
                idempotencyKey,
            ),
        )
    }

    suspend fun getRun(runId: String): RunWire = executeJson(
        requestFactory.get("${MobileApiPaths.RUNS}/$runId"),
    )

    suspend fun getRunEvents(runId: String): RunEventsResponse = executeJson(
        requestFactory.get("${MobileApiPaths.RUNS}/$runId/events"),
    )

    suspend fun cancelRun(runId: String, idempotencyKey: IdempotencyKey): RunWire = executeJson(
        requestFactory.postJson(
            "${MobileApiPaths.RUNS}/$runId/cancel",
            "{}",
            idempotencyKey,
        ),
    )

    suspend fun getSettings(opaqueProfileId: String): SettingsResponse = executeJson(
        requestFactory.get("${MobileApiPaths.PROFILES}/$opaqueProfileId/settings"),
    )

    suspend fun createStepUpChallenge(
        request: StepUpChallengeRequest,
    ): StepUpChallengeResponse = executeJson(
        requestFactory.postJson(
            "mobile/v1/step-up/challenges",
            json.encodeToString(request),
            IdempotencyKeys.generate(),
        ),
    )

    suspend fun createSettingsStepUpChallenge(
        opaqueProfileId: String,
        changes: JsonElement,
    ): StepUpChallengeResponse = executeJson(
        requestFactory.postJson(
            "${MobileApiPaths.PROFILES}/$opaqueProfileId/settings/step-up",
            json.encodeToString(SettingsUpdateRequest(changes)),
            IdempotencyKeys.generate(),
        ),
    )

    suspend fun updateSettings(
        opaqueProfileId: String,
        request: SettingsUpdateRequest,
        ifMatch: String,
        idempotencyKey: IdempotencyKey,
    ): SettingsResponse = executeJson(
        requestFactory.patchJson(
            "${MobileApiPaths.PROFILES}/$opaqueProfileId/settings",
            json.encodeToString(request),
            idempotencyKey,
            headers = mapOf("If-Match" to ifMatch),
        ),
    )

    suspend fun getCatalog(opaqueProfileId: String): CatalogResponse = executeJson(
        requestFactory.get("${MobileApiPaths.PROFILES}/$opaqueProfileId/catalog"),
    )

    suspend fun listRoutines(opaqueProfileId: String): RoutineListResponse = executeJson(
        requestFactory.get("${MobileApiPaths.PROFILES}/$opaqueProfileId/routines"),
    )

    suspend fun pauseRoutine(
        opaqueProfileId: String,
        routineId: String,
        request: RoutinePauseRequest,
        ifMatch: String,
        idempotencyKey: IdempotencyKey,
    ): RoutineWire = executeJson(
        requestFactory.patchJson(
            "${MobileApiPaths.PROFILES}/$opaqueProfileId/routines/$routineId",
            json.encodeToString(request),
            idempotencyKey,
            headers = mapOf("If-Match" to ifMatch),
        ),
    )

    suspend fun runRoutine(
        opaqueProfileId: String,
        routineId: String,
        request: RoutineRunRequest,
        idempotencyKey: IdempotencyKey,
    ): RoutineRunResponse = executeJson(
        requestFactory.postJson(
            "${MobileApiPaths.PROFILES}/$opaqueProfileId/routines/$routineId/run",
            json.encodeToString(request),
            idempotencyKey,
        ),
    )

    suspend fun getRoutineRun(runId: String): RoutineRunResponse = executeJson(
        requestFactory.get("mobile/v1/routine-runs/$runId"),
    )

    suspend fun cancelRoutineRun(
        runId: String,
        idempotencyKey: IdempotencyKey,
    ): RoutineRunResponse = executeJson(
        requestFactory.postJson(
            "${MobileApiPaths.RUNS}/$runId/cancel",
            "{}",
            idempotencyKey,
        ),
    )

    suspend fun getApproval(approvalId: String): ApprovalWire = executeJson(
        requestFactory.get("mobile/v1/approvals/$approvalId"),
    )

    suspend fun createApprovalStepUpChallenge(approvalId: String): StepUpChallengeResponse = executeJson(
        requestFactory.postJson(
            "mobile/v1/approvals/$approvalId/step-up",
            "{}",
            IdempotencyKeys.generate(),
        ),
    )

    suspend fun listApprovals(): ApprovalsResponse = executeJson(
        requestFactory.get("mobile/v1/approvals"),
    )

    suspend fun getRunApproval(runId: String): ApprovalWire = executeJson(
        requestFactory.get("${MobileApiPaths.RUNS}/$runId/approval"),
    )

    suspend fun approve(
        approvalId: String,
        proof: StepUpProofWire,
        idempotencyKey: IdempotencyKey,
    ): ApprovalWire = executeJson(
        requestFactory.postJson(
            "mobile/v1/approvals/$approvalId/approve",
            json.encodeToString(proof),
            idempotencyKey,
        ),
    )

    suspend fun deny(approvalId: String, idempotencyKey: IdempotencyKey): ApprovalWire = executeJson(
        requestFactory.postJson(
            "mobile/v1/approvals/$approvalId/deny",
            "{}",
            idempotencyKey,
        ),
    )

    suspend fun updateSensitiveSettings(
        opaqueProfileId: String,
        changes: JsonElement,
        proof: StepUpProofWire,
        ifMatch: String,
        idempotencyKey: IdempotencyKey,
    ): SettingsResponse = executeJson(
        requestFactory.patchJson(
            "${MobileApiPaths.PROFILES}/$opaqueProfileId/settings/sensitive",
            json.encodeToString(SensitiveSettingsUpdateRequest(changes, proof)),
            idempotencyKey,
            headers = mapOf("If-Match" to ifMatch),
        ),
    )

    suspend fun fetchSync(
        instanceId: String,
        opaqueProfileId: String,
        cursor: Long,
        snapshot: Boolean = false,
    ): SyncBatch {
        require(cursor >= 0)
        val request = requestFactory.get(
            MobileApiPaths.SYNC,
            mapOf(
                "instance_id" to instanceId,
                "profile_id" to opaqueProfileId,
                "cursor" to cursor.toString(),
                "snapshot" to snapshot.toString(),
            ),
        )
        return executeJson(request, cursorExpired = true)
    }

    suspend fun openEventStream(
        instanceId: String,
        opaqueProfileId: String,
        afterCursor: Long,
    ): HermesEventStream = withContext(Dispatchers.IO) {
        require(afterCursor >= 0)
        val request = requestFactory.get(
            MobileApiPaths.EVENTS,
            mapOf(
                "instance_id" to instanceId,
                "profile_id" to opaqueProfileId,
                "after" to afterCursor.toString(),
            ),
        ).newBuilder()
            .header("Accept", "text/event-stream")
            .build()
        val call = httpClient.newCall(request)
        val cancellationHandle = currentCoroutineContext()[Job]?.invokeOnCompletion {
            // Call.execute() blocks on headers; cancellation must reach OkHttp before a response
            // wrapper exists for SyncReconciler to close.
            call.cancel()
        }
        try {
            val response = call.execute()
            if (!response.isSuccessful) {
                val status = response.code
                call.cancel()
                response.close()
                if (status == 410) throw CursorExpiredException()
                throw HermesApiException(status)
            }
            HermesEventStream(call, response)
        } finally {
            // Once returned, HermesEventStream owns cancellation.  Before return this prevents a
            // completed request's callback from retaining the parent coroutine job.
            cancellationHandle?.dispose()
        }
    }

    suspend fun declareAttachment(
        declaration: AttachmentDeclaration,
        idempotencyKey: IdempotencyKey,
    ): AttachmentDeclarationResponse = executeJson(
        requestFactory.postJson(
            MobileApiPaths.ATTACHMENTS,
            json.encodeToString(declaration),
            idempotencyKey,
        ),
    )

    suspend fun uploadAttachmentChunk(
        serverUploadId: String,
        body: ByteArray,
        range: ContentRange,
        idempotencyKey: IdempotencyKey,
        scope: AttachmentBotId,
        conversationId: String,
    ): AttachmentChunkResponse = executeJson(
        requestFactory.putBytes(
            path = "${MobileApiPaths.ATTACHMENTS}/$serverUploadId",
            body = body,
            mediaType = OCTET_STREAM,
            idempotencyKey = idempotencyKey,
            headers = mapOf(
                "Content-Range" to range.headerValue(),
                "X-Hermes-Instance-Id" to scope.instanceId,
                "X-Hermes-Profile-Id" to scope.opaqueProfileId,
                "X-Hermes-Conversation-Id" to conversationId,
            ),
        ),
    )

    suspend fun completeAttachment(
        serverUploadId: String,
        totalBytes: Long,
        sha256: String,
        idempotencyKey: IdempotencyKey,
        scope: AttachmentBotId,
        conversationId: String,
    ): AttachmentCompletionResponse = executeJson(
        requestFactory.postJson(
            path = "${MobileApiPaths.ATTACHMENTS}/$serverUploadId/complete",
            jsonBody = json.encodeToString(AttachmentCompletionRequest(totalBytes, sha256)),
            idempotencyKey = idempotencyKey,
            headers = mapOf(
                "X-Hermes-Instance-Id" to scope.instanceId,
                "X-Hermes-Profile-Id" to scope.opaqueProfileId,
                "X-Hermes-Conversation-Id" to conversationId,
            ),
        ),
    )

    suspend fun registerFcmToken(
        deviceId: String,
        token: String,
        idempotencyKey: IdempotencyKey,
    ) = executeJson<Unit>(
        requestFactory.putJson(
            "${MobileApiPaths.DEVICES}/$deviceId/push",
            json.encodeToString(FcmRegistrationRequest(token)),
            idempotencyKey,
        ),
    )

    suspend fun revokeFcmToken(
        deviceId: String,
        idempotencyKey: IdempotencyKey,
    ) = executeJson<Unit>(
        requestFactory.delete(
            "${MobileApiPaths.DEVICES}/$deviceId/push",
            idempotencyKey,
        ),
    )

    suspend fun revokeDevice(
        deviceId: String,
        idempotencyKey: IdempotencyKey,
    ) = executeJson<Unit>(
        requestFactory.delete(
            "${MobileApiPaths.DEVICES}/$deviceId",
            idempotencyKey,
        ),
    )

    private suspend inline fun <reified T> executeJson(
        request: okhttp3.Request,
        cursorExpired: Boolean = false,
    ): T =
        withContext(Dispatchers.IO) {
            val call = httpClient.newCall(request)
            val cancellationHandle = currentCoroutineContext()[Job]?.invokeOnCompletion {
                call.cancel()
            }
            try {
                call.execute().use { response ->
                    if (!response.isSuccessful) {
                        if (cursorExpired && response.code == 410) throw CursorExpiredException()
                        val errorCode = response.body?.source()?.use { source ->
                            source.readUtf8(MAX_ERROR_BODY_BYTES)
                        }?.let(::parseMobileErrorCode)
                        throw HermesApiException(response.code, errorCode)
                    }
                    if (T::class == Unit::class) {
                        @Suppress("UNCHECKED_CAST")
                        Unit as T
                    } else {
                        val body = response.body?.string()
                            ?: throw IOException("Hermes mobile response body is missing")
                        json.decodeFromString(body)
                    }
                }
            } finally {
                cancellationHandle?.dispose()
            }
        }

    private companion object {
        val json = Json {
            ignoreUnknownKeys = true
            explicitNulls = false
        }
        val OCTET_STREAM = "application/octet-stream".toMediaType()
    }
}

private fun requireGroupRevision(ifMatch: String) {
    require(ifMatch.length <= 128 && GROUP_REVISION.matches(ifMatch)) {
        "group revision header is invalid"
    }
}
