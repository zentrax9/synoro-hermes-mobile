package com.hermes.mobile.data

import com.hermes.mobile.auth.MobileEnrollmentCoordinator
import com.hermes.mobile.contract.BotId
import com.hermes.mobile.contract.IdempotencyKey
import com.hermes.mobile.contract.OpaqueId
import com.hermes.mobile.network.HermesApiClient
import com.hermes.mobile.network.HermesApiException
import com.hermes.mobile.network.HermesAuthExpiredException
import com.hermes.mobile.network.IdempotencyKeys
import com.hermes.mobile.network.RoutineListResponse
import com.hermes.mobile.network.RoutinePauseRequest
import com.hermes.mobile.network.RoutineWire
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * A small seam around the typed routine endpoints.  The production adapter below is deliberately
 * private: callers only get the profile-scoped operations needed by the routines screen and cannot
 * supply an arbitrary mobile route.
 */
internal interface RoutineRemote {
    suspend fun listRoutines(opaqueProfileId: String): RoutineListResponse

    suspend fun setRoutinePaused(
        opaqueProfileId: String,
        routineId: String,
        request: RoutinePauseRequest,
        ifMatch: String,
        idempotencyKey: IdempotencyKey,
    ): RoutineWire
}

/** Auth/session seam kept internal so repository tests do not need a Keystore-backed session. */
internal interface RoutineSession {
    suspend fun ensureUsable(target: BotId, nowEpochMillis: Long)
}

/** Durable journal seam; the real implementation encrypts request bodies in Room. */
internal interface RoutineMutationJournal {
    suspend fun loadLatest(
        instanceId: String,
        opaqueProfileId: String,
        routineId: String,
        scope: String,
    ): PendingIdempotency?

    suspend fun persistBeforeAttempt(
        instanceId: String,
        opaqueProfileId: String,
        routineId: String,
        scope: String,
        key: IdempotencyKey,
        requestBody: String,
        createdAtEpochMillis: Long,
    )

    suspend fun delete(
        instanceId: String,
        opaqueProfileId: String,
        routineId: String,
        scope: String,
        key: IdempotencyKey,
    )
}

/** Queryable metadata for one routine mutation that still owns its encrypted request material. */
data class PendingRoutineMutation(
    val routineId: String,
    val requestedPaused: Boolean,
    val state: String,
)

/**
 * Authenticated, profile-scoped routine reads and pause/resume mutations.
 *
 * Routine definitions are intentionally not cached.  Only a mutation's exact request body and
 * idempotency key are journaled before the network attempt, allowing an explicit retry when the
 * response is lost without silently sending a second mutation.  A revision conflict is surfaced
 * to the caller and is never retried with a fresh ETag in this class.
 */
@Singleton
class RoutineRepository private constructor(
    private val remote: RoutineRemote,
    private val session: RoutineSession,
    private val mutations: RoutineMutationJournal,
    private val clockMillis: () -> Long,
    private val operationStore: MobileOperationStore?,
    @Suppress("UNUSED_PARAMETER") marker: Unit,
) {
    /** Hilt production constructor using the existing authenticated Hermes client. */
    @Inject
    constructor(
        api: HermesApiClient,
        authSession: HermesAuthSession,
        enrollment: MobileEnrollmentCoordinator,
        idempotency: IdempotencyStore,
        operations: MobileOperationStore,
    ) : this(
        remote = HermesRoutineRemote(api),
        session = AuthenticatedRoutineSession(authSession, enrollment),
        mutations = IdempotencyRoutineMutationJournal(idempotency),
        clockMillis = { System.currentTimeMillis() },
        operationStore = operations,
        marker = Unit,
    )

    /** Focused constructor for JVM tests; production callers should use the Hilt constructor. */
    internal constructor(
        remote: RoutineRemote,
        session: RoutineSession,
        mutations: RoutineMutationJournal,
        clockMillis: () -> Long = { System.currentTimeMillis() },
    ) : this(remote, session, mutations, clockMillis, null, Unit)

    suspend fun listRoutines(
        target: BotId,
        nowEpochMillis: Long = clockMillis(),
    ): List<RoutineWire> {
        require(nowEpochMillis >= 0) { "routine request time must not be negative" }
        requireOpaqueTarget(target)
        session.ensureUsable(target, nowEpochMillis)
        val response = remote.listRoutines(target.opaqueProfileId)
        validateList(response)
        return response.routines
    }

    /** Alias that reads naturally at the UI boundary. */
    suspend fun list(
        target: BotId,
        nowEpochMillis: Long = clockMillis(),
    ): List<RoutineWire> = listRoutines(target, nowEpochMillis)

    /** Refresh is a network read; no local routine snapshot is consulted or updated. */
    suspend fun refresh(
        target: BotId,
        nowEpochMillis: Long = clockMillis(),
    ): List<RoutineWire> = listRoutines(target, nowEpochMillis)

    /**
     * Returns the durable pause/resume intent for one routine without reading routine content
     * from a cache.  The UI uses this after a process restart to expose an explicit retry button;
     * the encrypted body and original ETag remain owned by [MobileOperationStore].
     */
    suspend fun pendingMutation(
        target: BotId,
        routineId: String,
    ): PendingRoutineMutation? {
        requireOpaqueTarget(target)
        OpaqueId.require(routineId, "routineId")
        val store = operationStore ?: return null
        val candidates = listOf(
            MobileOperationKinds.ROUTINE_PAUSE,
            MobileOperationKinds.ROUTINE_RESUME,
        ).mapNotNull { kind ->
            store.findActive(
                instanceId = target.instanceId,
                opaqueProfileId = target.opaqueProfileId,
                conversationId = routineId,
                kind = kind,
            )
        }
        val operation = candidates.maxByOrNull { it.updatedAtEpochMillis } ?: return null
        val handle = store.load(target.instanceId, target.opaqueProfileId, operation.operationId)
            ?: return null
        if (handle.requestBody.isBlank() || handle.originalEtag.isNullOrBlank()) return null
        val request = json.decodeFromString<RoutinePauseRequest>(handle.requestBody)
        return PendingRoutineMutation(
            routineId = routineId,
            requestedPaused = request.paused,
            state = operation.state,
        )
    }

    suspend fun pauseRoutine(
        target: BotId,
        routine: RoutineWire,
        nowEpochMillis: Long = clockMillis(),
    ): RoutineWire = setPaused(target, routine, paused = true, nowEpochMillis)

    suspend fun resumeRoutine(
        target: BotId,
        routine: RoutineWire,
        nowEpochMillis: Long = clockMillis(),
    ): RoutineWire = setPaused(target, routine, paused = false, nowEpochMillis)

    /** Explicitly sets the host-owned pause flag using the routine's current ETag. */
    suspend fun setPaused(
        target: BotId,
        routine: RoutineWire,
        paused: Boolean,
        nowEpochMillis: Long = clockMillis(),
    ): RoutineWire {
        require(nowEpochMillis >= 0) { "routine request time must not be negative" }
        requireOpaqueTarget(target)
        validateRoutine(routine)
        session.ensureUsable(target, nowEpochMillis)

        operationStore?.let {
            return setPausedWithDurableOperation(
                target = target,
                routine = routine,
                paused = paused,
                nowEpochMillis = nowEpochMillis,
                operations = it,
            )
        }

        val request = RoutinePauseRequest(paused = paused)
        val requestBody = json.encodeToString(request)
        // Revision is part of the journal scope.  If a later refresh observes a new revision, it
        // cannot accidentally reuse an unresolved request that was bound to an older ETag.
        val scope = routineRoute(target, routine) + "?revision=${routine.revision}"
        val pending = mutations.loadLatest(
            instanceId = target.instanceId,
            opaqueProfileId = target.opaqueProfileId,
            routineId = routine.routineId,
            scope = scope,
        )?.takeIf { it.requestBody == requestBody }
        val key = pending?.key ?: IdempotencyKeys.generate()
        if (pending == null) {
            mutations.persistBeforeAttempt(
                instanceId = target.instanceId,
                opaqueProfileId = target.opaqueProfileId,
                routineId = routine.routineId,
                scope = scope,
                key = key,
                requestBody = requestBody,
                createdAtEpochMillis = nowEpochMillis,
            )
        }

        // Do not catch or retry this call.  Any exception leaves the encrypted journal entry so
        // the caller can make an explicit retry with the same key/body/ETag.
        val result = remote.setRoutinePaused(
            opaqueProfileId = target.opaqueProfileId,
            routineId = routine.routineId,
            request = request,
            ifMatch = routine.etag,
            idempotencyKey = key,
        )
        validateMutationResult(previous = routine, requestedPaused = paused, result = result)

        // A result is only acknowledged after semantic validation.  A malformed host response
        // remains retryable rather than allowing an uncertain mutation to be forgotten.
        mutations.delete(
            instanceId = target.instanceId,
            opaqueProfileId = target.opaqueProfileId,
            routineId = routine.routineId,
            scope = scope,
            key = key,
        )
        return result
    }

    /**
     * Production mutation path.  The existing idempotency body and the original ETag are
     * encrypted before the first PATCH and are reused verbatim after a lost response.
     */
    private suspend fun setPausedWithDurableOperation(
        target: BotId,
        routine: RoutineWire,
        paused: Boolean,
        nowEpochMillis: Long,
        operations: MobileOperationStore,
    ): RoutineWire {
        val request = RoutinePauseRequest(paused = paused)
        val requestBody = json.encodeToString(request)
        val kind = if (paused) {
            MobileOperationKinds.ROUTINE_PAUSE
        } else {
            MobileOperationKinds.ROUTINE_RESUME
        }
        val oppositeKind = if (paused) {
            MobileOperationKinds.ROUTINE_RESUME
        } else {
            MobileOperationKinds.ROUTINE_PAUSE
        }
        val route = routineRoute(target, routine)
        val existing = operations.findActive(
            instanceId = target.instanceId,
            opaqueProfileId = target.opaqueProfileId,
            conversationId = routine.routineId,
            kind = kind,
        )
        // Pause and resume are separate operation kinds, but they still target one routine row.
        // Never allow a fresh opposite action to race an unresolved original mutation after a
        // process restart or a host response loss.
        if (existing == null && operations.findActive(
                instanceId = target.instanceId,
                opaqueProfileId = target.opaqueProfileId,
                conversationId = routine.routineId,
                kind = oppositeKind,
            ) != null
        ) {
            throw MobileOperationInProgressException()
        }
        val operation = existing ?: operations.begin(
            instanceId = target.instanceId,
            opaqueProfileId = target.opaqueProfileId,
            kind = kind,
            conversationId = routine.routineId,
            resourceId = routine.routineId,
            idempotencyScope = route,
            idempotencyKey = IdempotencyKeys.generate(),
            requestBody = requestBody,
            originalEtag = routine.etag,
            nowEpochMillis = nowEpochMillis,
        )
        val handle = operations.load(target.instanceId, target.opaqueProfileId, operation.operationId)
            ?: throw IllegalStateException("routine operation disappeared before the request")
        require(handle.requestBody.isNotBlank() && handle.originalEtag != null) {
            "the original routine request is unavailable; refresh before retrying"
        }
        val storedRequest = json.decodeFromString<RoutinePauseRequest>(handle.requestBody)
        require(storedRequest.paused == paused) {
            "routine operation does not match the requested pause state"
        }
        val key = IdempotencyKey(operation.idempotencyKey)
        return try {
            operations.update(
                operation,
                state = MobileOperationStates.SENDING,
                nowEpochMillis = nowEpochMillis,
            )
            val result = remote.setRoutinePaused(
                opaqueProfileId = target.opaqueProfileId,
                routineId = routine.routineId,
                request = storedRequest,
                ifMatch = requireNotNull(handle.originalEtag),
                idempotencyKey = key,
            )
            validateMutationResult(previous = routine, requestedPaused = paused, result = result)
            operations.retire(operation, nowEpochMillis)
            result
        } catch (error: HermesApiException) {
            if (error.statusCode == 409) {
                // A stale ETag is deterministic.  Retire the old request material so a later
                // action must bind a newly refreshed ETag and receive a new idempotency key.
                operations.retire(
                    operation,
                    nowEpochMillis,
                    terminalState = MobileOperationStates.CONFLICT,
                )
            } else {
                operations.update(
                    operation,
                    state = MobileOperationStates.UNCERTAIN,
                    nowEpochMillis = nowEpochMillis,
                )
            }
            throw error
        } catch (error: Exception) {
            operations.update(operation, state = MobileOperationStates.UNCERTAIN, nowEpochMillis = nowEpochMillis)
            throw error
        }
    }

    private fun validateList(response: RoutineListResponse) {
        require(response.routines.size <= MAX_ROUTINES) {
            "host returned too many routines"
        }
        response.routines.forEach(::validateRoutine)
        require(response.routines.map { it.routineId }.distinct().size == response.routines.size) {
            "host returned duplicate routine identifiers"
        }
    }

    private fun validateMutationResult(
        previous: RoutineWire,
        requestedPaused: Boolean,
        result: RoutineWire,
    ) {
        validateRoutine(result)
        require(result.routineId == previous.routineId) {
            "host returned a different routine"
        }
        require(result.paused == requestedPaused) {
            "host returned the wrong routine pause state"
        }
        require(result.revision >= previous.revision) {
            "host regressed the routine revision"
        }
        require(result.label == previous.label && result.summary == previous.summary) {
            "host returned different routine metadata"
        }
    }

    private fun validateRoutine(routine: RoutineWire) {
        OpaqueId.require(routine.routineId, "routineId")
        require(routine.revision >= 1) { "routine revision is invalid" }
        require(routine.etag.length <= MAX_ETAG_LENGTH && ROUTINE_ETAG.matches(routine.etag)) {
            "routine ETag is invalid"
        }
    }

    private fun routineRoute(target: BotId, routine: RoutineWire): String {
        OpaqueId.require(target.opaqueProfileId, "opaqueProfileId")
        OpaqueId.require(routine.routineId, "routineId")
        return "mobile/v1/profiles/${target.opaqueProfileId}/routines/${routine.routineId}"
    }

    private fun requireOpaqueTarget(target: BotId) {
        OpaqueId.require(target.instanceId, "instanceId")
        OpaqueId.require(target.opaqueProfileId, "opaqueProfileId")
    }

    private companion object {
        const val MAX_ROUTINES = 10_000
        const val MAX_ETAG_LENGTH = 128
        val ROUTINE_ETAG = Regex("^\"routine-[1-9][0-9]*\"$")
        val json = Json { explicitNulls = false }
    }
}

private class HermesRoutineRemote(
    private val api: HermesApiClient,
) : RoutineRemote {
    override suspend fun listRoutines(opaqueProfileId: String): RoutineListResponse =
        api.listRoutines(opaqueProfileId)

    override suspend fun setRoutinePaused(
        opaqueProfileId: String,
        routineId: String,
        request: RoutinePauseRequest,
        ifMatch: String,
        idempotencyKey: IdempotencyKey,
    ): RoutineWire = api.pauseRoutine(
        opaqueProfileId = opaqueProfileId,
        routineId = routineId,
        request = request,
        ifMatch = ifMatch,
        idempotencyKey = idempotencyKey,
    )
}

private class AuthenticatedRoutineSession(
    private val authSession: HermesAuthSession,
    private val enrollment: MobileEnrollmentCoordinator,
) : RoutineSession {
    override suspend fun ensureUsable(target: BotId, nowEpochMillis: Long) {
        require(nowEpochMillis >= 0) { "routine request time must not be negative" }
        if (authSession.current() == null &&
            !authSession.restore(target.instanceId, target.opaqueProfileId)
        ) {
            throw HermesAuthExpiredException()
        }
        val material = authSession.current() ?: throw HermesAuthExpiredException()
        val nowEpochSeconds = nowEpochMillis / 1_000
        if (material.hermesDeviceToken.isUsable(nowEpochSeconds)) return
        val deviceId = authSession.currentDeviceId() ?: throw HermesAuthExpiredException()
        enrollment.refreshApprovedSession(
            instanceId = target.instanceId,
            opaqueProfileId = target.opaqueProfileId,
            cloudflareAccessToken = material.cloudflareAccessToken,
            deviceId = deviceId,
            nowEpochMillis = nowEpochMillis,
        )
    }
}

private class IdempotencyRoutineMutationJournal(
    private val store: IdempotencyStore,
) : RoutineMutationJournal {
    override suspend fun loadLatest(
        instanceId: String,
        opaqueProfileId: String,
        routineId: String,
        scope: String,
    ): PendingIdempotency? = store.loadLatest(
        instanceId = instanceId,
        opaqueProfileId = opaqueProfileId,
        conversationId = routineId,
        scope = scope,
    )

    override suspend fun persistBeforeAttempt(
        instanceId: String,
        opaqueProfileId: String,
        routineId: String,
        scope: String,
        key: IdempotencyKey,
        requestBody: String,
        createdAtEpochMillis: Long,
    ) {
        store.persistBeforeAttempt(
            instanceId = instanceId,
            opaqueProfileId = opaqueProfileId,
            conversationId = routineId,
            scope = scope,
            key = key,
            requestBody = requestBody,
            createdAtEpochMillis = createdAtEpochMillis,
        )
    }

    override suspend fun delete(
        instanceId: String,
        opaqueProfileId: String,
        routineId: String,
        scope: String,
        key: IdempotencyKey,
    ) {
        store.delete(
            instanceId = instanceId,
            opaqueProfileId = opaqueProfileId,
            conversationId = routineId,
            scope = scope,
            key = key,
        )
    }
}
