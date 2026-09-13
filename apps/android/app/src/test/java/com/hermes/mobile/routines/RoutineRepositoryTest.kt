package com.hermes.mobile.routines

import com.hermes.mobile.contract.BotId
import com.hermes.mobile.contract.IdempotencyKey
import com.hermes.mobile.data.PendingIdempotency
import com.hermes.mobile.data.RoutineMutationJournal
import com.hermes.mobile.data.RoutineRemote
import com.hermes.mobile.data.RoutineRepository
import com.hermes.mobile.data.RoutineSession
import com.hermes.mobile.network.HermesApiException
import com.hermes.mobile.network.RoutineListResponse
import com.hermes.mobile.network.RoutinePauseRequest
import com.hermes.mobile.network.RoutineWire
import java.io.IOException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

class RoutineRepositoryTest {
    private val target = BotId("instance-123456", "profile-123456")
    private val active = routine(paused = false, revision = 1)
    private val paused = routine(paused = true, revision = 2)
    private val resumed = routine(paused = false, revision = 3)

    @Test
    fun listRoutinesUsesProfileScopeWithoutPersistingRoutineDefinitions() = runBlocking {
        val remote = FakeRoutineRemote().apply {
            listResult = RoutineListResponse(listOf(active))
        }
        val journal = FakeRoutineMutationJournal()
        val repository = repository(remote, journal)

        assertEquals(listOf(active), repository.listRoutines(target, nowEpochMillis = 10_000))
        assertEquals("profile-123456", remote.lastListedProfile)
        assertTrue(journal.entries.isEmpty())
    }

    @Test
    fun pauseAndResumeUseTypedRequestCurrentEtagAndClearAfterValidatedResponse() = runBlocking {
        val remote = FakeRoutineRemote().apply {
            mutationHandler = { request, _, _, _ -> if (request.paused) paused else resumed }
        }
        val journal = FakeRoutineMutationJournal()
        val repository = repository(remote, journal)

        val pauseResult = repository.pauseRoutine(target, active, nowEpochMillis = 10_000)
        val resumeResult = repository.resumeRoutine(target, pauseResult, nowEpochMillis = 11_000)

        assertEquals(paused, pauseResult)
        assertEquals(resumed, resumeResult)
        assertEquals(listOf(true, false), remote.mutationCalls.map { it.request.paused })
        assertEquals(listOf("\"routine-1\"", "\"routine-2\""), remote.mutationCalls.map { it.ifMatch })
        assertEquals(2, remote.mutationCalls.map { it.key }.distinct().size)
        assertTrue(journal.entries.isEmpty())
    }

    @Test
    fun lostPauseResponseRetainsExactJournalAndExplicitRetryReusesKey() = runBlocking {
        val remote = FakeRoutineRemote()
        var attempts = 0
        remote.mutationHandler = { _, _, _, _ ->
            attempts += 1
            if (attempts == 1) throw IOException("connection lost")
            paused
        }
        val journal = FakeRoutineMutationJournal()
        val repository = repository(remote, journal)

        assertThrows(IOException::class.java) {
            runBlocking { repository.pauseRoutine(target, active, nowEpochMillis = 10_000) }
        }
        assertEquals(1, journal.entries.size)
        val firstKey = remote.mutationCalls.single().key

        assertEquals(paused, repository.pauseRoutine(target, active, nowEpochMillis = 10_001))
        assertEquals(firstKey, remote.mutationCalls[1].key)
        assertEquals(2, remote.mutationCalls.size)
        assertTrue(journal.entries.isEmpty())
    }

    @Test
    fun revisionConflictDoesNotRetryOrForgetTheMutationJournal() = runBlocking {
        val remote = FakeRoutineRemote().apply {
            mutationHandler = { _, _, _, _ -> throw HermesApiException(409) }
        }
        val journal = FakeRoutineMutationJournal()
        val repository = repository(remote, journal)

        assertThrows(HermesApiException::class.java) {
            runBlocking { repository.pauseRoutine(target, active, nowEpochMillis = 10_000) }
        }
        assertEquals(1, remote.mutationCalls.size)
        assertEquals(1, journal.entries.size)
        assertTrue(journal.deletedKeys.isEmpty())
    }

    @Test
    fun malformedListResponseIsRejectedBeforeItReachesTheUi() = runBlocking {
        val remote = FakeRoutineRemote().apply {
            listResult = RoutineListResponse(listOf(active, active))
        }
        val repository = repository(remote, FakeRoutineMutationJournal())

        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { repository.listRoutines(target, nowEpochMillis = 10_000) }
        }
    }

    private fun repository(
        remote: FakeRoutineRemote,
        journal: FakeRoutineMutationJournal,
    ): RoutineRepository = RoutineRepository(
        remote = remote,
        session = NoopRoutineSession,
        mutations = journal,
        clockMillis = { 10_000 },
    )

    private fun routine(paused: Boolean, revision: Long): RoutineWire = RoutineWire(
        routineId = "routine-123456",
        label = "Daily check",
        summary = "Review the host routine",
        paused = paused,
        revision = revision,
        etag = "\"routine-$revision\"",
    )
}

private object NoopRoutineSession : RoutineSession {
    override suspend fun ensureUsable(target: BotId, nowEpochMillis: Long) = Unit
}

private class FakeRoutineRemote : RoutineRemote {
    var listResult = RoutineListResponse()
    var lastListedProfile: String? = null
    var mutationHandler: suspend (RoutinePauseRequest, String, String, IdempotencyKey) -> RoutineWire =
        { _, _, _, _ -> error("mutation handler not configured") }
    val mutationCalls = mutableListOf<MutationCall>()

    override suspend fun listRoutines(opaqueProfileId: String): RoutineListResponse {
        lastListedProfile = opaqueProfileId
        return listResult
    }

    override suspend fun setRoutinePaused(
        opaqueProfileId: String,
        routineId: String,
        request: RoutinePauseRequest,
        ifMatch: String,
        idempotencyKey: IdempotencyKey,
    ): RoutineWire {
        mutationCalls += MutationCall(request, opaqueProfileId, routineId, ifMatch, idempotencyKey)
        return mutationHandler(request, opaqueProfileId, routineId, idempotencyKey)
    }
}

private data class MutationCall(
    val request: RoutinePauseRequest,
    val profileId: String,
    val routineId: String,
    val ifMatch: String,
    val key: IdempotencyKey,
)

private class FakeRoutineMutationJournal : RoutineMutationJournal {
    val entries = linkedMapOf<JournalKey, PendingIdempotency>()
    val deletedKeys = mutableListOf<IdempotencyKey>()

    override suspend fun loadLatest(
        instanceId: String,
        opaqueProfileId: String,
        routineId: String,
        scope: String,
    ): PendingIdempotency? = entries[JournalKey(instanceId, opaqueProfileId, routineId, scope)]

    override suspend fun persistBeforeAttempt(
        instanceId: String,
        opaqueProfileId: String,
        routineId: String,
        scope: String,
        key: IdempotencyKey,
        requestBody: String,
        createdAtEpochMillis: Long,
    ) {
        entries[JournalKey(instanceId, opaqueProfileId, routineId, scope)] = PendingIdempotency(
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
        deletedKeys += key
        entries.remove(JournalKey(instanceId, opaqueProfileId, routineId, scope))
    }
}

private data class JournalKey(
    val instanceId: String,
    val profileId: String,
    val routineId: String,
    val scope: String,
)
