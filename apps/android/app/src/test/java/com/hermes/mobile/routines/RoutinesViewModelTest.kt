package com.hermes.mobile.routines

import com.hermes.mobile.contract.BotId
import com.hermes.mobile.data.PendingRoutineMutation
import com.hermes.mobile.network.HermesApiException
import com.hermes.mobile.network.HermesAuthExpiredException
import com.hermes.mobile.network.RoutineWire
import com.hermes.mobile.ui.RoutineErrorKind
import com.hermes.mobile.ui.RoutineMutationPhase
import com.hermes.mobile.ui.RoutineOperations
import com.hermes.mobile.ui.RoutinesContentState
import com.hermes.mobile.ui.RoutinesViewModel
import java.io.IOException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RoutinesViewModelTest {
    private val target = BotId("instance-123456", "profile-123456")
    private val active = routine(paused = false, revision = 1)
    private val paused = routine(paused = true, revision = 2)
    private val resumed = routine(paused = false, revision = 3)

    @Test
    fun loadExposesLoadingThenReadyState() {
        val gate = CompletableDeferred<Unit>()
        val operations = FakeRoutineOperations().apply {
            listGate = gate
            listResult = listOf(active)
        }
        val scope = testScope()
        val viewModel = RoutinesViewModel(operations, { 10_000 }, scope)

        viewModel.load(target)
        assertEquals(RoutinesContentState.LOADING, viewModel.uiState.value.contentState)
        assertTrue(viewModel.uiState.value.isLoading)

        gate.complete(Unit)
        assertEquals(RoutinesContentState.READY, viewModel.uiState.value.contentState)
        assertEquals(listOf(active.routineId), viewModel.uiState.value.routines.map { it.routineId })
        scope.cancel()
    }

    @Test
    fun emptyResponseIsDistinctFromUnavailableHost() {
        val emptyOps = FakeRoutineOperations().apply { listResult = emptyList() }
        val emptyScope = testScope()
        val emptyViewModel = RoutinesViewModel(emptyOps, { 10_000 }, emptyScope)
        emptyViewModel.load(target)
        assertEquals(RoutinesContentState.EMPTY, emptyViewModel.uiState.value.contentState)
        assertTrue(emptyViewModel.uiState.value.isEmpty)

        val unavailableOps = FakeRoutineOperations().apply {
            listError = HermesApiException(503)
        }
        val unavailableScope = testScope()
        val unavailableViewModel = RoutinesViewModel(unavailableOps, { 10_000 }, unavailableScope)
        unavailableViewModel.load(target)
        assertEquals(RoutinesContentState.UNAVAILABLE, unavailableViewModel.uiState.value.contentState)
        assertTrue(unavailableViewModel.uiState.value.unavailable)
        assertEquals(RoutineErrorKind.UNAVAILABLE, unavailableViewModel.uiState.value.error?.kind)
        emptyScope.cancel()
        unavailableScope.cancel()
    }

    @Test
    fun failedRefreshRetainsLastListAndMarksItStale() {
        val operations = FakeRoutineOperations().apply { listResult = listOf(active) }
        val scope = testScope()
        val viewModel = RoutinesViewModel(operations, { 10_000 }, scope)
        viewModel.load(target)
        operations.listError = IOException("offline")

        viewModel.refresh()

        assertEquals(RoutinesContentState.STALE, viewModel.uiState.value.contentState)
        assertTrue(viewModel.uiState.value.isStale)
        assertEquals(listOf(active.routineId), viewModel.uiState.value.routines.map { it.routineId })
        assertEquals(RoutineErrorKind.NETWORK, viewModel.uiState.value.error?.kind)
        scope.cancel()
    }

    @Test
    fun authFailureIsSafeAndDoesNotExposeExceptionText() {
        val operations = FakeRoutineOperations().apply {
            listError = HermesAuthExpiredException()
        }
        val scope = testScope()
        val viewModel = RoutinesViewModel(operations, { 10_000 }, scope)

        viewModel.load(target)

        assertEquals(RoutinesContentState.ERROR, viewModel.uiState.value.contentState)
        assertEquals(RoutineErrorKind.AUTHENTICATION, viewModel.uiState.value.error?.kind)
        assertEquals(
            "Session expired. Sign in again before loading routines.",
            viewModel.uiState.value.error?.message,
        )
        scope.cancel()
    }

    @Test
    fun pauseAndResumeReplaceOnlyTheMatchingRoutine() {
        val operations = FakeRoutineOperations().apply {
            listResult = listOf(active)
            mutationHandler = { request -> if (request) paused else resumed }
        }
        val scope = testScope()
        val viewModel = RoutinesViewModel(operations, { 10_000 }, scope)
        viewModel.load(target)

        viewModel.pause(active.routineId)
        assertEquals(true, viewModel.uiState.value.routines.single().paused)
        assertNull(viewModel.uiState.value.mutations[active.routineId])

        viewModel.resume(active.routineId)
        assertEquals(false, viewModel.uiState.value.routines.single().paused)
        assertEquals("Routine resumed.", viewModel.uiState.value.message)
        scope.cancel()
    }

    @Test
    fun unresolvedMutationCanBeRetriedWithOriginalRoutineRevision() {
        val operations = FakeRoutineOperations().apply {
            listResult = listOf(active)
            mutationErrors = ArrayDeque(listOf(IOException("response lost")))
            mutationHandler = { paused }
        }
        val scope = testScope()
        val viewModel = RoutinesViewModel(operations, { 10_000 }, scope)
        viewModel.load(target)

        viewModel.pause(active.routineId)
        assertEquals(
            RoutineMutationPhase.UNRESOLVED,
            viewModel.uiState.value.mutations.getValue(active.routineId).phase,
        )
        viewModel.retry(active.routineId)

        assertEquals(true, viewModel.uiState.value.routines.single().paused)
        assertNull(viewModel.uiState.value.mutations[active.routineId])
        assertEquals(2, operations.mutationCalls.size)
        assertEquals(1, operations.mutationCalls[0].revision)
        assertEquals(1, operations.mutationCalls[1].revision)
        scope.cancel()
    }

    @Test
    fun loadRestoresDurableUnresolvedMutationAfterProcessRestart() {
        val operations = FakeRoutineOperations().apply {
            listResult = listOf(active)
            pendingResults[active.routineId] = PendingRoutineMutation(
                routineId = active.routineId,
                requestedPaused = true,
                state = "uncertain",
            )
            mutationHandler = { paused }
        }
        val scope = testScope()
        val viewModel = RoutinesViewModel(operations, { 10_000 }, scope)

        viewModel.load(target)

        assertEquals(
            RoutineMutationPhase.UNRESOLVED,
            viewModel.uiState.value.mutations.getValue(active.routineId).phase,
        )
        assertTrue(viewModel.uiState.value.isStale)

        viewModel.retry(active.routineId)

        assertTrue(viewModel.uiState.value.routines.single().paused)
        assertEquals(1, operations.mutationCalls.size)
        scope.cancel()
    }

    @Test
    fun revisionConflictAutomaticallyRefreshesBeforeRetryCanBeAttempted() {
        val operations = FakeRoutineOperations().apply {
            listResult = listOf(active)
            mutationErrors = ArrayDeque(listOf(HermesApiException(409)))
            mutationHandler = { paused }
        }
        val scope = testScope()
        val viewModel = RoutinesViewModel(operations, { 10_000 }, scope)
        viewModel.load(target)

        viewModel.pause(active.routineId)
        // The conflict path immediately re-reads the list so the visible ETag is rebased without
        // requiring a second manual refresh gesture.
        assertTrue(operations.listCalls >= 2)
        assertTrue(viewModel.uiState.value.mutations.isEmpty())
        assertEquals(RoutinesContentState.READY, viewModel.uiState.value.contentState)
        scope.cancel()
    }

    @Test
    fun clearRemovesProfileScopedLabelsAndMutationControls() {
        val operations = FakeRoutineOperations().apply { listResult = listOf(active) }
        val scope = testScope()
        val viewModel = RoutinesViewModel(operations, { 10_000 }, scope)
        viewModel.load(target)

        viewModel.clear()

        assertNull(viewModel.uiState.value.target)
        assertTrue(viewModel.uiState.value.routines.isEmpty())
        assertEquals(RoutinesContentState.IDLE, viewModel.uiState.value.contentState)
        scope.cancel()
    }

    private fun testScope(): CoroutineScope =
        CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)

    private fun routine(paused: Boolean, revision: Long): RoutineWire = RoutineWire(
        routineId = "routine-123456",
        label = "Daily check",
        summary = "Review the host routine",
        paused = paused,
        revision = revision,
        etag = "\"routine-$revision\"",
    )
}

private class FakeRoutineOperations : RoutineOperations {
    var listResult: List<RoutineWire> = emptyList()
    var listError: Throwable? = null
    var listGate: CompletableDeferred<Unit>? = null
    var listCalls = 0
    val pendingResults = mutableMapOf<String, PendingRoutineMutation>()
    var mutationHandler: (Boolean) -> RoutineWire = { error("mutation handler not configured") }
    var mutationErrors = ArrayDeque<Throwable>()
    val mutationCalls = mutableListOf<MutationRequest>()

    override suspend fun listRoutines(target: BotId, nowEpochMillis: Long): List<RoutineWire> {
        listCalls += 1
        listGate?.await()
        listError?.let { throw it }
        return listResult
    }

    override suspend fun pendingMutation(
        target: BotId,
        routineId: String,
    ): PendingRoutineMutation? = pendingResults[routineId]

    override suspend fun setPaused(
        target: BotId,
        routine: RoutineWire,
        paused: Boolean,
        nowEpochMillis: Long,
    ): RoutineWire {
        mutationCalls += MutationRequest(routine.revision, paused)
        if (mutationErrors.isNotEmpty()) throw mutationErrors.removeFirst()
        return mutationHandler(paused)
    }
}

private data class MutationRequest(
    val revision: Long,
    val paused: Boolean,
)
