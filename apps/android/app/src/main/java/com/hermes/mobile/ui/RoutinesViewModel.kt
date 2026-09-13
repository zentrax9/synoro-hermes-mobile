package com.hermes.mobile.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.hermes.mobile.contract.BotId
import com.hermes.mobile.contract.OpaqueId
import com.hermes.mobile.data.AuthenticationCacheInvalidatedException
import com.hermes.mobile.data.MobileOperationInProgressException
import com.hermes.mobile.data.PendingRoutineMutation
import com.hermes.mobile.data.RoutineRepository
import com.hermes.mobile.network.HermesApiException
import com.hermes.mobile.network.HermesAuthExpiredException
import com.hermes.mobile.network.RoutineWire
import dagger.hilt.android.lifecycle.HiltViewModel
import java.io.IOException
import javax.inject.Inject
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlin.coroutines.coroutineContext

enum class RoutinesContentState {
    IDLE,
    LOADING,
    READY,
    EMPTY,
    STALE,
    UNAVAILABLE,
    ERROR,
}

enum class RoutineErrorKind {
    AUTHENTICATION,
    NETWORK,
    UNAVAILABLE,
    REVISION_CONFLICT,
    INVALID_RESPONSE,
    UNKNOWN,
}

data class RoutineUiError(
    val kind: RoutineErrorKind,
    val message: String,
    val retryable: Boolean,
)

data class RoutineItem(
    val routineId: String,
    val label: String,
    val summary: String,
    val paused: Boolean,
    val revision: Long,
    val etag: String,
) {
    /** The short alias is useful to list/detail composables without changing the opaque ID. */
    val id: String get() = routineId

    internal fun toWire(): RoutineWire = RoutineWire(
        routineId = routineId,
        label = label,
        summary = summary,
        paused = paused,
        revision = revision,
        etag = etag,
    )

    companion object {
        fun fromWire(value: RoutineWire): RoutineItem = RoutineItem(
            routineId = value.routineId,
            label = value.label,
            summary = value.summary,
            paused = value.paused,
            revision = value.revision,
            etag = value.etag,
        )
    }
}

typealias RoutineUiModel = RoutineItem

enum class RoutineMutationPhase {
    IN_FLIGHT,
    UNRESOLVED,
    REVISION_CONFLICT,
}

data class RoutineMutationUiState(
    val routineId: String,
    val requestedPaused: Boolean,
    val phase: RoutineMutationPhase,
    val error: RoutineUiError? = null,
) {
    val isRetryable: Boolean get() = phase == RoutineMutationPhase.UNRESOLVED
}

data class RoutinesUiState(
    val target: BotId? = null,
    val routines: List<RoutineItem> = emptyList(),
    val contentState: RoutinesContentState = RoutinesContentState.IDLE,
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val error: RoutineUiError? = null,
    val mutations: Map<String, RoutineMutationUiState> = emptyMap(),
    val lastUpdatedAtEpochMillis: Long? = null,
    val message: String? = null,
) {
    val profileId: String? get() = target?.opaqueProfileId
    val isEmpty: Boolean get() = contentState == RoutinesContentState.EMPTY
    val unavailable: Boolean get() = contentState == RoutinesContentState.UNAVAILABLE
    val stale: Boolean get() = isStale
}

/** Internal operation seam for deterministic JVM tests without a network or Android Keystore. */
internal interface RoutineOperations {
    suspend fun listRoutines(target: BotId, nowEpochMillis: Long): List<RoutineWire>

    /** Durable operation metadata used to restore an explicit retry affordance after restart. */
    suspend fun pendingMutation(target: BotId, routineId: String): PendingRoutineMutation? = null

    suspend fun setPaused(
        target: BotId,
        routine: RoutineWire,
        paused: Boolean,
        nowEpochMillis: Long,
    ): RoutineWire
}

/**
 * Presentation state for the profile-scoped routines screen.
 *
 * List data lives only in this ViewModel.  On a failed refresh the last in-memory list is marked
 * stale, while an uncertain mutation remains attached to the exact routine revision so a retry
 * cannot silently switch to a newer ETag or create a duplicate side effect.
 */
@HiltViewModel
class RoutinesViewModel private constructor(
    private val operations: RoutineOperations,
    private val clockMillis: () -> Long,
    private val suppliedScope: CoroutineScope?,
    @Suppress("UNUSED_PARAMETER") marker: Unit,
) : ViewModel() {
    @Inject
    constructor(repository: RoutineRepository) : this(
        operations = RepositoryRoutineOperations(repository),
        clockMillis = { System.currentTimeMillis() },
        suppliedScope = null,
        marker = Unit,
    )

    /** Focused constructor for JVM tests; production callers should use the Hilt constructor. */
    internal constructor(
        operations: RoutineOperations,
        clockMillis: () -> Long,
        scope: CoroutineScope,
    ) : this(operations, clockMillis, scope, Unit)

    private val mutableState = MutableStateFlow(RoutinesUiState())
    val uiState: StateFlow<RoutinesUiState> = mutableState.asStateFlow()

    private val operationScope: CoroutineScope
        get() = suppliedScope ?: viewModelScope

    private var refreshJob: Job? = null
    private val mutationJobs = mutableMapOf<String, Job>()
    private val pendingMutations = mutableMapOf<String, PendingMutation>()
    private var targetGeneration = 0L

    /** Loads routines for an approved profile, replacing any state from another profile. */
    fun load(target: BotId) {
        val current = mutableState.value
        val targetChanged = current.target != target
        if (targetChanged) {
            mutationJobs.values.forEach { it.cancel() }
            mutationJobs.clear()
            pendingMutations.clear()
        }
        beginRefresh(target, targetChanged)
    }

    /**
     * Clears profile-scoped routine state when the authenticated main session is revoked or no
     * approved profile remains selected. Routine labels and controls must never outlive the
     * profile that authorized them.
     */
    fun clear() {
        refreshJob?.cancel()
        refreshJob = null
        mutationJobs.values.forEach { it.cancel() }
        mutationJobs.clear()
        pendingMutations.clear()
        targetGeneration += 1L
        mutableState.value = RoutinesUiState()
    }

    /** Refreshes the currently selected profile; no-op state is never mistaken for a cache hit. */
    fun refresh() {
        val target = mutableState.value.target
        if (target == null) {
            mutableState.value = mutableState.value.copy(
                contentState = RoutinesContentState.ERROR,
                error = RoutineUiError(
                    kind = RoutineErrorKind.UNKNOWN,
                    message = "Select an approved profile before loading routines.",
                    retryable = false,
                ),
                message = null,
            )
            return
        }
        beginRefresh(target, targetChanged = false)
    }

    /** Convenience overload for navigation code that already owns the selected profile. */
    fun refresh(target: BotId) {
        if (mutableState.value.target == target) refresh() else load(target)
    }

    fun pause(routineId: String) {
        mutate(routineId, paused = true)
    }

    fun resume(routineId: String) {
        mutate(routineId, paused = false)
    }

    /** Retries only an unresolved mutation with its original request material. */
    fun retry(routineId: String) {
        val pending = mutableState.value.mutations[routineId]
        if (pending?.phase == RoutineMutationPhase.UNRESOLVED) {
            mutate(routineId, pending.requestedPaused)
        }
    }

    private fun beginRefresh(target: BotId, targetChanged: Boolean) {
        refreshJob?.cancel()
        targetGeneration += 1L
        val generation = targetGeneration
        val current = mutableState.value
        val hasData = !targetChanged && current.routines.isNotEmpty()
        mutableState.value = current.copy(
            target = target,
            routines = if (targetChanged) emptyList() else current.routines,
            contentState = if (hasData) RoutinesContentState.STALE else RoutinesContentState.LOADING,
            isLoading = !hasData,
            isRefreshing = hasData,
            isStale = hasData,
            error = null,
            mutations = if (targetChanged) emptyMap() else current.mutations,
            message = null,
        )
        refreshJob = operationScope.launch {
            try {
                val nowEpochMillis = clockMillis()
                val values = operations.listRoutines(target, nowEpochMillis)
                val items = values.map(RoutineItem::fromWire)
                if (!isCurrent(target, generation)) return@launch

                val persistedMutations = items.mapNotNull { item ->
                    loadPendingMutation(target, item.routineId)
                }
                val persistedByRoutine = persistedMutations.associateBy(PendingRoutineMutation::routineId)
                val previousMutations = mutableState.value.mutations
                val mergedMutations = items.mapNotNull { item ->
                    val currentMutation = previousMutations[item.routineId]
                    val persisted = persistedByRoutine[item.routineId]
                    val restored = when {
                        currentMutation?.phase == RoutineMutationPhase.IN_FLIGHT -> currentMutation
                        currentMutation?.phase == RoutineMutationPhase.UNRESOLVED -> currentMutation
                        persisted != null -> RoutineMutationUiState(
                            routineId = item.routineId,
                            requestedPaused = persisted.requestedPaused,
                            phase = RoutineMutationPhase.UNRESOLVED,
                        )
                        else -> null
                    }
                    restored?.let { item.routineId to it }
                }.toMap()
                pendingMutations.keys.retainAll(mergedMutations.keys)
                persistedMutations.forEach { persisted ->
                    items.firstOrNull { it.routineId == persisted.routineId }?.let { item ->
                        pendingMutations[persisted.routineId] = PendingMutation(
                            target = target,
                            routine = item.toWire(),
                            requestedPaused = persisted.requestedPaused,
                        )
                    }
                }

                // A 409 is deterministic and must be re-based on a fresh list.  An unresolved
                // network result, however, remains visible and retryable after this read.
                val unresolved = mergedMutations.filterValues {
                    it.phase == RoutineMutationPhase.UNRESOLVED
                }
                val staleBecauseUnresolved = unresolved.isNotEmpty()
                mutableState.value = mutableState.value.copy(
                    routines = items,
                    contentState = when {
                        staleBecauseUnresolved -> RoutinesContentState.STALE
                        items.isEmpty() -> RoutinesContentState.EMPTY
                        else -> RoutinesContentState.READY
                    },
                    isLoading = false,
                    isRefreshing = false,
                    isStale = staleBecauseUnresolved,
                    error = null,
                    lastUpdatedAtEpochMillis = nowEpochMillis,
                    message = if (staleBecauseUnresolved) {
                        "A pause/resume result is unresolved; retry it explicitly."
                    } else {
                        null
                    },
                    // Conflict entries are cleared only after this successful re-read.  They are
                    // known not to have been applied, unlike an unresolved transport failure.
                    mutations = mergedMutations,
                )
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                if (!isCurrent(target, generation)) return@launch
                val uiError = error.toRoutineUiError()
                val hasVisibleData = mutableState.value.routines.isNotEmpty()
                mutableState.value = mutableState.value.copy(
                    contentState = when {
                        hasVisibleData -> RoutinesContentState.STALE
                        uiError.kind == RoutineErrorKind.UNAVAILABLE -> RoutinesContentState.UNAVAILABLE
                        else -> RoutinesContentState.ERROR
                    },
                    isLoading = false,
                    isRefreshing = false,
                    isStale = hasVisibleData,
                    error = uiError,
                    message = if (hasVisibleData) {
                        "Showing the last routines response; refresh to try again."
                    } else {
                        null
                    },
                )
            }
        }
    }

    private fun mutate(routineId: String, paused: Boolean) {
        runCatching { OpaqueId.require(routineId, "routineId") }.onFailure {
            mutableState.value = mutableState.value.copy(
                error = RoutineUiError(
                    kind = RoutineErrorKind.INVALID_RESPONSE,
                    message = "That routine reference is invalid.",
                    retryable = false,
                ),
            )
            return
        }

        val current = mutableState.value
        val target = current.target
        if (target == null) {
            mutableState.value = current.copy(
                error = RoutineUiError(
                    kind = RoutineErrorKind.UNKNOWN,
                    message = "Select an approved profile before changing a routine.",
                    retryable = false,
                ),
            )
            return
        }
        val existing = current.mutations[routineId]
        when (existing?.phase) {
            RoutineMutationPhase.IN_FLIGHT -> return
            RoutineMutationPhase.REVISION_CONFLICT -> {
                mutableState.value = current.copy(
                    message = "Refresh routines before trying that revision again.",
                )
                return
            }
            RoutineMutationPhase.UNRESOLVED, null -> Unit
        }

        // A stale list must not send a fresh ETag.  An unresolved operation is the one explicit
        // exception: it reuses the original request/ETag and is therefore safe to retry.
        if ((current.isLoading || current.isRefreshing || current.isStale) &&
            existing?.phase != RoutineMutationPhase.UNRESOLVED
        ) {
            mutableState.value = current.copy(
                message = "Refresh routines before making another change.",
            )
            return
        }

        val visible = current.routines.firstOrNull { it.routineId == routineId }
        if (visible == null) {
            mutableState.value = current.copy(
                error = RoutineUiError(
                    kind = RoutineErrorKind.UNKNOWN,
                    message = "That routine is no longer in the current profile list.",
                    retryable = true,
                ),
            )
            return
        }
        val requestRoutine = pendingMutations[routineId]
            ?.takeIf { existing?.phase == RoutineMutationPhase.UNRESOLVED && it.requestedPaused == paused }
            ?.routine
            ?: visible.toWire()
        val generation = targetGeneration
        pendingMutations[routineId] = PendingMutation(target, requestRoutine, paused)
        mutableState.value = current.copy(
            error = null,
            message = null,
            mutations = current.mutations + (
                routineId to RoutineMutationUiState(
                    routineId = routineId,
                    requestedPaused = paused,
                    phase = RoutineMutationPhase.IN_FLIGHT,
                )
            ),
        )

        mutationJobs[routineId]?.cancel()
        mutationJobs[routineId] = operationScope.launch {
            try {
                val result = operations.setPaused(
                    target = target,
                    routine = requestRoutine,
                    paused = paused,
                    nowEpochMillis = clockMillis(),
                )
                if (!isCurrent(target, generation)) return@launch
                val item = RoutineItem.fromWire(result)
                val updated = mutableState.value.routines.toMutableList()
                val index = updated.indexOfFirst { it.routineId == routineId }
                if (index >= 0) updated[index] = item else updated += item
                pendingMutations.remove(routineId)
                val remainingMutations = mutableState.value.mutations - routineId
                val hasUnresolved = remainingMutations.values.any {
                    it.phase == RoutineMutationPhase.UNRESOLVED
                }
                mutableState.value = mutableState.value.copy(
                    routines = updated,
                    contentState = when {
                        hasUnresolved -> RoutinesContentState.STALE
                        updated.isEmpty() -> RoutinesContentState.EMPTY
                        else -> RoutinesContentState.READY
                    },
                    isStale = hasUnresolved,
                    error = null,
                    mutations = remainingMutations,
                    message = when {
                        hasUnresolved -> "A pause/resume result is unresolved; retry it explicitly."
                        paused -> "Routine paused."
                        else -> "Routine resumed."
                    },
                )
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: MobileOperationInProgressException) {
                if (!isCurrent(target, generation)) return@launch
                val persisted = loadPendingMutation(target, routineId)
                val visibleRoutine = mutableState.value.routines.firstOrNull {
                    it.routineId == routineId
                }
                if (persisted != null && visibleRoutine != null) {
                    pendingMutations[routineId] = PendingMutation(
                        target = target,
                        routine = visibleRoutine.toWire(),
                        requestedPaused = persisted.requestedPaused,
                    )
                }
                val requested = persisted?.requestedPaused ?: paused
                mutableState.value = mutableState.value.copy(
                    contentState = if (mutableState.value.routines.isNotEmpty()) {
                        RoutinesContentState.STALE
                    } else {
                        mutableState.value.contentState
                    },
                    isStale = mutableState.value.routines.isNotEmpty(),
                    message = "A previous pause/resume request is unresolved; retry it explicitly.",
                    mutations = mutableState.value.mutations + (
                        routineId to RoutineMutationUiState(
                            routineId = routineId,
                            requestedPaused = requested,
                            phase = RoutineMutationPhase.UNRESOLVED,
                        )
                    ),
                )
            } catch (error: Exception) {
                if (!isCurrent(target, generation)) return@launch
                val uiError = error.toRoutineUiError()
                val conflict = uiError.kind == RoutineErrorKind.REVISION_CONFLICT
                mutableState.value = mutableState.value.copy(
                    contentState = if (mutableState.value.routines.isNotEmpty()) {
                        RoutinesContentState.STALE
                    } else {
                        mutableState.value.contentState
                    },
                    isStale = mutableState.value.routines.isNotEmpty(),
                    error = uiError,
                    message = if (conflict) {
                        "Routine changed on the host; refresh before trying again."
                    } else {
                        "The pause/resume result is unresolved; retry it explicitly."
                    },
                    mutations = mutableState.value.mutations + (
                        routineId to RoutineMutationUiState(
                            routineId = routineId,
                            requestedPaused = paused,
                            phase = if (conflict) {
                                RoutineMutationPhase.REVISION_CONFLICT
                            } else {
                                RoutineMutationPhase.UNRESOLVED
                            },
                            error = uiError,
                        )
                    ),
                )
                if (conflict) {
                    // A 409 means the visible ETag is stale. Re-read immediately so the retry
                    // gate can be evaluated against the host's current revision.
                    beginRefresh(target, targetChanged = false)
                }
            } finally {
                // A target switch can cancel this job while a new job for the same opaque ID is
                // already in flight.  Do not let the old cancellation remove the new guard.
                val completedJob = coroutineContext[Job]
                if (mutationJobs[routineId] == completedJob) {
                    mutationJobs.remove(routineId)
                }
            }
        }
    }

    private fun isCurrent(target: BotId, generation: Long): Boolean =
        targetGeneration == generation && mutableState.value.target == target

    private suspend fun loadPendingMutation(
        target: BotId,
        routineId: String,
    ): PendingRoutineMutation? = try {
        operations.pendingMutation(target, routineId)
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (_: Exception) {
        // A malformed or unreadable local operation must not hide the fresh routine list. The
        // next authenticated refresh can still surface the operation through the repository.
        null
    }

    override fun onCleared() {
        refreshJob?.cancel()
        mutationJobs.values.forEach { it.cancel() }
        mutationJobs.clear()
        super.onCleared()
    }

    private data class PendingMutation(
        val target: BotId,
        val routine: RoutineWire,
        val requestedPaused: Boolean,
    )
}

private class RepositoryRoutineOperations(
    private val repository: RoutineRepository,
) : RoutineOperations {
    override suspend fun listRoutines(target: BotId, nowEpochMillis: Long): List<RoutineWire> =
        repository.listRoutines(target, nowEpochMillis)

    override suspend fun pendingMutation(
        target: BotId,
        routineId: String,
    ): PendingRoutineMutation? = repository.pendingMutation(target, routineId)

    override suspend fun setPaused(
        target: BotId,
        routine: RoutineWire,
        paused: Boolean,
        nowEpochMillis: Long,
    ): RoutineWire = repository.setPaused(target, routine, paused, nowEpochMillis)
}

private fun Throwable.toRoutineUiError(): RoutineUiError = when (this) {
    is HermesAuthExpiredException, is AuthenticationCacheInvalidatedException -> RoutineUiError(
        kind = RoutineErrorKind.AUTHENTICATION,
        message = "Session expired. Sign in again before loading routines.",
        retryable = true,
    )
    is HermesApiException -> when (statusCode) {
        401, 403 -> RoutineUiError(
            kind = RoutineErrorKind.AUTHENTICATION,
            message = "Session expired or is not approved for routines.",
            retryable = true,
        )
        409 -> RoutineUiError(
            kind = RoutineErrorKind.REVISION_CONFLICT,
            message = "The routine changed on the Hermes host.",
            retryable = false,
        )
        503 -> RoutineUiError(
            kind = RoutineErrorKind.UNAVAILABLE,
            message = "Routines are unavailable on this Hermes host.",
            retryable = true,
        )
        else -> RoutineUiError(
            kind = RoutineErrorKind.UNKNOWN,
            message = "Hermes could not complete the routines request.",
            retryable = true,
        )
    }
    is IOException -> RoutineUiError(
        kind = RoutineErrorKind.NETWORK,
        message = "Routines could not reach Hermes. Retry when connected.",
        retryable = true,
    )
    is IllegalArgumentException -> RoutineUiError(
        kind = RoutineErrorKind.INVALID_RESPONSE,
        message = "Hermes returned an invalid routines response.",
        retryable = false,
    )
    else -> RoutineUiError(
        kind = RoutineErrorKind.UNKNOWN,
        message = "Hermes could not complete the routines request.",
        retryable = true,
    )
}
