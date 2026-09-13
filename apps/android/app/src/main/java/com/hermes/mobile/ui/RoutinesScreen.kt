package com.hermes.mobile.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/**
 * Stateless routines surface.  The parent owns profile selection and supplies the
 * [RoutinesViewModel] callbacks; this keeps navigation and authentication wiring out of the
 * feature slice.
 */
@Composable
fun RoutinesScreen(
    state: RoutinesUiState,
    onRefresh: () -> Unit,
    onPause: (String) -> Unit,
    onResume: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Routines", style = MaterialTheme.typography.headlineSmall)
                Text(
                    "View and pause host-owned routines for this profile.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            IconButton(
                onClick = onRefresh,
                enabled = !state.isLoading && !state.isRefreshing,
                modifier = Modifier
                    .size(48.dp)
                    .semantics { contentDescription = "Refresh routines" },
            ) {
                Icon(Icons.Outlined.Refresh, contentDescription = null)
            }
        }

        if (state.isRefreshing) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                Text("Refreshing routines…", style = MaterialTheme.typography.bodySmall)
            }
        }

        state.error?.let { error ->
            RoutineErrorBanner(error = error, onRefresh = onRefresh)
        }

        when (state.contentState) {
            RoutinesContentState.IDLE -> RoutineMessage(
                "Select an approved profile to view its routines.",
            )
            RoutinesContentState.LOADING -> LoadingRoutines()
            RoutinesContentState.EMPTY -> RoutineMessage(
                "No routines are available for this profile.",
            )
            RoutinesContentState.UNAVAILABLE -> Unit
            RoutinesContentState.ERROR -> Unit
            RoutinesContentState.READY, RoutinesContentState.STALE -> {
                if (state.isStale && state.error == null) {
                    Text(
                        "Showing routines that may be out of date. Refresh before making another change.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    items(state.routines, key = { it.routineId }) { routine ->
                        RoutineCard(
                            routine = routine,
                            mutation = state.mutations[routine.routineId],
                            mutationsEnabled = !state.isLoading && !state.isRefreshing,
                            isStale = state.isStale,
                            onPause = onPause,
                            onResume = onResume,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun LoadingRoutines() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 32.dp),
        contentAlignment = Alignment.Center,
    ) {
        CircularProgressIndicator()
    }
}

@Composable
private fun RoutineMessage(message: String) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Text(
            message,
            modifier = Modifier.padding(16.dp),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

@Composable
private fun RoutineErrorBanner(
    error: RoutineUiError,
    onRefresh: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(error.message, style = MaterialTheme.typography.bodyMedium)
            if (error.retryable) {
                Button(
                    onClick = onRefresh,
                    modifier = Modifier.heightIn(min = 48.dp),
                ) {
                    Text("Retry")
                }
            }
        }
    }
}

@Composable
private fun RoutineCard(
    routine: RoutineItem,
    mutation: RoutineMutationUiState?,
    mutationsEnabled: Boolean,
    isStale: Boolean,
    onPause: (String) -> Unit,
    onResume: (String) -> Unit,
) {
    val inFlight = mutation?.phase == RoutineMutationPhase.IN_FLIGHT
    val conflict = mutation?.phase == RoutineMutationPhase.REVISION_CONFLICT
    val unresolved = mutation?.phase == RoutineMutationPhase.UNRESOLVED
    val requestedPaused = mutation?.requestedPaused
    val actionLabel = when {
        inFlight && requestedPaused == true -> "Pausing…"
        inFlight && requestedPaused == false -> "Resuming…"
        mutation?.phase == RoutineMutationPhase.UNRESOLVED && requestedPaused == true -> "Retry pause"
        mutation?.phase == RoutineMutationPhase.UNRESOLVED && requestedPaused == false -> "Retry resume"
        routine.paused -> "Resume"
        else -> "Pause"
    }
    val action: () -> Unit = when {
        mutation?.phase == RoutineMutationPhase.UNRESOLVED && requestedPaused == true ->
            ({ onPause(routine.routineId) })
        mutation?.phase == RoutineMutationPhase.UNRESOLVED && requestedPaused == false ->
            ({ onResume(routine.routineId) })
        routine.paused -> ({ onResume(routine.routineId) })
        else -> ({ onPause(routine.routineId) })
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(routine.label, fontWeight = FontWeight.SemiBold)
            if (routine.summary.isNotBlank()) {
                Text(routine.summary, style = MaterialTheme.typography.bodyMedium)
            }
            HorizontalDivider()
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    if (routine.paused) "Paused" else "Active",
                    style = MaterialTheme.typography.labelMedium,
                )
                Text("Revision ${routine.revision}", style = MaterialTheme.typography.labelSmall)
            }
            if (mutation?.phase == RoutineMutationPhase.UNRESOLVED) {
                Text(
                    "The last response was not confirmed. Retry explicitly; Hermes will reuse the request key.",
                    style = MaterialTheme.typography.bodySmall,
                )
            } else if (conflict) {
                Text(
                    "The host revision changed. Refresh to load the current routine before trying again.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Button(
                onClick = action,
                enabled = mutationsEnabled && !inFlight && !conflict && (!isStale || unresolved),
                modifier = Modifier
                    .heightIn(min = 48.dp)
                    .semantics {
                        contentDescription = if (routine.paused) {
                            "Resume ${routine.label}"
                        } else {
                            "Pause ${routine.label}"
                        }
                    },
            ) {
                Text(actionLabel)
            }
            TextButton(
                onClick = { },
                enabled = false,
                modifier = Modifier.heightIn(min = 48.dp),
            ) {
                Text("Run now unavailable")
            }
            Text(
                "Execution is unavailable on this host; pausing only changes this routine's mobile availability.",
                style = MaterialTheme.typography.labelSmall,
            )
        }
    }
}
