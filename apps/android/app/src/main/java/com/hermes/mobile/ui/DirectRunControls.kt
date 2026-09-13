package com.hermes.mobile.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.hermes.mobile.contract.RunState

@Composable
fun DirectRunControls(
    state: DirectRunUiState,
    onStop: (String) -> Unit,
    onRefresh: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val runId = state.runId ?: return
    val canStop = state.state in setOf(
        RunState.QUEUED,
        RunState.THINKING,
        RunState.TOOL_RUNNING,
        RunState.WAITING_FOR_USER,
        RunState.APPROVAL_REQUIRED,
    ) && !state.cancelRequested && !state.isCancelling
    Card(modifier = modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text("Direct run · ${state.state.label()}", style = MaterialTheme.typography.titleSmall)
                TextButton(onClick = { onRefresh(runId) }) { Text("Refresh") }
            }
            if (state.cancelRequested || state.isCancelling) {
                Text(
                    if (state.isCancelling) "Requesting a stop…" else "Stop requested; waiting for the host outcome.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (state.completedExternalSideEffectsNotUndone || state.state == RunState.INDETERMINATE) {
                Text(
                    "The run outcome may include external effects that cannot be undone automatically.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (state.message != null) {
                Text(state.message, style = MaterialTheme.typography.bodySmall)
            }
            Button(
                onClick = { onStop(runId) },
                enabled = canStop,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (state.isCancelling) "Stopping…" else "Stop run")
            }
        }
    }
}

private fun RunState.label(): String = when (this) {
    RunState.QUEUED -> "queued"
    RunState.THINKING -> "thinking"
    RunState.TOOL_RUNNING -> "running a tool"
    RunState.WAITING_FOR_USER -> "waiting for you"
    RunState.APPROVAL_REQUIRED -> "approval required"
    RunState.COMPLETED -> "completed"
    RunState.FAILED -> "failed"
    RunState.CANCELLED -> "cancelled"
    RunState.INDETERMINATE -> "outcome uncertain"
}
