package com.hermes.mobile.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import java.text.DateFormat
import java.util.Date

@Composable
fun ConversationPicker(
    conversations: List<ConversationCardState>,
    selectedConversationId: String?,
    isLoading: Boolean,
    isStale: Boolean,
    canCreate: Boolean,
    canSelect: Boolean = true,
    onSelect: (String) -> Unit,
    onCreate: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var expanded by remember { mutableStateOf(false) }
    val selected = conversations.firstOrNull { it.conversationId == selectedConversationId }
    Card(modifier = modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Box(modifier = Modifier.weight(1f)) {
                OutlinedButton(
                    onClick = { expanded = true },
                    enabled = conversations.isNotEmpty() && !isLoading && canSelect,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        text = selected?.let { "${it.title} · ${updatedLabel(it.updatedAtEpochMillis)}" }
                            ?: if (isLoading) "Loading conversations…" else "Choose conversation",
                        maxLines = 1,
                    )
                }
                DropdownMenu(
                    expanded = expanded,
                    onDismissRequest = { expanded = false },
                ) {
                    conversations.forEach { conversation ->
                        val isSelected = conversation.conversationId == selectedConversationId
                        DropdownMenuItem(
                            text = {
                                Column {
                                    Text(
                                        text = buildString {
                                            if (isSelected) append("✓ ")
                                            append(conversation.title)
                                            if (conversation.canonical) append(" · Main")
                                        },
                                        maxLines = 1,
                                    )
                                    Text(
                                        text = "Updated ${updatedLabel(conversation.updatedAtEpochMillis)}",
                                        maxLines = 1,
                                        style = MaterialTheme.typography.labelSmall,
                                    )
                                }
                            },
                            onClick = {
                                expanded = false
                                onSelect(conversation.conversationId)
                            },
                            enabled = canSelect && !isLoading,
                        )
                    }
                }
            }
            Button(onClick = onCreate, enabled = canCreate && !isLoading) {
                Text("New chat")
            }
        }
        if (isStale) {
            Text(
                "Showing encrypted conversation summaries from the last successful sync.",
                modifier = Modifier.padding(start = 12.dp, end = 12.dp, bottom = 8.dp),
                style = MaterialTheme.typography.labelSmall,
            )
        }
    }
}

private fun updatedLabel(epochMillis: Long): String = if (epochMillis <= 0) {
    "unknown"
} else {
    DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(epochMillis))
}
