package com.hermes.mobile.sync

import androidx.room.withTransaction
import com.hermes.mobile.contract.OpaqueId
import com.hermes.mobile.data.HermesDao
import com.hermes.mobile.data.HermesDatabase
import com.hermes.mobile.data.RunEntity
import com.hermes.mobile.data.SyncCursorEntity
import com.hermes.mobile.data.SyncEventEntity
import com.hermes.mobile.data.mergeRunProjection
import com.hermes.mobile.network.SyncBatch
import com.hermes.mobile.network.SyncEventWire
import com.hermes.mobile.security.EncryptedValue
import com.hermes.mobile.security.EncryptedValueStore
import java.nio.charset.StandardCharsets
import javax.inject.Inject
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

data class SyncTarget(val instanceId: String, val opaqueProfileId: String) {
    init {
        OpaqueId.require(instanceId, "instanceId")
        OpaqueId.require(opaqueProfileId, "opaqueProfileId")
    }
}

data class StoredSyncEvent(
    val target: SyncTarget,
    val event: SyncEventWire,
)

/** Applies read-only replay batches atomically; it never creates or retries a mutation. */
class DurableSyncStore @Inject constructor(
    private val database: HermesDatabase,
    private val dao: HermesDao,
    private val crypto: EncryptedValueStore,
) {
    suspend fun currentCursor(target: SyncTarget): Long =
        dao.findSyncCursor(target.instanceId, target.opaqueProfileId)?.cursor ?: 0L

    suspend fun hasLegacyAggregateMetadata(target: SyncTarget): Boolean =
        dao.hasLegacySyncEvents(target.instanceId, target.opaqueProfileId)

    suspend fun replaceWithSnapshot(target: SyncTarget, nowEpochMillis: Long) {
        require(nowEpochMillis >= 0)
        database.withTransaction {
            dao.deleteSyncEventsForTarget(target.instanceId, target.opaqueProfileId)
            // Run projections are derived solely from semantic events.  Clear them with the
            // event log so a cursor-expiry/legacy-metadata snapshot cannot leave an old run
            // visible after the authenticated replay completes.
            dao.deleteRunsForTarget(target.instanceId, target.opaqueProfileId)
            dao.saveSyncCursor(
                SyncCursorEntity(
                    instanceId = target.instanceId,
                    opaqueProfileId = target.opaqueProfileId,
                    cursor = 0,
                    updatedAtEpochMillis = nowEpochMillis,
                ),
            )
        }
    }

    suspend fun applyBatch(target: SyncTarget, batch: SyncBatch, nowEpochMillis: Long) {
        require(nowEpochMillis >= 0)
        database.withTransaction {
            val current = dao.findSyncCursor(target.instanceId, target.opaqueProfileId)?.cursor ?: 0L
            require(batch.cursor >= current) { "sync cursor moved backwards" }
            for (event in batch.events.sortedWith(compareBy<SyncEventWire> { it.cursor }.thenBy { it.eventId })) {
                if (event.cursor <= current) continue
                val aad = aad(target, event)
                dao.saveSyncEvent(
                    SyncEventEntity(
                        instanceId = target.instanceId,
                        opaqueProfileId = target.opaqueProfileId,
                        cursor = event.cursor,
                        eventId = event.eventId,
                        eventType = event.eventType,
                        aggregateType = event.aggregateType,
                        aggregateId = event.aggregateId,
                        tombstone = event.tombstone,
                        payloadCiphertext = crypto.encrypt(
                            json.encodeToString(event.payload).toByteArray(StandardCharsets.UTF_8),
                            aad.toByteArray(StandardCharsets.UTF_8),
                        ).toByteArray(),
                        createdAtEpochMillis = (event.createdAtEpochSeconds * 1_000.0).toLong(),
                    ),
                )
                projectRunEvent(target, event)
            }
            dao.saveSyncCursor(
                SyncCursorEntity(
                    instanceId = target.instanceId,
                    opaqueProfileId = target.opaqueProfileId,
                    cursor = batch.cursor,
                    updatedAtEpochMillis = nowEpochMillis,
                ),
            )
        }
    }

    suspend fun eventsAfter(target: SyncTarget, afterCursor: Long): List<StoredSyncEvent> {
        require(afterCursor >= 0)
        return dao.listSyncEventsAfter(target.instanceId, target.opaqueProfileId, afterCursor)
            .map { row ->
                val event = SyncEventWire(
                    cursor = row.cursor,
                    eventId = row.eventId,
                    eventType = row.eventType,
                    payload = json.decodeFromString(
                        String(
                            crypto.decrypt(
                                EncryptedValue.fromByteArray(row.payloadCiphertext),
                                aad(target, row.cursor, row.eventId).toByteArray(StandardCharsets.UTF_8),
                            ),
                            StandardCharsets.UTF_8,
                        ),
                    ),
                    createdAtEpochSeconds = row.createdAtEpochMillis / 1_000.0,
                    aggregateType = row.aggregateType,
                    aggregateId = row.aggregateId,
                    tombstone = row.tombstone,
                )
                StoredSyncEvent(target, event)
            }
    }

    suspend fun prune(target: SyncTarget, nowEpochMillis: Long): Int {
        require(nowEpochMillis >= 0)
        return dao.deleteOldSyncEvents(
            target.instanceId,
            target.opaqueProfileId,
            (nowEpochMillis - EVENT_RETENTION_MILLIS).coerceAtLeast(0),
        )
    }

    private fun aad(target: SyncTarget, event: SyncEventWire): String =
        aad(target, event.cursor, event.eventId)

    private fun aad(target: SyncTarget, cursor: Long, eventId: String): String =
        listOf(target.instanceId, target.opaqueProfileId, cursor, eventId).joinToString("\u001f")

    /** Projects only semantic run metadata; transcript text remains in the history read path. */
    private suspend fun projectRunEvent(target: SyncTarget, event: SyncEventWire) {
        if (event.aggregateType != "run" || event.aggregateId.isBlank()) return
        val payload = event.payload as? JsonObject
        val conversationId = payload?.get("conversation_id")?.jsonPrimitive?.content
            ?.takeIf { it.isNotBlank() }
            ?: return
        val state = when (event.eventType) {
            "run.queued" -> "queued"
            "run.thinking" -> "thinking"
            "run.completed" -> "completed"
            "run.failed" -> "failed"
            "run.cancelled" -> "cancelled"
            "run.indeterminate" -> "indeterminate"
            else -> payload?.get("state")?.jsonPrimitive?.content ?: return
        }
        val requested = RunEntity(
            instanceId = target.instanceId,
            opaqueProfileId = target.opaqueProfileId,
            conversationId = conversationId,
            runId = event.aggregateId,
            state = state,
            transportState = "connected",
            attentionState = if (state == "indeterminate" || state == "failed") "failed" else "none",
            revision = event.cursor,
            updatedAtEpochMillis = (event.createdAtEpochSeconds * 1_000.0).toLong(),
            cancelRequested = payload?.get("cancel_requested")?.jsonPrimitive?.content?.toBoolean() == true ||
                event.eventType == "run.cancelled",
            completedExternalSideEffectsNotUndone = payload?.get("completed_external_side_effects_not_undone")
                ?.jsonPrimitive?.content?.toBoolean() == true,
        )
        val current = dao.findRun(
            instanceId = target.instanceId,
            opaqueProfileId = target.opaqueProfileId,
            conversationId = conversationId,
            runId = event.aggregateId,
        )
        dao.upsertRun(current?.let { mergeRunProjection(it, requested) } ?: requested)
    }

    private companion object {
        const val EVENT_RETENTION_MILLIS = 30L * 24 * 60 * 60 * 1_000
        val json = Json { explicitNulls = false; ignoreUnknownKeys = true }
    }
}
