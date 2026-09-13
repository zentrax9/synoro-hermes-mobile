package com.hermes.mobile.sync

import com.hermes.mobile.auth.MobileEnrollmentCoordinator
import com.hermes.mobile.data.HermesAuthSession
import com.hermes.mobile.network.CursorExpiredException
import com.hermes.mobile.network.HermesApiClient
import com.hermes.mobile.network.HermesAuthExpiredException
import com.hermes.mobile.network.HermesEventStream
import com.hermes.mobile.network.SyncBatch
import com.hermes.mobile.network.SyncEventWire
import java.io.IOException
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.withContext
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

data class ReconciliationResult(
    val target: SyncTarget,
    val previousCursor: Long,
    val cursor: Long,
    val eventsApplied: Int,
    val fullSnapshot: Boolean,
)

/** Read-only reconciliation coordinator. A restart or network loss never resubmits mutations. */
class SyncReconciler @Inject constructor(
    private val api: HermesApiClient,
    private val store: DurableSyncStore,
    private val authSession: HermesAuthSession,
    private val enrollment: MobileEnrollmentCoordinator,
) {
    suspend fun currentCursor(target: SyncTarget): Long = store.currentCursor(target)

    suspend fun reconcile(
        target: SyncTarget,
        nowEpochMillis: Long,
        forceSnapshot: Boolean = false,
    ): ReconciliationResult {
        require(nowEpochMillis >= 0)
        val previous = store.currentCursor(target)
        // Version-5 clients persisted events without aggregate identity.  An authenticated full
        // snapshot is the only safe way to rebuild run projections from that cursor.
        var full = forceSnapshot || store.hasLegacyAggregateMetadata(target)
        var requestCursor = if (full) 0 else previous
        var firstPage = true
        var applied = 0
        var batch = SyncBatch(cursor = requestCursor)
        while (true) {
            batch = try {
                withUsableSession(target, nowEpochMillis) {
                    api.fetchSync(
                        instanceId = target.instanceId,
                        opaqueProfileId = target.opaqueProfileId,
                        cursor = requestCursor,
                        snapshot = full,
                    )
                }
            } catch (_: CursorExpiredException) {
                if (full) throw CursorExpiredException()
                full = true
                requestCursor = 0
                firstPage = true
                continue
            }
            if (batch.snapshotRequired && !full) {
                full = true
                requestCursor = 0
                firstPage = true
                continue
            }
            if (full && firstPage) store.replaceWithSnapshot(target, nowEpochMillis)
            store.applyBatch(target, batch, nowEpochMillis)
            applied += if (full) batch.events.size else batch.events.count { it.cursor > previous }
            if (!batch.hasMore) break
            requestCursor = batch.cursor
            firstPage = false
        }
        store.prune(target, nowEpochMillis)
        return ReconciliationResult(
            target = target,
            previousCursor = previous,
            cursor = batch.cursor,
            eventsApplied = applied,
            fullSnapshot = full,
        )
    }

    /** Read-only sync may be retried once after a five-minute device token refresh. */
    private suspend fun <T> withUsableSession(
        target: SyncTarget,
        nowEpochMillis: Long,
        block: suspend () -> T,
    ): T {
        if (authSession.current() == null &&
            !authSession.restore(target.instanceId, target.opaqueProfileId)
        ) {
            throw HermesAuthExpiredException()
        }
        val material = authSession.current() ?: throw HermesAuthExpiredException()
        val nowSeconds = nowEpochMillis / 1_000
        if (!material.hermesDeviceToken.isUsable(nowSeconds)) {
            val deviceId = authSession.currentDeviceId() ?: throw HermesAuthExpiredException()
            enrollment.refreshApprovedSession(
                instanceId = target.instanceId,
                opaqueProfileId = target.opaqueProfileId,
                cloudflareAccessToken = material.cloudflareAccessToken,
                deviceId = deviceId,
                nowEpochMillis = nowEpochMillis,
            )
        }
        return try {
            block()
        } catch (_: HermesAuthExpiredException) {
            val refreshed = authSession.current() ?: throw HermesAuthExpiredException()
            val deviceId = authSession.currentDeviceId() ?: throw HermesAuthExpiredException()
            enrollment.refreshApprovedSession(
                instanceId = target.instanceId,
                opaqueProfileId = target.opaqueProfileId,
                cloudflareAccessToken = refreshed.cloudflareAccessToken,
                deviceId = deviceId,
                nowEpochMillis = System.currentTimeMillis(),
            )
            block()
        }
    }

    suspend fun consumeEventStream(
        target: SyncTarget,
        stream: HermesEventStream,
        nowEpochMillis: () -> Long,
    ): Int = withContext(Dispatchers.IO) {
        var applied = 0
        val parser = SseParser()
        // Okio's blocking source read is not itself cancellable. Registering the close callback
        // on the coroutine job actively cancels the underlying OkHttp call when the foreground
        // screen disappears, so the stream cannot outlive its ViewModel.
        val cancellationHandle = currentCoroutineContext()[Job]?.invokeOnCompletion {
            stream.close()
        }
        try {
            val source = stream.response.body?.source()
                ?: throw IOException("SSE response body is missing")
            while (!source.exhausted()) {
                val line = source.readUtf8Line() ?: break
                val frame = parser.feed(line)
                if (frame != null) {
                    applied += applyFrame(target, frame, nowEpochMillis())
                }
            }
            val finalFrame = parser.finish()
            if (finalFrame != null) {
                applied += applyFrame(target, finalFrame, nowEpochMillis())
            }
        } finally {
            cancellationHandle?.dispose()
            stream.close()
        }
        applied
    }

    private suspend fun applyFrame(target: SyncTarget, frame: SseFrame, nowEpochMillis: Long): Int {
        if (frame.data.isBlank()) return 0
        val events = if (frame.data.trimStart().startsWith("[")) {
            json.decodeFromString<List<SyncEventWire>>(frame.data)
        } else {
            listOf(json.decodeFromString<SyncEventWire>(frame.data))
        }
        var applied = 0
        for (event in events.sortedWith(compareBy<SyncEventWire> { it.cursor }.thenBy { it.eventId })) {
            // The Hermes listener emits the stable stream name "mobile". Accepting the
            // event-specific name as well keeps this parser compatible with generic SSE
            // proxies, while still rejecting an unrelated stream on the same connection.
            if (frame.event != null &&
                frame.event != "mobile" &&
                frame.event != "sync" &&
                frame.event != event.eventType
            ) {
                throw IOException("unexpected SSE event type")
            }
            if (frame.id != null && frame.id != event.eventId && frame.id != event.cursor.toString()) {
                throw IOException("SSE event ID mismatch")
            }
            val current = store.currentCursor(target)
            if (event.cursor <= current) continue
            store.applyBatch(
                target,
                SyncBatch(cursor = event.cursor, events = listOf(event)),
                nowEpochMillis,
            )
            applied++
        }
        return applied
    }

    private companion object {
        val json = Json { ignoreUnknownKeys = true; explicitNulls = false }
    }
}
