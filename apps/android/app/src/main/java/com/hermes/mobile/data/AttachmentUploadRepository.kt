package com.hermes.mobile.data

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.hermes.mobile.contract.IdempotencyKey
import com.hermes.mobile.network.AttachmentBotId
import com.hermes.mobile.network.AttachmentCompletionResponse
import com.hermes.mobile.network.AttachmentDeclaration
import com.hermes.mobile.network.ContentRange
import com.hermes.mobile.network.HermesApiClient
import com.hermes.mobile.network.IdempotencyKeys
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * Resumable, encrypted-staging upload orchestration. Progress is committed after every accepted
 * fixed-size chunk; deterministic per-offset keys make a crash between server acceptance and the
 * local progress write safe to retry without creating a duplicate upload.
 */
@Singleton
class AttachmentUploadRepository @Inject constructor(
    private val stager: EncryptedAttachmentStager,
    private val sessions: UploadSessionStore,
    private val api: HermesApiClient,
) {
    suspend fun uploadUri(
        context: Context,
        bot: AttachmentBotId,
        conversationId: String,
        uri: Uri,
        nowEpochMillis: Long,
    ): AttachmentCompletionResponse {
        require(nowEpochMillis >= 0)
        val fileName = context.contentResolver.query(
            uri,
            arrayOf(OpenableColumns.DISPLAY_NAME),
            null,
            null,
            null,
        )?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(0) else null
        } ?: "attachment"
        val mimeType = context.contentResolver.getType(uri) ?: "application/octet-stream"
        val staged = stager.stageFromUri(uri, fileName, mimeType, nowEpochMillis)
        // The staged file and encrypted upload row remain on a network failure so WorkManager or
        // an explicit retry can resume with the same declaration/chunk/completion keys.
        return begin(bot, conversationId, staged, nowEpochMillis)
    }

    suspend fun uploadFile(
        bot: AttachmentBotId,
        conversationId: String,
        file: java.io.File,
        fileName: String,
        mimeType: String,
        nowEpochMillis: Long,
    ): AttachmentCompletionResponse {
        val staged = stager.stageFromFile(file, fileName, mimeType, nowEpochMillis)
        return begin(bot, conversationId, staged, nowEpochMillis)
    }

    suspend fun begin(
        bot: AttachmentBotId,
        conversationId: String,
        staged: StagedAttachment,
        nowEpochMillis: Long,
    ): AttachmentCompletionResponse {
        require(staged.plaintextBytes in 1..EncryptedAttachmentStager.MAX_PLAINTEXT_BYTES)
        val declaration = AttachmentDeclaration(
            bot = bot,
            conversationId = conversationId,
            filename = staged.originalFileName,
            size = staged.plaintextBytes,
            mimeType = staged.mimeType,
            sha256 = staged.sha256,
        )
        val declarationKey = IdempotencyKeys.generate()
        val completionKey = IdempotencyKeys.generate()
        val body = json.encodeToString(declaration)
        val session = sessions.create(
            declaration = declaration,
            declarationBody = body,
            stagedUploadId = staged.uploadId,
            declarationKey = declarationKey,
            completionKey = completionKey,
            nowEpochMillis = nowEpochMillis,
        )
        return resume(session.uploadId, nowEpochMillis)
    }

    suspend fun resume(uploadId: String, nowEpochMillis: Long): AttachmentCompletionResponse {
        require(nowEpochMillis >= 0)
        var session = sessions.load(uploadId) ?: error("upload session is missing")
        val staged = stager.load(session.stagedUploadId) ?: error("staged attachment is missing")
        require(staged.plaintextBytes == session.declaration.size)
        require(staged.sha256.equals(session.declaration.sha256, ignoreCase = true))

        if (session.serverUploadId == null) {
            session = session.copy(status = UploadStatuses.DECLARING)
            val declaration = api.declareAttachmentBody(
                jsonBody = session.declarationBody,
                idempotencyKey = session.declarationIdempotencyKey,
            )
            session = session.copy(
                serverUploadId = declaration.uploadId,
                chunkBytes = declaration.chunkBytes,
                nextByte = declaration.nextByte,
                status = UploadStatuses.UPLOADING,
            )
            sessions.update(
                session = session,
                serverUploadId = session.serverUploadId,
                chunkBytes = session.chunkBytes,
                nextByte = session.nextByte,
                status = session.status,
                nowEpochMillis = nowEpochMillis,
            )
        }

        require(session.serverUploadId != null)
        require(session.chunkBytes in 1..MAX_CHUNK_BYTES)
        var nextByte = session.nextByte
        stager.usePlaintext(session.stagedUploadId) { _, input ->
            skipExactly(input, nextByte)
            while (nextByte < session.declaration.size) {
                val length = minOf(session.chunkBytes, session.declaration.size - nextByte)
                val bytes = input.readExactly(length.toInt())
                val range = ContentRange.forChunk(nextByte, bytes.size.toLong(), session.declaration.size)
                val response = api.uploadAttachmentChunk(
                    serverUploadId = session.serverUploadId!!,
                    body = bytes,
                    range = range,
                    idempotencyKey = chunkKey(session.uploadId, nextByte),
                    scope = session.declaration.bot,
                    conversationId = session.declaration.conversationId,
                )
                require(response.chunkBytes in 1..MAX_CHUNK_BYTES) {
                    "server returned an invalid upload chunk size"
                }
                require(response.nextByte == range.endInclusive + 1) {
                    "server returned a non-monotonic upload offset"
                }
                nextByte = response.nextByte
                session = session.copy(
                    chunkBytes = response.chunkBytes,
                    nextByte = nextByte,
                    status = UploadStatuses.UPLOADING,
                )
                sessions.update(
                    session = session,
                    serverUploadId = session.serverUploadId,
                    chunkBytes = session.chunkBytes,
                    nextByte = nextByte,
                    status = session.status,
                    nowEpochMillis = System.currentTimeMillis(),
                )
            }
        }

        session = session.copy(nextByte = nextByte, status = UploadStatuses.COMPLETING)
        sessions.update(
            session = session,
            serverUploadId = session.serverUploadId,
            chunkBytes = session.chunkBytes,
            nextByte = nextByte,
            status = UploadStatuses.COMPLETING,
            nowEpochMillis = System.currentTimeMillis(),
        )
        val completed = api.completeAttachment(
            serverUploadId = session.serverUploadId!!,
            totalBytes = session.declaration.size,
            sha256 = session.declaration.sha256,
            idempotencyKey = session.completionIdempotencyKey,
            scope = session.declaration.bot,
            conversationId = session.declaration.conversationId,
        )
        sessions.delete(session.uploadId)
        stager.delete(session.stagedUploadId)
        return completed
    }

    private fun chunkKey(uploadId: String, offset: Long): IdempotencyKey =
        IdempotencyKey("chunk-$uploadId-$offset")

    private fun skipExactly(input: java.io.InputStream, count: Long) {
        var remaining = count
        while (remaining > 0) {
            val skipped = input.skip(remaining)
            if (skipped > 0) {
                remaining -= skipped
                continue
            }
            if (input.read() == -1) error("staged attachment ended before the saved offset")
            remaining--
        }
    }

    private fun java.io.InputStream.readExactly(count: Int): ByteArray {
        require(count > 0)
        val result = ByteArray(count)
        var offset = 0
        while (offset < count) {
            val read = read(result, offset, count - offset)
            if (read < 0) error("staged attachment ended before the declared size")
            offset += read
        }
        return result
    }

    private companion object {
        const val MAX_CHUNK_BYTES = 4L * 1024 * 1024
        val json = Json { explicitNulls = false }
    }
}
