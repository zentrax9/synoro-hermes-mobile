package com.hermes.mobile.data

import com.hermes.mobile.contract.IdempotencyKey
import com.hermes.mobile.network.AttachmentDeclaration
import com.hermes.mobile.security.EncryptedValue
import com.hermes.mobile.security.EncryptedValueStore
import java.nio.charset.StandardCharsets
import java.util.UUID
import javax.inject.Inject

object UploadStatuses {
    const val DECLARING = "declaring"
    const val UPLOADING = "uploading"
    const val COMPLETING = "completing"
    const val COMPLETE = "complete"
    const val FAILED = "failed"
}

data class UploadSession(
    val uploadId: String,
    val stagedUploadId: String,
    val declaration: AttachmentDeclaration,
    val declarationBody: String,
    val declarationIdempotencyKey: IdempotencyKey,
    val completionIdempotencyKey: IdempotencyKey,
    val serverUploadId: String?,
    val chunkBytes: Long,
    val nextByte: Long,
    val status: String,
    val updatedAtEpochMillis: Long,
)

/** Stores exact declaration bytes and progress before any upload mutation is attempted. */
class UploadSessionStore @Inject constructor(
    private val dao: HermesDao,
    private val crypto: EncryptedValueStore,
) {
    suspend fun create(
        declaration: AttachmentDeclaration,
        declarationBody: String,
        stagedUploadId: String,
        declarationKey: IdempotencyKey,
        completionKey: IdempotencyKey,
        nowEpochMillis: Long,
    ): UploadSession {
        require(nowEpochMillis >= 0)
        require(declarationBody.isNotBlank())
        require(stagedUploadId.matches(UPLOAD_ID))
        val uploadId = UUID.randomUUID().toString()
        val row = UploadSessionEntity(
            uploadId = uploadId,
            instanceId = declaration.bot.instanceId,
            opaqueProfileId = declaration.bot.opaqueProfileId,
            conversationId = declaration.conversationId,
            stagedUploadId = stagedUploadId,
            declarationBodyCiphertext = crypto.encrypt(
                declarationBody.toByteArray(StandardCharsets.UTF_8),
                uploadId.toByteArray(StandardCharsets.UTF_8),
            ).toByteArray(),
            declarationIdempotencyKey = declarationKey.value,
            completionIdempotencyKey = completionKey.value,
            serverUploadId = null,
            chunkBytes = 0,
            nextByte = 0,
            totalBytes = declaration.size,
            status = UploadStatuses.DECLARING,
            updatedAtEpochMillis = nowEpochMillis,
        )
        dao.saveUploadSession(row)
        return UploadSession(
            uploadId = uploadId,
            stagedUploadId = stagedUploadId,
            declaration = declaration,
            declarationBody = declarationBody,
            declarationIdempotencyKey = declarationKey,
            completionIdempotencyKey = completionKey,
            serverUploadId = null,
            chunkBytes = 0,
            nextByte = 0,
            status = UploadStatuses.DECLARING,
            updatedAtEpochMillis = nowEpochMillis,
        )
    }

    suspend fun load(uploadId: String): UploadSession? {
        require(uploadId.matches(UPLOAD_ID))
        val row = dao.findUploadSession(uploadId) ?: return null
        val body = String(
            crypto.decrypt(
                EncryptedValue.fromByteArray(row.declarationBodyCiphertext),
                uploadId.toByteArray(StandardCharsets.UTF_8),
            ),
            StandardCharsets.UTF_8,
        )
        val declaration = parseDeclaration(body)
        require(declaration.bot.instanceId == row.instanceId)
        require(declaration.bot.opaqueProfileId == row.opaqueProfileId)
        require(declaration.conversationId == row.conversationId)
        require(declaration.size == row.totalBytes)
        require(row.nextByte in 0..row.totalBytes)
        require(row.chunkBytes >= 0)
        return UploadSession(
            uploadId = row.uploadId,
            stagedUploadId = row.stagedUploadId,
            declaration = declaration,
            declarationBody = body,
            declarationIdempotencyKey = IdempotencyKey(row.declarationIdempotencyKey),
            completionIdempotencyKey = IdempotencyKey(row.completionIdempotencyKey),
            serverUploadId = row.serverUploadId,
            chunkBytes = row.chunkBytes,
            nextByte = row.nextByte,
            status = row.status,
            updatedAtEpochMillis = row.updatedAtEpochMillis,
        )
    }

    suspend fun update(
        session: UploadSession,
        serverUploadId: String?,
        chunkBytes: Long,
        nextByte: Long,
        status: String,
        nowEpochMillis: Long,
    ) {
        require(nowEpochMillis >= 0)
        require(chunkBytes >= 0 && nextByte in 0..session.declaration.size)
        dao.saveUploadSession(
            UploadSessionEntity(
                uploadId = session.uploadId,
                instanceId = session.declaration.bot.instanceId,
                opaqueProfileId = session.declaration.bot.opaqueProfileId,
                conversationId = session.declaration.conversationId,
                stagedUploadId = session.stagedUploadId,
                declarationBodyCiphertext = crypto.encrypt(
                    session.declarationBody.toByteArray(StandardCharsets.UTF_8),
                    session.uploadId.toByteArray(StandardCharsets.UTF_8),
                ).toByteArray(),
                declarationIdempotencyKey = session.declarationIdempotencyKey.value,
                completionIdempotencyKey = session.completionIdempotencyKey.value,
                serverUploadId = serverUploadId,
                chunkBytes = chunkBytes,
                nextByte = nextByte,
                totalBytes = session.declaration.size,
                status = status,
                updatedAtEpochMillis = nowEpochMillis,
            ),
        )
    }

    suspend fun delete(uploadId: String) {
        require(uploadId.matches(UPLOAD_ID))
        dao.deleteUploadSession(uploadId)
    }

    private fun parseDeclaration(body: String): AttachmentDeclaration =
        kotlinx.serialization.json.Json.decodeFromString(body)

    private companion object {
        val UPLOAD_ID = Regex("^[A-Za-z0-9-]{36}$")
    }
}
