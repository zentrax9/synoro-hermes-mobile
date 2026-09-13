package com.hermes.mobile.data

import com.hermes.mobile.contract.IdempotencyKey
import com.hermes.mobile.security.EncryptedValueStore
import java.nio.charset.StandardCharsets
import javax.inject.Inject

/** Persists the exact encrypted request body before a side-effecting network attempt. */
class IdempotencyStore @Inject constructor(
    private val dao: HermesDao,
    private val crypto: EncryptedValueStore,
) {
    suspend fun persistBeforeAttempt(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
        scope: String,
        key: IdempotencyKey,
        requestBody: String,
        createdAtEpochMillis: Long,
    ) {
        require(scope.startsWith("mobile/v1/")) { "idempotency scope must be a typed mobile route" }
        val aad = aad(instanceId, opaqueProfileId, conversationId, scope, key.value)
        val ciphertext = crypto.encrypt(
            requestBody.toByteArray(StandardCharsets.UTF_8),
            aad.toByteArray(StandardCharsets.UTF_8),
        ).toByteArray()
        dao.saveIdempotency(
            IdempotencyEntity(
                instanceId = instanceId,
                opaqueProfileId = opaqueProfileId,
                conversationId = conversationId,
                scope = scope,
                idempotencyKey = key.value,
                requestBodyCiphertext = ciphertext,
                createdAtEpochMillis = createdAtEpochMillis,
            ),
        )
    }

    suspend fun loadBody(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
        scope: String,
        key: IdempotencyKey,
    ): String? {
        val row = dao.findIdempotency(
            instanceId,
            opaqueProfileId,
            conversationId,
            scope,
            key.value,
        ) ?: return null
        val aad = aad(instanceId, opaqueProfileId, conversationId, scope, key.value)
        val plaintext = crypto.decrypt(
            com.hermes.mobile.security.EncryptedValue.fromByteArray(row.requestBodyCiphertext),
            aad.toByteArray(StandardCharsets.UTF_8),
        )
        return String(plaintext, StandardCharsets.UTF_8)
    }

    suspend fun loadLatest(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
        scope: String,
    ): PendingIdempotency? {
        require(scope.startsWith("mobile/v1/")) { "idempotency scope must be a typed mobile route" }
        val row = dao.findLatestIdempotency(
            instanceId,
            opaqueProfileId,
            conversationId,
            scope,
        ) ?: return null
        val aad = aad(instanceId, opaqueProfileId, conversationId, scope, row.idempotencyKey)
        val plaintext = crypto.decrypt(
            com.hermes.mobile.security.EncryptedValue.fromByteArray(row.requestBodyCiphertext),
            aad.toByteArray(StandardCharsets.UTF_8),
        )
        return PendingIdempotency(
            key = IdempotencyKey(row.idempotencyKey),
            requestBody = String(plaintext, StandardCharsets.UTF_8),
            createdAtEpochMillis = row.createdAtEpochMillis,
        )
    }

    suspend fun delete(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
        scope: String,
        key: IdempotencyKey,
    ) {
        dao.deleteIdempotency(
            instanceId,
            opaqueProfileId,
            conversationId,
            scope,
            key.value,
        )
    }

    private fun aad(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
        scope: String,
        key: String,
    ): String = listOf(instanceId, opaqueProfileId, conversationId, scope, key).joinToString("\u001f")
}

data class PendingIdempotency(
    val key: IdempotencyKey,
    val requestBody: String,
    val createdAtEpochMillis: Long,
)
