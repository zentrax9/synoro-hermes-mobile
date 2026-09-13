package com.hermes.mobile.data

import com.hermes.mobile.auth.PkceAuthTransaction
import com.hermes.mobile.security.EncryptedValue
import com.hermes.mobile.security.EncryptedValueStore
import java.nio.charset.StandardCharsets
import javax.inject.Inject
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** Persists PKCE state, verifier, issuer, resource, and redirect only as AES-GCM ciphertext. */
class AuthTransactionStore @Inject constructor(
    private val dao: HermesDao,
    private val crypto: EncryptedValueStore,
) {
    suspend fun persist(transaction: PkceAuthTransaction) {
        val payload = Json.encodeToString(transaction).toByteArray(StandardCharsets.UTF_8)
        val aad = transaction.transactionId.toByteArray(StandardCharsets.UTF_8)
        dao.saveAuthenticationTransaction(
            AuthenticationTransactionEntity(
                transactionId = transaction.transactionId,
                payloadCiphertext = crypto.encrypt(payload, aad).toByteArray(),
                createdAtEpochMillis = transaction.createdAtEpochMillis,
                expiresAtEpochMillis = transaction.expiresAtEpochMillis,
            ),
        )
    }

    suspend fun load(transactionId: String): PkceAuthTransaction? {
        val row = dao.findAuthenticationTransaction(transactionId) ?: return null
        val aad = transactionId.toByteArray(StandardCharsets.UTF_8)
        val bytes = crypto.decrypt(
            EncryptedValue.fromByteArray(row.payloadCiphertext),
            aad,
        )
        val transaction = Json.decodeFromString<PkceAuthTransaction>(
            String(bytes, StandardCharsets.UTF_8),
        )
        require(transaction.transactionId == transactionId) { "authentication transaction ID mismatch" }
        require(transaction.createdAtEpochMillis == row.createdAtEpochMillis) {
            "authentication transaction creation time mismatch"
        }
        require(transaction.expiresAtEpochMillis == row.expiresAtEpochMillis) {
            "authentication transaction expiry mismatch"
        }
        return transaction
    }

    suspend fun delete(transactionId: String) {
        dao.deleteAuthenticationTransaction(transactionId)
    }

    suspend fun deleteExpired(nowEpochMillis: Long): Int {
        require(nowEpochMillis >= 0)
        val ids = dao.findExpiredAuthenticationTransactionIds(nowEpochMillis)
        for (id in ids) dao.deleteAuthenticationTransaction(id)
        return ids.size
    }
}
