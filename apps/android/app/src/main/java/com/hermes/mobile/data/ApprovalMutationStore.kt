package com.hermes.mobile.data

import com.hermes.mobile.contract.IdempotencyKey
import com.hermes.mobile.network.StepUpProofWire
import com.hermes.mobile.security.EncryptedValue
import com.hermes.mobile.security.EncryptedValueStore
import java.nio.charset.StandardCharsets
import javax.inject.Inject
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * Persists the exact approval proof and idempotency key before its first network attempt. A crash
 * after the host consumes the proof can therefore be replayed safely and never generates a new
 * challenge/signature under the same user action.
 */
class ApprovalMutationStore @Inject constructor(
    private val dao: HermesDao,
    private val crypto: EncryptedValueStore,
) {
    suspend fun save(
        approvalId: String,
        action: String,
        idempotencyKey: IdempotencyKey,
        proof: StepUpProofWire?,
        nowEpochMillis: Long,
    ) {
        require(approvalId.isNotBlank() && action.isNotBlank() && nowEpochMillis >= 0)
        val payload = Json.encodeToString(
            StoredApprovalMutation(proof),
        ).toByteArray(StandardCharsets.UTF_8)
        dao.saveApprovalMutation(
            ApprovalMutationEntity(
                approvalId = approvalId,
                action = action,
                idempotencyKey = idempotencyKey.value,
                proofCiphertext = crypto.encrypt(payload, aad(approvalId, action)).toByteArray(),
                createdAtEpochMillis = nowEpochMillis,
            ),
        )
    }

    suspend fun load(approvalId: String, action: String): StoredApprovalMutationRecord? {
        val row = dao.findApprovalMutation(approvalId, action) ?: return null
        val payload = crypto.decrypt(
            EncryptedValue.fromByteArray(row.proofCiphertext),
            aad(approvalId, action),
        )
        val stored = Json.decodeFromString<StoredApprovalMutation>(
            String(payload, StandardCharsets.UTF_8),
        )
        return StoredApprovalMutationRecord(
            idempotencyKey = IdempotencyKey(row.idempotencyKey),
            proof = stored.proof,
            createdAtEpochMillis = row.createdAtEpochMillis,
        )
    }

    suspend fun delete(approvalId: String, action: String) {
        dao.deleteApprovalMutation(approvalId, action)
    }

    private fun aad(approvalId: String, action: String): ByteArray =
        "approval-mutation:$approvalId:$action".toByteArray(StandardCharsets.UTF_8)

    @Serializable
    private data class StoredApprovalMutation(val proof: StepUpProofWire? = null)
}

data class StoredApprovalMutationRecord(
    val idempotencyKey: IdempotencyKey,
    val proof: StepUpProofWire?,
    val createdAtEpochMillis: Long,
)
