package com.hermes.mobile.data

import com.hermes.mobile.network.ApprovalWire
import com.hermes.mobile.network.ApprovalsResponse
import com.hermes.mobile.network.HermesApiClient
import com.hermes.mobile.network.IdempotencyKeys
import com.hermes.mobile.network.StepUpProofWire
import com.hermes.mobile.security.StepUpProofFactory
import javax.inject.Inject
import javax.inject.Singleton

/** Read/decide approval operations; the server owns the exact tool context and expiry. */
@Singleton
class ApprovalRepository @Inject constructor(
    private val api: HermesApiClient,
    private val authSession: HermesAuthSession,
    private val stepUpProofs: StepUpProofFactory,
    private val mutations: ApprovalMutationStore,
) {
    suspend fun listPending(): ApprovalsResponse = api.listApprovals()

    suspend fun deny(approvalId: String): ApprovalWire {
        val action = "deny"
        val stored = mutations.load(approvalId, action)
        val key = if (stored != null) {
            stored.idempotencyKey
        } else {
            val generated = IdempotencyKeys.generate()
            mutations.save(
                approvalId = approvalId,
                action = action,
                idempotencyKey = generated,
                proof = null,
                nowEpochMillis = System.currentTimeMillis(),
            )
            generated
        }
        val result = api.deny(approvalId, key)
        mutations.delete(approvalId, action)
        return result
    }

    suspend fun approveOnce(approvalId: String): ApprovalWire {
        val deviceId = authSession.currentDeviceId()
            ?: error("approved device identity is unavailable")
        // The challenge endpoint re-fetches and binds the durable server-side approval context;
        // no internal profile name, session ID, or tool arguments are reconstructed on Android.
        val action = "approve_once"
        val stored = mutations.load(approvalId, action)
        val proof: StepUpProofWire
        val key = if (stored != null && stored.proof != null) {
            proof = stored.proof
            stored.idempotencyKey
        } else {
            val challenge = api.createApprovalStepUpChallenge(approvalId)
            proof = stepUpProofs.create(challenge, deviceId)
            val generated = IdempotencyKeys.generate()
            mutations.save(
                approvalId = approvalId,
                action = action,
                idempotencyKey = generated,
                proof = proof,
                nowEpochMillis = System.currentTimeMillis(),
            )
            generated
        }
        val result = api.approve(approvalId, proof, key)
        mutations.delete(approvalId, action)
        return result
    }
}
