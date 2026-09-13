package com.hermes.mobile.security

import com.hermes.mobile.network.StepUpChallengeResponse
import com.hermes.mobile.network.StepUpProofWire
import java.nio.charset.StandardCharsets
import javax.inject.Inject

/**
 * Creates the exact server-bound proof used for approvals and sensitive settings.
 * Calling [sign] may require the Android user-authentication window; the UI must first present
 * BiometricPrompt (with device credential fallback) and then retry if Keystore reports that the
 * key is not currently authorized.
 */
class StepUpProofFactory @Inject constructor(
    private val keyStore: HermesKeyStore,
) {
    fun sign(
        challenge: StepUpChallengeResponse,
        deviceId: String,
    ): String {
        require(deviceId.isNotBlank() && deviceId.none { it.isISOControl() })
        val message = stepUpMessage(challenge, deviceId)
        return JoseBase64.encode(
            keyStore.sign(KeyAliases.USER_AUTHENTICATED, message),
        )
    }

    fun create(
        challenge: StepUpChallengeResponse,
        deviceId: String,
    ): StepUpProofWire = StepUpProofWire(
        challengeId = challenge.challengeId,
        action = challenge.action,
        contextDigest = challenge.contextDigest,
        nonce = challenge.nonce,
        expiresAtEpochSeconds = challenge.expiresAtEpochSeconds,
        signature = sign(challenge, deviceId),
    )

    private fun stepUpMessage(
        challenge: StepUpChallengeResponse,
        deviceId: String,
    ): ByteArray {
        require(challenge.action.isNotBlank() && challenge.action.none { it.isISOControl() })
        require(challenge.contextDigest.matches(HEX_DIGEST))
        require(challenge.nonce.isNotBlank() && challenge.nonce.none { it.isISOControl() })
        require(challenge.expiresAtEpochSeconds >= 0)
        return (
            "hermes-mobile-step-up-v1\u0000" +
                "${challenge.challengeId}\u0000$deviceId\u0000${challenge.action}\u0000" +
                "${challenge.contextDigest}\u0000${challenge.nonce}\u0000" +
                challenge.expiresAtEpochSeconds.toLong().toString()
            ).toByteArray(StandardCharsets.UTF_8)
    }

    private companion object {
        val HEX_DIGEST = Regex("^[0-9a-fA-F]{64}$")
    }
}
