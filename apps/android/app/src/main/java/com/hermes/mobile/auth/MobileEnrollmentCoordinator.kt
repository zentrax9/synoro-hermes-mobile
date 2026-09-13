package com.hermes.mobile.auth

import android.content.Context
import com.hermes.mobile.data.HermesAuthSession
import com.hermes.mobile.network.DeviceEnrollmentRequest
import com.hermes.mobile.network.DeviceEnrollmentResponse
import com.hermes.mobile.network.DeviceTokenRequest
import com.hermes.mobile.network.HermesApiClient
import com.hermes.mobile.network.HermesAuthMaterial
import com.hermes.mobile.network.HermesDeviceToken
import com.hermes.mobile.security.EcPublicJwk
import com.hermes.mobile.security.HermesKeyStore
import com.hermes.mobile.security.JoseBase64
import com.hermes.mobile.security.KeystoreDpopProofProvider
import com.hermes.mobile.security.KeyAliases
import java.nio.charset.StandardCharsets
import javax.inject.Inject
import javax.inject.Singleton

data class PendingDeviceEnrollment(
    val accessToken: String,
    val response: DeviceEnrollmentResponse,
)

/** Coordinates PKCE, host enrollment, nonce refresh, and encrypted session persistence. */
@Singleton
class MobileEnrollmentCoordinator @Inject constructor(
    private val pkceFlow: CustomTabPkceFlow,
    private val tokenExchange: PkceTokenExchange,
    private val api: HermesApiClient,
    private val keyStore: HermesKeyStore,
    private val authSession: HermesAuthSession,
) {
    suspend fun enroll(
        context: Context,
        authorization: AuthorizationStart,
        tokenEndpoint: String,
        deviceLabel: String,
        nowEpochMillis: Long,
    ): PendingDeviceEnrollment {
        require(deviceLabel.isNotBlank() && deviceLabel.length <= 64) {
            "device label is required"
        }
        val pending = pkceFlow.begin(context, authorization)
        // Validate the callback against the real wall clock, not the timestamp captured before
        // the browser opened; otherwise a stalled Custom Tab could outlive the PKCE TTL.
        val callback = pending.await { maxOf(nowEpochMillis, System.currentTimeMillis()) }
        val success = callback as? AuthorizationCallbackResult.Success
            ?: throw IllegalStateException("OAuth authorization failed")
        val oauth = tokenExchange.exchange(
            transaction = success.transaction,
            tokenEndpoint = tokenEndpoint,
            authorizationCode = success.code,
        )
        val enrollment = api.enrollDevice(
            cloudflareAccessToken = oauth.accessToken,
            request = DeviceEnrollmentRequest(
                deviceLabel = deviceLabel,
                backgroundJwk = keyStore.ensureBackgroundDeviceKey().publicKey.toJwkMap(),
                userPresenceJwk = keyStore.ensureUserAuthenticatedKey().publicKey.toJwkMap(),
            ),
        )
        return PendingDeviceEnrollment(oauth.accessToken, enrollment)
    }

    /** Call after local approval, once the user has selected an opaque instance/profile target. */
    suspend fun establishApprovedSession(
        pending: PendingDeviceEnrollment,
        instanceId: String,
        opaqueProfileId: String,
        nowEpochMillis: Long,
    ): HermesAuthMaterial {
        require(nowEpochMillis >= 0)
        val deviceId = pending.response.deviceId
        val challenge = api.createDeviceTokenChallenge(pending.accessToken, deviceId)
        val signature = keyStore.sign(
            KeyAliases.BACKGROUND_DEVICE,
            tokenChallengeMessage(deviceId, challenge.nonce),
        )
        val issued = api.issueDeviceToken(
            cloudflareAccessToken = pending.accessToken,
            deviceId = deviceId,
            request = DeviceTokenRequest(
                nonce = challenge.nonce,
                signature = JoseBase64.encode(signature),
            ),
        )
        val issuedAt = nowEpochMillis / 1_000
        require(issued.expiresInSeconds in 1..300) { "device token lifetime exceeds five minutes" }
        val material = HermesAuthMaterial(
            cloudflareAccessToken = pending.accessToken,
            hermesDeviceToken = HermesDeviceToken(
                value = issued.deviceToken,
                issuedAtEpochSeconds = issuedAt,
                expiresAtEpochSeconds = issuedAt + issued.expiresInSeconds,
            ),
            dpopProofProvider = KeystoreDpopProofProvider(keyStore),
        )
        authSession.persist(
            instanceId = instanceId,
            opaqueProfileId = opaqueProfileId,
            material = material,
            nowEpochMillis = nowEpochMillis,
            deviceId = deviceId,
        )
        return material
    }

    /**
     * Refreshes the five-minute Hermes token without re-running OAuth. The host nonce is
     * single-use, so every refresh signs a fresh challenge with the non-exportable background key.
     */
    suspend fun refreshApprovedSession(
        instanceId: String,
        opaqueProfileId: String,
        cloudflareAccessToken: String,
        deviceId: String,
        nowEpochMillis: Long,
    ): HermesAuthMaterial {
        require(instanceId.isNotBlank() && opaqueProfileId.isNotBlank())
        require(deviceId.isNotBlank() && nowEpochMillis >= 0)
        val challenge = api.createDeviceTokenChallenge(cloudflareAccessToken, deviceId)
        val signature = keyStore.sign(
            KeyAliases.BACKGROUND_DEVICE,
            tokenChallengeMessage(deviceId, challenge.nonce),
        )
        val issued = api.issueDeviceToken(
            cloudflareAccessToken = cloudflareAccessToken,
            deviceId = deviceId,
            request = DeviceTokenRequest(
                nonce = challenge.nonce,
                signature = JoseBase64.encode(signature),
            ),
        )
        val issuedAt = nowEpochMillis / 1_000
        require(issued.expiresInSeconds in 1..300) { "device token lifetime exceeds five minutes" }
        val material = HermesAuthMaterial(
            cloudflareAccessToken = cloudflareAccessToken,
            hermesDeviceToken = HermesDeviceToken(
                value = issued.deviceToken,
                issuedAtEpochSeconds = issuedAt,
                expiresAtEpochSeconds = issuedAt + issued.expiresInSeconds,
            ),
            dpopProofProvider = KeystoreDpopProofProvider(keyStore),
        )
        authSession.persist(
            instanceId = instanceId,
            opaqueProfileId = opaqueProfileId,
            material = material,
            nowEpochMillis = nowEpochMillis,
            deviceId = deviceId,
        )
        return material
    }

    private fun tokenChallengeMessage(deviceId: String, nonce: String): ByteArray {
        require(deviceId.isNotBlank() && deviceId.none { it.isISOControl() })
        require(nonce.isNotBlank() && nonce.none { it.isISOControl() })
        return "hermes-mobile-token-v1\u0000$deviceId\u0000$nonce"
            .toByteArray(StandardCharsets.US_ASCII)
    }
}

private fun java.security.PublicKey.toJwkMap(): Map<String, String> {
    val ec = this as? java.security.interfaces.ECPublicKey
        ?: error("Hermes device key must be an EC public key")
    val jwk = EcPublicJwk.from(ec)
    return mapOf(
        "kty" to jwk.kty,
        "crv" to jwk.crv,
        "x" to jwk.x,
        "y" to jwk.y,
    )
}
