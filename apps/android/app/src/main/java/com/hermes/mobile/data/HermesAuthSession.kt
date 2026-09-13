package com.hermes.mobile.data

import com.hermes.mobile.network.HermesAuthMaterial
import com.hermes.mobile.network.HermesAuthMaterialProvider
import com.hermes.mobile.network.HermesDeviceToken
import com.hermes.mobile.security.HermesKeyStore
import com.hermes.mobile.security.KeystoreDpopProofProvider
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import javax.inject.Inject
import javax.inject.Singleton

class AuthenticationCacheInvalidatedException(cause: Throwable) :
    IllegalStateException("Hermes authentication cache is unreadable; re-enrollment is required", cause)

/**
 * Holds the active session only after the caller has completed PKCE and device approval.
 * Persisted values use the same encrypted Room secret envelope as the rest of the mobile cache;
 * the request factory reads only the in-memory session and never accepts per-request tokens.
 */
@Singleton
class HermesAuthSession @Inject constructor(
    private val dao: HermesDao,
    private val crypto: com.hermes.mobile.security.EncryptedValueStore,
    private val keyStore: HermesKeyStore,
) : HermesAuthMaterialProvider {
    @Volatile
    private var active: HermesAuthMaterial? = null
    @Volatile
    private var activeDeviceId: String? = null

    override fun current(): HermesAuthMaterial? = active

    fun currentDeviceId(): String? = activeDeviceId

    suspend fun persist(
        instanceId: String,
        opaqueProfileId: String,
        material: HermesAuthMaterial,
        nowEpochMillis: Long,
        deviceId: String? = null,
    ) {
        require(instanceId.isNotBlank() && opaqueProfileId.isNotBlank())
        require(nowEpochMillis >= 0)
        val payload = Json.encodeToString(
            StoredSession(
                cloudflareAccessToken = material.cloudflareAccessToken,
                deviceToken = material.hermesDeviceToken.value,
                issuedAtEpochSeconds = material.hermesDeviceToken.issuedAtEpochSeconds,
                expiresAtEpochSeconds = material.hermesDeviceToken.expiresAtEpochSeconds,
                deviceId = deviceId,
            ),
        ).toByteArray(StandardCharsets.UTF_8)
        val aad = secretKey(instanceId, opaqueProfileId).toByteArray(StandardCharsets.UTF_8)
        dao.saveSecret(
            SessionSecretEntity(
                instanceId = instanceId,
                opaqueProfileId = opaqueProfileId,
                secretKind = SECRET_KIND,
                valueCiphertext = crypto.encrypt(payload, aad).toByteArray(),
                updatedAtEpochMillis = nowEpochMillis,
            ),
        )
        active = material
        activeDeviceId = deviceId
    }

    suspend fun restore(instanceId: String, opaqueProfileId: String): Boolean {
        require(instanceId.isNotBlank() && opaqueProfileId.isNotBlank())
        val key = secretKey(instanceId, opaqueProfileId)
        val row = dao.findSecret(instanceId, opaqueProfileId, SECRET_KIND) ?: return false
        val stored = try {
            val payload = crypto.decrypt(
                com.hermes.mobile.security.EncryptedValue.fromByteArray(row.valueCiphertext),
                key.toByteArray(StandardCharsets.UTF_8),
            )
            Json.decodeFromString<StoredSession>(
                String(payload, StandardCharsets.UTF_8),
            )
        } catch (error: Throwable) {
            if (error is com.hermes.mobile.security.UnreadableEncryptedValueException ||
                error is GeneralSecurityException ||
                error is IllegalArgumentException
            ) {
                active = null
                activeDeviceId = null
                keyStore.deleteAllHermesKeys()
                throw AuthenticationCacheInvalidatedException(error)
            }
            throw error
        }
        val material = try {
            // A persisted session without its non-exportable background key is not recoverable.
            // Fail closed before any request can accidentally fall back to bearer-only auth.
            keyStore.publicKey(com.hermes.mobile.security.KeyAliases.BACKGROUND_DEVICE)
            HermesAuthMaterial(
                cloudflareAccessToken = stored.cloudflareAccessToken,
                hermesDeviceToken = HermesDeviceToken(
                    value = stored.deviceToken,
                    issuedAtEpochSeconds = stored.issuedAtEpochSeconds,
                    expiresAtEpochSeconds = stored.expiresAtEpochSeconds,
                ),
                dpopProofProvider = KeystoreDpopProofProvider(keyStore),
            )
        } catch (error: Throwable) {
            active = null
            activeDeviceId = null
            keyStore.deleteAllHermesKeys()
            throw AuthenticationCacheInvalidatedException(error)
        }
        active = material
        activeDeviceId = stored.deviceId
        return true
    }

    suspend fun clear(instanceId: String, opaqueProfileId: String) {
        require(instanceId.isNotBlank() && opaqueProfileId.isNotBlank())
        dao.deleteSecret(instanceId, opaqueProfileId, SECRET_KIND)
        active = null
        activeDeviceId = null
    }

    fun clearInMemory() {
        active = null
        activeDeviceId = null
    }

    @Serializable
    private data class StoredSession(
        val cloudflareAccessToken: String,
        val deviceToken: String,
        val issuedAtEpochSeconds: Long,
        val expiresAtEpochSeconds: Long,
        val deviceId: String? = null,
    )

    private companion object {
        const val SECRET_KIND = "mobile-auth-session"

        fun secretKey(instanceId: String, opaqueProfileId: String): String =
            "$SECRET_KIND:$instanceId:$opaqueProfileId"
    }
}
