package com.hermes.mobile.data

import com.hermes.mobile.network.HermesApiClient
import com.hermes.mobile.network.IdempotencyKeys
import javax.inject.Inject
import javax.inject.Singleton

/** Registers the encrypted FCM token only after an approved Hermes session is active. */
@Singleton
class PushRegistrationCoordinator @Inject constructor(
    private val tokens: FcmTokenRepository,
    private val authSession: HermesAuthSession,
    private val api: HermesApiClient,
) {
    suspend fun registerIfAuthenticated(): Boolean {
        val token = try {
            tokens.load()
        } catch (error: com.hermes.mobile.security.UnreadableEncryptedValueException) {
            throw AuthenticationCacheInvalidatedException(error)
        } ?: return false
        val deviceId = authSession.currentDeviceId() ?: return false
        authSession.current()?.requireUsableDeviceToken() ?: return false
        api.registerFcmToken(deviceId, token, IdempotencyKeys.generate())
        return true
    }

    suspend fun revokeIfAuthenticated(): Boolean {
        val deviceId = authSession.currentDeviceId() ?: return false
        authSession.current()?.requireUsableDeviceToken() ?: return false
        api.revokeFcmToken(deviceId, IdempotencyKeys.generate())
        tokens.clear()
        return true
    }
}
