package com.hermes.mobile.data

import com.hermes.mobile.security.EncryptedValue
import com.hermes.mobile.security.EncryptedValueStore
import java.nio.charset.StandardCharsets
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Keeps the provider token encrypted until an authenticated device-registration call uses it. */
class FcmTokenRepository @Inject constructor(
    private val dao: HermesDao,
    private val crypto: EncryptedValueStore,
) {
    suspend fun save(token: String, nowEpochMillis: Long) = withContext(Dispatchers.IO) {
        require(token.length in 32..4096 && token.none { it.isISOControl() })
        require(nowEpochMillis >= 0)
        dao.saveFcmRegistration(
            FcmRegistrationEntity(
                registrationId = REGISTRATION_ID,
                tokenCiphertext = crypto.encrypt(
                    token.toByteArray(StandardCharsets.UTF_8),
                    REGISTRATION_ID.toByteArray(StandardCharsets.UTF_8),
                ).toByteArray(),
                updatedAtEpochMillis = nowEpochMillis,
            ),
        )
    }

    suspend fun load(): String? = withContext(Dispatchers.IO) {
        val row = dao.findFcmRegistration(REGISTRATION_ID) ?: return@withContext null
        String(
            crypto.decrypt(
                EncryptedValue.fromByteArray(row.tokenCiphertext),
                REGISTRATION_ID.toByteArray(StandardCharsets.UTF_8),
            ),
            StandardCharsets.UTF_8,
        ).also { token ->
            require(token.length in 32..4096 && token.none { it.isISOControl() })
        }
    }

    suspend fun clear() = withContext(Dispatchers.IO) {
        dao.deleteFcmRegistration(REGISTRATION_ID)
    }

    private companion object {
        const val REGISTRATION_ID = "primary"
    }
}
