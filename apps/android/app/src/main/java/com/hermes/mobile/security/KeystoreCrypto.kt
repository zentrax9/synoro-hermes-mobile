package com.hermes.mobile.security

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import java.security.MessageDigest

object KeyAliases {
    const val BACKGROUND_DEVICE = "hermes.background.device.p256"
    const val USER_AUTHENTICATED = "hermes.user.authenticated.p256"
    const val VALUE_ENCRYPTION = "hermes.value.aes256"
}

private const val ANDROID_KEY_STORE = "AndroidKeyStore"
private const val AES_TRANSFORMATION = "AES/GCM/NoPadding"
private const val EC_TRANSFORMATION = "SHA256withECDSA"
private const val AES_KEY_SIZE_BITS = 256
private const val GCM_TAG_SIZE_BITS = 128
private const val USER_AUTH_VALIDITY_SECONDS = 300
private val STAGED_FILE_MAGIC = byteArrayOf('H'.code.toByte(), 'M'.code.toByte(), 'F'.code.toByte(), 1)

class UnreadableEncryptedValueException(cause: Throwable) :
    IllegalStateException("encrypted app data is no longer readable", cause)

data class EncryptedStreamResult(
    val plaintextBytes: Long,
    val sha256: ByteArray,
)

/** Keystore-backed P-256 signing key lifecycle for background and step-up authentication. */
class HermesKeyStore(
    private val keyStore: KeyStore = loadKeyStore(),
) {
    fun ensureBackgroundDeviceKey(): KeyPair = ensureSigningKey(
        alias = KeyAliases.BACKGROUND_DEVICE,
        userAuthenticated = false,
    )

    fun ensureUserAuthenticatedKey(): KeyPair = ensureSigningKey(
        alias = KeyAliases.USER_AUTHENTICATED,
        userAuthenticated = true,
    )

    fun publicKey(alias: String): PublicKey =
        requireNotNull(keyStore.getCertificate(alias)?.publicKey) {
            "Keystore key has not been enrolled: $alias"
        }

    fun sign(alias: String, payload: ByteArray): ByteArray {
        val privateKey = keyStore.getKey(alias, null) as? PrivateKey
            ?: error("Keystore signing key has not been enrolled: $alias")
        return Signature.getInstance(EC_TRANSFORMATION).run {
            initSign(privateKey)
            update(payload)
            sign()
        }
    }

    fun delete(alias: String) {
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    fun deleteAllHermesKeys() {
        listOf(
            KeyAliases.BACKGROUND_DEVICE,
            KeyAliases.USER_AUTHENTICATED,
            KeyAliases.VALUE_ENCRYPTION,
        ).forEach(::delete)
    }

    private fun ensureSigningKey(alias: String, userAuthenticated: Boolean): KeyPair {
        val existing = keyStore.getEntry(alias, null)
        if (existing is KeyStore.PrivateKeyEntry) {
            return KeyPair(existing.certificate.publicKey, existing.privateKey)
        }

        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .apply {
                if (userAuthenticated) {
                    setUserAuthenticationRequired(true)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        setUserAuthenticationParameters(
                            USER_AUTH_VALIDITY_SECONDS,
                            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                        )
                    } else {
                        @Suppress("DEPRECATION")
                        setUserAuthenticationValidityDurationSeconds(USER_AUTH_VALIDITY_SECONDS)
                    }
                }
            }
            .build()

        return KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEY_STORE,
        ).apply { initialize(spec) }.generateKeyPair()
    }

    companion object {
        private fun loadKeyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply {
            load(null)
        }
    }
}

data class EncryptedValue(
    val version: Int,
    val iv: ByteArray,
    val cipherText: ByteArray,
) {
    init {
        require(version == 1) { "unsupported encrypted value version" }
        require(iv.size == 12) { "AES-GCM IV must be 96 bits" }
        require(cipherText.isNotEmpty()) { "ciphertext must not be empty" }
    }

    fun toByteArray(): ByteArray = ByteBuffer.allocate(4 + iv.size + cipherText.size)
        .putInt(version)
        .put(iv)
        .put(cipherText)
        .array()

    companion object {
        fun fromByteArray(encoded: ByteArray): EncryptedValue {
            require(encoded.size > 16) { "encrypted value is truncated" }
            val buffer = ByteBuffer.wrap(encoded)
            val version = buffer.int
            val iv = ByteArray(12)
            buffer.get(iv)
            val cipherText = ByteArray(buffer.remaining())
            buffer.get(cipherText)
            return EncryptedValue(version, iv, cipherText)
        }
    }
}

/** AES-GCM primitive used before sensitive values enter Room or staged private files. */
class EncryptedValueStore(
    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) },
) {
    fun encrypt(value: ByteArray, associatedData: ByteArray = byteArrayOf()): EncryptedValue {
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, ensureKey())
        cipher.updateAAD(associatedData)
        return EncryptedValue(
            version = 1,
            iv = cipher.iv.copyOf(),
            cipherText = cipher.doFinal(value),
        )
    }

    fun decrypt(encrypted: EncryptedValue, associatedData: ByteArray = byteArrayOf()): ByteArray {
        return try {
            Cipher.getInstance(AES_TRANSFORMATION).run {
                init(
                    Cipher.DECRYPT_MODE,
                    ensureKey(),
                    GCMParameterSpec(GCM_TAG_SIZE_BITS, encrypted.iv),
                )
                updateAAD(associatedData)
                doFinal(encrypted.cipherText)
            }
        } catch (error: KeyPermanentlyInvalidatedException) {
            throw UnreadableEncryptedValueException(error)
        } catch (error: java.security.GeneralSecurityException) {
            // Treat an invalidated key, tampered ciphertext, or an unreadable Keystore entry as
            // one cache-invalidated condition. Callers can then wipe only Hermes app state and
            // force re-enrollment instead of rendering partial/corrupt plaintext.
            throw UnreadableEncryptedValueException(error)
        } catch (error: IllegalArgumentException) {
            throw UnreadableEncryptedValueException(error)
        }
    }

    /** Encrypts a bounded stream, writing a versioned magic/IV envelope before AES-GCM bytes. */
    fun encryptStream(
        input: InputStream,
        output: OutputStream,
        associatedData: ByteArray,
        maxPlaintextBytes: Long,
    ): EncryptedStreamResult {
        require(maxPlaintextBytes > 0) { "stream size limit must be positive" }
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, ensureKey())
        cipher.updateAAD(associatedData)
        output.write(STAGED_FILE_MAGIC)
        output.write(cipher.iv)

        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(DEFAULT_STREAM_BUFFER_BYTES)
        var bytesRead = 0L
        CipherOutputStream(output, cipher).use { encryptedOutput ->
            while (true) {
                val count = input.read(buffer)
                if (count == -1) break
                require(bytesRead + count <= maxPlaintextBytes) {
                    "staged file exceeds the configured size limit"
                }
                digest.update(buffer, 0, count)
                encryptedOutput.write(buffer, 0, count)
                bytesRead += count
            }
        }
        return EncryptedStreamResult(bytesRead, digest.digest())
    }

    /** Opens a bounded staged-file envelope after authenticating its magic and IV header. */
    fun openDecryptingStream(
        input: InputStream,
        associatedData: ByteArray,
    ): InputStream {
        return try {
            val magic = ByteArray(STAGED_FILE_MAGIC.size)
            readFully(input, magic)
            require(magic.contentEquals(STAGED_FILE_MAGIC)) { "staged file envelope is invalid" }
            val iv = ByteArray(12)
            readFully(input, iv)
            val cipher = Cipher.getInstance(AES_TRANSFORMATION).apply {
                init(
                    Cipher.DECRYPT_MODE,
                    ensureKey(),
                    GCMParameterSpec(GCM_TAG_SIZE_BITS, iv),
                )
                updateAAD(associatedData)
            }
            CipherInputStream(input, cipher)
        } catch (error: Throwable) {
            input.close()
            throw error
        }
    }

    private fun ensureKey(): SecretKey {
        val existing = keyStore.getKey(KeyAliases.VALUE_ENCRYPTION, null) as? SecretKey
        if (existing != null) return existing

        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
            .apply {
                init(
                    KeyGenParameterSpec.Builder(
                        KeyAliases.VALUE_ENCRYPTION,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                    )
                        .setKeySize(AES_KEY_SIZE_BITS)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setRandomizedEncryptionRequired(true)
                        .build(),
                )
            }
            .generateKey()
    }

    private fun readFully(input: InputStream, destination: ByteArray) {
        var offset = 0
        while (offset < destination.size) {
            val count = input.read(destination, offset, destination.size - offset)
            require(count > 0) { "staged file envelope is truncated" }
            offset += count
        }
    }

    private companion object {
        const val DEFAULT_STREAM_BUFFER_BYTES = 32 * 1024
    }
}

/**
 * Wipes only app-private cache locations after a Keystore invalidation. No user-selected path is
 * accepted here, and the staging directory is anchored under filesDir.
 */
object CacheWiper {
    fun wipeUnreadableCache(context: Context, databaseName: String = "hermes-cache.db") {
        require(databaseName == "hermes-cache.db") { "only the Hermes cache may be wiped" }
        context.deleteDatabase(databaseName)
        val stagingRoot = File(context.filesDir, "staged_uploads")
        if (stagingRoot.parentFile?.canonicalFile == context.filesDir.canonicalFile) {
            stagingRoot.deleteRecursively()
        }
    }
}
