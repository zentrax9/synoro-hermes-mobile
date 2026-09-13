package com.hermes.mobile.security

import com.hermes.mobile.network.DpopProofProvider
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.HttpUrl
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.interfaces.ECPublicKey
import java.security.MessageDigest
import java.util.Base64
import java.util.Locale
import java.util.UUID
import okhttp3.HttpUrl.Companion.toHttpUrl

private const val ES256_COORDINATE_BYTES = 32
private const val DPOP_TYPE = "dpop+jwt"
private const val DPOP_ALGORITHM = "ES256"
private const val DPOP_NONCE_MIN_LENGTH = 16
private const val DPOP_NONCE_MAX_LENGTH = 256

private val dpopJson = Json {
    encodeDefaults = true
    explicitNulls = false
}

fun interface Es256Signer {
    /** Returns the ASN.1 DER-encoded ECDSA signature for the supplied signing input. */
    fun sign(signingInput: ByteArray): ByteArray
}

@Serializable
data class EcPublicJwk(
    val kty: String = "EC",
    val crv: String = "P-256",
    val x: String,
    val y: String,
) {
    init {
        require(kty == "EC") { "DPoP JWK must be an EC key" }
        require(crv == "P-256") { "DPoP JWK must use P-256" }
        require(isCoordinate(x) && isCoordinate(y)) { "DPoP JWK coordinates are invalid" }
    }

    private fun isCoordinate(value: String): Boolean = runCatching {
        val decoded = JoseBase64.decode(value)
        decoded.size == ES256_COORDINATE_BYTES && JoseBase64.encode(decoded) == value
    }.getOrDefault(false)

    companion object {
        fun from(publicKey: ECPublicKey): EcPublicJwk {
            require(publicKey.params.order == P256_ORDER) {
                "DPoP requires an NIST P-256 public key"
            }
            return EcPublicJwk(
                x = JoseBase64.encode(unsignedFixed(publicKey.w.affineX)),
                y = JoseBase64.encode(unsignedFixed(publicKey.w.affineY)),
            )
        }

        private fun unsignedFixed(value: BigInteger): ByteArray {
            require(value.signum() >= 0) { "EC coordinates must be non-negative" }
            val raw = value.toByteArray()
            val unsigned = if (raw.size > 1 && raw[0] == 0.toByte()) {
                raw.copyOfRange(1, raw.size)
            } else {
                raw
            }
            require(unsigned.size <= ES256_COORDINATE_BYTES) {
                "EC coordinate exceeds P-256 width"
            }
            return ByteArray(ES256_COORDINATE_BYTES).also {
                unsigned.copyInto(
                    destination = it,
                    destinationOffset = ES256_COORDINATE_BYTES - unsigned.size,
                )
            }
        }
    }
}

@Serializable
private data class DpopHeader(
    @SerialName("typ") val type: String = DPOP_TYPE,
    val alg: String = DPOP_ALGORITHM,
    val jwk: EcPublicJwk,
)

@Serializable
private data class DpopClaims(
    val htm: String,
    val htu: String,
    val iat: Long,
    val jti: String,
    val nonce: String,
    @SerialName("request_id") val requestId: String,
    val ath: String,
)

/** RFC 9449-shaped proof generator; the signer is deliberately injected for pure tests. */
class DpopJwtGenerator(
    private val publicKey: ECPublicKey,
    private val signer: Es256Signer,
    private val clockSeconds: () -> Long = { System.currentTimeMillis() / 1_000 },
    private val jtiGenerator: () -> String = { UUID.randomUUID().toString() },
    private val nonceGenerator: () -> String = { UUID.randomUUID().toString() },
) {
    fun create(method: String, url: HttpUrl, accessToken: String): String {
        require(method.isNotBlank()) { "DPoP method is required" }
        require(accessToken.isNotBlank()) { "DPoP access token is required" }
        val normalizedMethod = method.trim().uppercase(Locale.ROOT)
        val normalizedUrl = DpopHtu.normalize(url)
        val issuedAt = clockSeconds()
        require(issuedAt >= 0) { "DPoP iat must not be negative" }
        val jti = jtiGenerator()
        require(jti.isNotBlank()) { "DPoP jti is required" }
        val nonce = nonceGenerator()
        require(
            nonce.length in DPOP_NONCE_MIN_LENGTH..DPOP_NONCE_MAX_LENGTH &&
                nonce.all { it in '\u0021'..'\u007e' },
        ) { "DPoP nonce is invalid" }

        val encodedHeader = JoseBase64.encode(
            dpopJson.encodeToString(DpopHeader(jwk = EcPublicJwk.from(publicKey)))
                .toByteArray(StandardCharsets.UTF_8),
        )
        val encodedClaims = JoseBase64.encode(
            dpopJson.encodeToString(
                DpopClaims(
                    htm = normalizedMethod,
                    htu = normalizedUrl,
                    iat = issuedAt,
                    jti = jti,
                    nonce = nonce,
                    requestId = jti,
                    ath = JoseBase64.sha256(accessToken),
                ),
            ).toByteArray(StandardCharsets.UTF_8),
        )
        val signingInput = "$encodedHeader.$encodedClaims"
            .toByteArray(StandardCharsets.US_ASCII)
        val joseSignature = EcdsaDerSignature.toJose(
            signer.sign(signingInput),
            coordinateBytes = ES256_COORDINATE_BYTES,
        )
        return "$encodedHeader.$encodedClaims.${JoseBase64.encode(joseSignature)}"
    }
}

/** Connects the real non-exportable background Keystore key to the DPoP provider seam. */
class KeystoreDpopProofProvider(
    private val keyStore: HermesKeyStore,
    private val keyAlias: String = KeyAliases.BACKGROUND_DEVICE,
    private val clockSeconds: () -> Long = { System.currentTimeMillis() / 1_000 },
    private val jtiGenerator: () -> String = { UUID.randomUUID().toString() },
    private val nonceGenerator: () -> String = { UUID.randomUUID().toString() },
) : DpopProofProvider {
    override fun create(method: String, url: HttpUrl, accessToken: String): String {
        if (keyAlias == KeyAliases.BACKGROUND_DEVICE) keyStore.ensureBackgroundDeviceKey()
        val publicKey = keyStore.publicKey(keyAlias) as? ECPublicKey
            ?: error("DPoP background key is not an EC public key")
        return DpopJwtGenerator(
            publicKey = publicKey,
            signer = Es256Signer { input -> keyStore.sign(keyAlias, input) },
            clockSeconds = clockSeconds,
            jtiGenerator = jtiGenerator,
            nonceGenerator = nonceGenerator,
        ).create(method, url, accessToken)
    }
}

object DpopHtu {
    fun normalize(url: HttpUrl): String {
        require(url.scheme == "https") { "DPoP htu must use HTTPS" }
        require(url.username.isEmpty() && url.password.isEmpty()) {
            "DPoP htu must not contain user information"
        }
        return url.newBuilder()
            .query(null)
            .fragment(null)
            .build()
            .toString()
    }

    fun normalize(raw: String): String {
        return normalize(raw.toHttpUrl())
    }
}

object JoseBase64 {
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()

    fun encode(bytes: ByteArray): String = encoder.encodeToString(bytes)

    fun decode(value: String): ByteArray = decoder.decode(value)

    fun sha256(value: String): String = encode(
        MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(StandardCharsets.UTF_8)),
    )
}

/** Converts Java/Android DER ECDSA signatures to the fixed-width JOSE R || S form. */
object EcdsaDerSignature {
    fun toJose(der: ByteArray, coordinateBytes: Int): ByteArray {
        require(coordinateBytes > 0) { "ECDSA coordinate width must be positive" }
        require(der.firstOrNull()?.toInt() == 0x30) { "ECDSA signature must be a DER sequence" }
        var offset = 1
        val (sequenceLengthBytes, sequenceLength) = readLength(der, offset)
        offset += sequenceLengthBytes
        require(sequenceLength == der.size - offset) { "invalid DER ECDSA sequence length" }

        val (r, afterR) = readInteger(der, offset)
        val (s, afterS) = readInteger(der, afterR)
        require(afterS == der.size) { "trailing bytes in DER ECDSA signature" }
        return leftPad(r, coordinateBytes) + leftPad(s, coordinateBytes)
    }

    private fun readInteger(bytes: ByteArray, start: Int): Pair<ByteArray, Int> {
        require(bytes.getOrNull(start)?.toInt() == 0x02) { "ECDSA value must be an INTEGER" }
        val (lengthBytes, length) = readLength(bytes, start + 1)
        val valueStart = start + 1 + lengthBytes
        val valueEnd = valueStart + length
        require(length > 0 && valueEnd <= bytes.size) { "invalid DER ECDSA integer" }
        val raw = bytes.copyOfRange(valueStart, valueEnd)
        require((raw[0].toInt() and 0x80) == 0) { "negative DER ECDSA integer" }
        val unsigned = raw.dropWhile { it == 0.toByte() }.toByteArray()
        require(unsigned.isNotEmpty()) { "zero DER ECDSA integer" }
        return unsigned to valueEnd
    }

    private fun readLength(bytes: ByteArray, start: Int): Pair<Int, Int> {
        val first = bytes.getOrNull(start)?.toInt()?.and(0xff)
            ?: error("truncated DER length")
        if (first < 0x80) return 1 to first
        val count = first and 0x7f
        require(count in 1..4) { "unsupported DER length" }
        require(start + count < bytes.size) { "truncated DER long length" }
        var length = 0
        repeat(count) { index ->
            length = (length shl 8) or (bytes[start + 1 + index].toInt() and 0xff)
        }
        return (count + 1) to length
    }

    private fun leftPad(value: ByteArray, width: Int): ByteArray {
        require(value.size <= width) { "ECDSA integer exceeds coordinate width" }
        return ByteArray(width).also {
            value.copyInto(it, destinationOffset = width - value.size)
        }
    }
}

private val P256_ORDER = BigInteger(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)
