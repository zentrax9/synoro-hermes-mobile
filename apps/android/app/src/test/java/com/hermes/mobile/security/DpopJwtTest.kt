package com.hermes.mobile.security

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.nio.charset.StandardCharsets
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DpopJwtTest {
    private val keyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    @Test
    fun generatorEmitsRfc9449ShapeWithJwkClaimsAndTokenHash() {
        val generator = DpopJwtGenerator(
            publicKey = keyPair.public as java.security.interfaces.ECPublicKey,
            signer = Es256Signer { input ->
                Signature.getInstance("SHA256withECDSA").run {
                    initSign(keyPair.private)
                    update(input)
                    sign()
                }
            },
            clockSeconds = { 1_700_000_000L },
            jtiGenerator = { "jti-123" },
            nonceGenerator = { "nonce-0000000001" },
        )

        val jwt = generator.create(
            method = "post",
            url = "HTTPS://Example.com:443/mobile/v1/messages?cursor=4".toHttpUrl(),
            accessToken = "cloudflare-token",
        )
        val parts = jwt.split('.')
        assertEquals(3, parts.size)

        val json = Json {}
        val header = json.parseToJsonElement(
            String(JoseBase64.decode(parts[0]), StandardCharsets.UTF_8),
        ).jsonObject
        val claims = json.parseToJsonElement(
            String(JoseBase64.decode(parts[1]), StandardCharsets.UTF_8),
        ).jsonObject
        val jwk = header.getValue("jwk").jsonObject

        assertEquals("dpop+jwt", header.getValue("typ").jsonPrimitive.content)
        assertEquals("ES256", header.getValue("alg").jsonPrimitive.content)
        assertEquals("EC", jwk.getValue("kty").jsonPrimitive.content)
        assertEquals("P-256", jwk.getValue("crv").jsonPrimitive.content)
        assertEquals(32, JoseBase64.decode(jwk.getValue("x").jsonPrimitive.content).size)
        assertEquals(32, JoseBase64.decode(jwk.getValue("y").jsonPrimitive.content).size)
        assertEquals("POST", claims.getValue("htm").jsonPrimitive.content)
        assertEquals(
            "https://example.com/mobile/v1/messages",
            claims.getValue("htu").jsonPrimitive.content,
        )
        assertEquals("1700000000", claims.getValue("iat").jsonPrimitive.content)
        assertEquals("jti-123", claims.getValue("jti").jsonPrimitive.content)
        assertEquals("nonce-0000000001", claims.getValue("nonce").jsonPrimitive.content)
        assertEquals("jti-123", claims.getValue("request_id").jsonPrimitive.content)
        assertEquals(
            "YP9yrQnqJsCI-_UbMOL5xpdmFFo1HIC__f0HXyVySVA",
            claims.getValue("ath").jsonPrimitive.content,
        )
        val joseSignature = JoseBase64.decode(parts[2])
        assertEquals(64, joseSignature.size)
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(keyPair.public)
            update("${parts[0]}.${parts[1]}".toByteArray(StandardCharsets.US_ASCII))
            assertTrue(verify(joseToDer(joseSignature)))
        }
    }

    @Test
    fun derSignatureConvertsToFixedWidthJoseRAndS() {
        val jose = EcdsaDerSignature.toJose(
            byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02),
            coordinateBytes = 32,
        )
        assertEquals(64, jose.size)
        assertEquals(1, jose[31].toInt())
        assertEquals(2, jose[63].toInt())
        assertTrue(jose.take(31).all { it == 0.toByte() })
    }

    @Test
    fun htuNormalizationDropsQueryAndFragmentAndDefaultPort() {
        assertEquals(
            "https://example.com/mobile/v1/sync",
            DpopHtu.normalize("HTTPS://Example.com:443/mobile/v1/sync?cursor=4#fragment"),
        )
    }

    private fun joseToDer(jose: ByteArray): ByteArray {
        require(jose.size == 64)
        fun integer(offset: Int): ByteArray {
            val unsigned = jose.copyOfRange(offset, offset + 32).dropWhile { it == 0.toByte() }
                .toByteArray()
            val first = unsigned.firstOrNull()?.toInt() ?: 0
            val value = if ((first and 0x80) != 0) {
                byteArrayOf(0) + unsigned
            } else {
                unsigned
            }
            return byteArrayOf(0x02, value.size.toByte()) + value
        }
        val body = integer(0) + integer(32)
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}
