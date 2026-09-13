package com.hermes.mobile.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceProofTest {
    @Test
    fun canonicalProofFieldsAreStableAndOrdered() {
        val proof = DeviceProofPayload(
            method = "post",
            normalizedUrl = "https://hermes.example/mobile/v1/messages",
            tokenThumbprint = "thumbprint",
            nonce = "nonce",
            issuedAtEpochSeconds = 100,
            requestId = "request-1",
        )
        assertEquals(
            "POST\nhttps://hermes.example/mobile/v1/messages\nthumbprint\nnonce\n100\nrequest-1",
            proof.canonical(),
        )
    }

    @Test
    fun replayGuardAcceptsOnceAndRejectsDuplicateOrStaleProofs() {
        var now = 100L
        val guard = ProofReplayGuard(clockSeconds = { now })
        val proof = DeviceProofPayload(
            method = "GET",
            normalizedUrl = "https://hermes.example/mobile/v1/sync",
            tokenThumbprint = "thumbprint",
            nonce = "nonce",
            issuedAtEpochSeconds = now,
            requestId = "request-1",
        )
        assertTrue(guard.accept(proof))
        assertFalse(guard.accept(proof))
        now = 401
        assertFalse(guard.accept(proof))
    }

    @Test
    fun proofUrlNormalizesHostAndDefaultPort() {
        assertEquals(
            "https://hermes.example/mobile/v1/sync",
            ProofUrl.normalize("HTTPS://Hermes.Example:443/mobile/v1/sync"),
        )
    }

    @Test
    fun routePolicyRejectsArbitraryDeepLinkPayloads() {
        assertEquals("conversation:conversation-1", RoutePolicy.sanitize(" conversation:conversation-1 "))
        assertEquals(null, RoutePolicy.sanitize("intent://settings"))
        assertEquals(null, RoutePolicy.sanitize("conversation:../secrets"))
    }

    @Test
    fun encryptedValueEnvelopeRoundTripsVersionAndBytes() {
        val original = EncryptedValue(1, ByteArray(12) { 1 }, ByteArray(16) { 2 })
        val decoded = EncryptedValue.fromByteArray(original.toByteArray())
        assertEquals(original.version, decoded.version)
        assertTrue(original.iv.contentEquals(decoded.iv))
        assertTrue(original.cipherText.contentEquals(decoded.cipherText))
    }
}
