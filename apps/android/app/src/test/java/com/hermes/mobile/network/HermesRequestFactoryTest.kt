package com.hermes.mobile.network

import com.hermes.mobile.contract.IdempotencyKey
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class HermesRequestFactoryTest {
    private val auth = HermesAuthMaterial(
        cloudflareAccessToken = "cf-token",
        hermesDeviceToken = HermesDeviceToken(
            value = "device-token",
            issuedAtEpochSeconds = 1_000,
            expiresAtEpochSeconds = 1_200,
        ),
        dpopProofProvider = DpopProofProvider { method, url, accessToken ->
            "proof:$method:${url.encodedPath}:$accessToken"
        },
        clockSeconds = { 1_100 },
    )
    private val factory = HermesRequestFactory("https://hermes.example/".toHttpUrl(), auth)

    @Test
    fun getUsesTypedMobilePathAndDualHeaders() {
        val request = factory.get(MobileApiPaths.SYNC, mapOf("cursor" to "4"))
        assertEquals("https", request.url.scheme)
        assertEquals("/mobile/v1/sync", request.url.encodedPath)
        assertEquals("4", request.url.queryParameter("cursor"))
        assertEquals("Bearer cf-token", request.header("Authorization"))
        assertEquals("device-token", request.header("X-Hermes-Device-Token"))
        assertEquals("proof:GET:/mobile/v1/sync:device-token", request.header("DPoP"))
    }

    @Test
    fun everyMutationCarriesIdempotencyKey() {
        val request = factory.postJson(
            MobileApiPaths.MESSAGES,
            "{\"text\":\"hello\"}",
            IdempotencyKey("request-01"),
        )
        assertEquals("request-01", request.header("Idempotency-Key"))
        assertEquals("POST", request.method)
    }

    @Test
    fun genericRpcAndPathTraversalAreRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            factory.get("rpc/execute")
        }
        assertThrows(IllegalArgumentException::class.java) {
            factory.get("mobile/v1/../rpc")
        }
    }

    @Test
    fun baseUrlMustBeAnHttpsOriginWithoutCredentialsOrPathPrefix() {
        assertThrows(IllegalArgumentException::class.java) {
            HermesRequestFactory("https://hermes.example/api".toHttpUrl())
        }
        assertThrows(IllegalArgumentException::class.java) {
            HermesRequestFactory("https://user:pass@hermes.example/".toHttpUrl())
        }
        assertThrows(IllegalArgumentException::class.java) {
            HermesRequestFactory("http://hermes.example/".toHttpUrl())
        }
    }

    @Test
    fun accessOnlyCallsCannotReachNonBootstrapMobileRoutes() {
        assertThrows(IllegalArgumentException::class.java) {
            factory.getWithAccessToken(MobileApiPaths.PROFILES, "oauth-token")
        }
        assertThrows(IllegalArgumentException::class.java) {
            factory.postJsonWithAccessToken("mobile/v1/runs/run-id/cancel", "{}", "oauth-token")
        }
    }

    @Test
    fun expiredFiveMinuteDeviceTokenFailsBeforeNetworkAttempt() {
        val expired = HermesRequestFactory(
            "https://hermes.example/".toHttpUrl(),
            HermesAuthMaterial(
                cloudflareAccessToken = "cf-token",
                hermesDeviceToken = HermesDeviceToken("device-token", 1_000, 1_200),
                dpopProofProvider = DpopProofProvider { _, _, _ -> "proof" },
                clockSeconds = { 1_200 },
            ),
        )
        assertThrows(HermesAuthExpiredException::class.java) {
            expired.get(MobileApiPaths.SYNC)
        }
    }
}
