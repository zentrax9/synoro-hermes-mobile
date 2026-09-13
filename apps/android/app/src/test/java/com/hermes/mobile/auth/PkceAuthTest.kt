package com.hermes.mobile.auth

import java.net.URLEncoder
import java.net.Socket
import java.net.URI
import java.io.IOException
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

class PkceAuthTest {
    private val verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    private val transaction = PkceAuthTransaction(
        transactionId = "transaction-1",
        issuer = "https://issuer.example/",
        resource = "https://api.example/hermes",
        clientId = "hermes-mobile",
        authorizationEndpoint = "https://issuer.example/authorize",
        redirectUri = "http://127.0.0.1:34567/callback",
        state = "state-state-state-state-state-state-state-state-1",
        codeVerifier = verifier,
        codeChallenge = PkceS256.challengeFor(verifier),
        createdAtEpochMillis = 100,
        expiresAtEpochMillis = 1_000,
    )

    @Test
    fun rfc7636S256ChallengeMatchesKnownVector() {
        assertEquals(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            PkceS256.challengeFor(verifier),
        )
    }

    @Test
    fun authorizationUrlContainsS256AndExactRedirect() {
        val url = transaction.authorizationUrl()
        assertEquals("https", url.scheme)
        assertEquals("code", url.queryParameter("response_type"))
        assertEquals("S256", url.queryParameter("code_challenge_method"))
        assertEquals(transaction.redirectUri, url.queryParameter("redirect_uri"))
        assertEquals(transaction.resource, url.queryParameter("resource"))
    }

    @Test
    fun callbackRequiresExactStateIssuerResourceAndRedirect() {
        val callback = AuthorizationCallbackParser.parseRequestTarget(
            requestTarget = "/callback?code=code-1" +
                "&state=${enc(transaction.state)}" +
                "&iss=${enc(transaction.issuer)}" +
                "&resource=${enc(transaction.resource)}" +
                "&redirect_uri=${enc(transaction.redirectUri)}",
            expectedRedirectUri = transaction.redirectUri,
        )
        val result = AuthorizationCallbackParser.validate(callback, transaction, 500)
        assertTrue(result is AuthorizationCallbackResult.Success)
        assertEquals("code-1", (result as AuthorizationCallbackResult.Success).code)

        val wrongResource = callback.copy(resource = "https://other.example")
        assertEquals(
            "resource_mismatch",
            (AuthorizationCallbackParser.validate(wrongResource, transaction, 500)
                as AuthorizationCallbackResult.Failure).reason,
        )
    }

    @Test
    fun callbackParserRejectsDuplicateAndUnknownParameters() {
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationCallbackParser.parseRequestTarget(
                "/callback?state=${transaction.state}&state=again",
                transaction.redirectUri,
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationCallbackParser.parseRequestTarget(
                "/callback?unexpected=value",
                transaction.redirectUri,
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationCallbackParser.parseRequestTarget(
                "/callback?state=%ZZ",
                transaction.redirectUri,
            )
        }
    }

    @Test
    fun transactionSerializationPreservesVerifierAndRedirect() {
        val json = Json.encodeToString(transaction)
        val decoded = Json.decodeFromString<PkceAuthTransaction>(json)
        assertEquals(transaction.codeVerifier, decoded.codeVerifier)
        assertEquals(transaction.redirectUri, decoded.redirectUri)
    }

    @Test
    fun loopbackCallbackAcceptsOneRequestAndClosesListener() = runBlocking {
        val listener = EphemeralLoopbackCallback.open(timeoutMillis = 5_000)
        val callbackTransaction = PkceS256.newTransaction(
            issuer = transaction.issuer,
            resource = transaction.resource,
            clientId = transaction.clientId,
            authorizationEndpoint = transaction.authorizationEndpoint,
            redirectUri = listener.redirectUri,
            nowEpochMillis = 100,
        )
        val result = async {
            listener.await(callbackTransaction) { 500 }
        }
        delay(10)
        val port = URI(listener.redirectUri).port
        var socket: Socket? = null
        for (attempt in 0 until 50) {
            if (socket == null) {
                try {
                    socket = Socket("127.0.0.1", port)
                } catch (_: IOException) {
                    delay(10)
                }
            }
            if (socket != null) break
        }
        requireNotNull(socket).use { connected ->
            val query = "code=code-1" +
                "&state=${enc(callbackTransaction.state)}" +
                "&iss=${enc(callbackTransaction.issuer)}" +
                "&resource=${enc(callbackTransaction.resource)}" +
                "&redirect_uri=${enc(callbackTransaction.redirectUri)}"
            connected.getOutputStream().write(
                (
                    "GET /callback?$query HTTP/1.1\r\n" +
                        "Host: 127.0.0.1:$port\r\n\r\n"
                    ).toByteArray(Charsets.US_ASCII),
            )
            connected.getOutputStream().flush()
            connected.getInputStream().readBytes()
        }
        assertTrue(result.await() is AuthorizationCallbackResult.Success)
        assertThrows(java.io.IOException::class.java) {
            Socket("127.0.0.1", port)
        }
    }

    private fun enc(value: String): String = URLEncoder.encode(value, Charsets.UTF_8.name())
}
