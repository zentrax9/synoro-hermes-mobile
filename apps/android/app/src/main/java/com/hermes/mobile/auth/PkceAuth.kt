package com.hermes.mobile.auth

import com.hermes.mobile.security.JoseBase64
import java.net.URI
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.Locale
import kotlinx.serialization.Serializable
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl

@Serializable
data class PkceAuthTransaction(
    val transactionId: String,
    val issuer: String,
    val resource: String,
    val clientId: String,
    val authorizationEndpoint: String,
    val redirectUri: String,
    val state: String,
    val codeVerifier: String,
    val codeChallenge: String,
    val createdAtEpochMillis: Long,
    val expiresAtEpochMillis: Long,
) {
    init {
        require(transactionId.matches(OPAQUE_ID)) { "transaction ID must be opaque" }
        require(issuer == normalizeHttpsUri(issuer)) { "issuer must be an exact HTTPS URI" }
        require(resource == normalizeHttpsUri(resource)) { "resource must be an exact HTTPS URI" }
        require(
            clientId.length in 1..256 &&
                clientId.isNotBlank() &&
                clientId.none { it.isISOControl() },
        ) {
            "client ID is required"
        }
        val endpoint = authorizationEndpoint.toHttpUrl()
        require(
            endpoint.scheme == "https" &&
                endpoint.username.isEmpty() &&
                endpoint.password.isEmpty() &&
                endpoint.fragment == null,
        ) {
            "authorization endpoint must use HTTPS"
        }
        require(redirectUri == normalizeLoopbackRedirect(redirectUri)) {
            "redirect URI must be an exact loopback callback URI"
        }
        require(state.matches(VERIFIER_OR_STATE)) { "state must be URL-safe" }
        require(codeVerifier.matches(VERIFIER_OR_STATE)) { "code verifier must be URL-safe" }
        require(codeChallenge == PkceS256.challengeFor(codeVerifier)) {
            "code challenge must be S256(code verifier)"
        }
        require(createdAtEpochMillis >= 0 && expiresAtEpochMillis > createdAtEpochMillis) {
            "authorization transaction expiry is invalid"
        }
    }

    fun isExpired(nowEpochMillis: Long): Boolean {
        require(nowEpochMillis >= 0)
        return nowEpochMillis >= expiresAtEpochMillis
    }

    fun authorizationUrl(): HttpUrl = authorizationEndpoint.toHttpUrl().newBuilder()
        .addQueryParameter("response_type", "code")
        .addQueryParameter("client_id", clientId)
        .addQueryParameter("redirect_uri", redirectUri)
        .addQueryParameter("state", state)
        .addQueryParameter("code_challenge", codeChallenge)
        .addQueryParameter("code_challenge_method", "S256")
        .addQueryParameter("resource", resource)
        .build()

    companion object {
        private val OPAQUE_ID = Regex("^[A-Za-z0-9_-]{8,256}$")
        private val VERIFIER_OR_STATE = Regex("^[A-Za-z0-9._~-]{43,128}$")

        private fun normalizeHttpsUri(raw: String): String {
            val uri = URI(raw)
            require(uri.scheme.equals("https", ignoreCase = true))
            require(uri.host?.isNotBlank() == true && uri.userInfo == null)
            require(uri.fragment == null)
            return URI(
                "https",
                null,
                uri.host.lowercase(Locale.ROOT),
                if (uri.port == 443) -1 else uri.port,
                uri.rawPath?.ifBlank { "/" } ?: "/",
                uri.rawQuery,
                null,
            ).normalize().toASCIIString()
        }

        private fun normalizeLoopbackRedirect(raw: String): String {
            val uri = URI(raw)
            require(uri.scheme.equals("http", ignoreCase = true))
            require(uri.host == "127.0.0.1")
            require(uri.port in 1..65535)
            require(uri.rawPath == "/callback")
            require(uri.rawQuery == null && uri.fragment == null && uri.userInfo == null)
            return "http://127.0.0.1:${uri.port}/callback"
        }
    }
}

object PkceS256 {
    fun challengeFor(codeVerifier: String): String =
        JoseBase64.encode(
            MessageDigest.getInstance("SHA-256")
                .digest(codeVerifier.toByteArray(Charsets.US_ASCII)),
        )

    fun newTransaction(
        issuer: String,
        resource: String,
        clientId: String,
        authorizationEndpoint: String,
        redirectUri: String,
        nowEpochMillis: Long,
        ttlMillis: Long = 5 * 60 * 1_000,
        random: SecureRandom = SecureRandom(),
    ): PkceAuthTransaction {
        require(nowEpochMillis >= 0)
        require(ttlMillis > 0 && nowEpochMillis <= Long.MAX_VALUE - ttlMillis)
        val verifier = randomUrlSafe(random, 32)
        return PkceAuthTransaction(
            transactionId = randomUrlSafe(random, 16),
            issuer = normalizeForTransaction(issuer),
            resource = normalizeForTransaction(resource),
            clientId = clientId,
            authorizationEndpoint = authorizationEndpoint,
            redirectUri = redirectUri,
            state = randomUrlSafe(random, 32),
            codeVerifier = verifier,
            codeChallenge = challengeFor(verifier),
            createdAtEpochMillis = nowEpochMillis,
            expiresAtEpochMillis = nowEpochMillis + ttlMillis,
        )
    }

    private fun randomUrlSafe(random: SecureRandom, bytes: Int): String {
        val value = ByteArray(bytes)
        random.nextBytes(value)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value)
    }

    private fun normalizeForTransaction(raw: String): String {
        val uri = URI(raw)
        require(uri.scheme.equals("https", ignoreCase = true))
        require(uri.host?.isNotBlank() == true && uri.userInfo == null && uri.fragment == null)
        return URI(
            "https",
            null,
            uri.host.lowercase(Locale.ROOT),
            if (uri.port == 443) -1 else uri.port,
            uri.rawPath?.ifBlank { "/" } ?: "/",
            uri.rawQuery,
            null,
        ).normalize().toASCIIString()
    }
}

data class AuthorizationCallback(
    val code: String?,
    val state: String?,
    val issuer: String?,
    val resource: String?,
    val redirectUri: String?,
    val error: String?,
    val errorDescription: String?,
)

sealed interface AuthorizationCallbackResult {
    data class Success(val code: String, val transaction: PkceAuthTransaction) :
        AuthorizationCallbackResult

    data class Failure(val reason: String, val description: String? = null) :
        AuthorizationCallbackResult
}

object AuthorizationCallbackParser {
    private val allowedParameters = setOf(
        "code",
        "state",
        "iss",
        "resource",
        "redirect_uri",
        "error",
        "error_description",
    )

    fun parseRequestTarget(requestTarget: String, expectedRedirectUri: String): AuthorizationCallback {
        require(requestTarget.startsWith("/") && !requestTarget.startsWith("//")) {
            "callback must use origin-form request target"
        }
        val uri = parseUri(requestTarget)
        val expected = parseUri(expectedRedirectUri)
        require(uri.scheme == null && uri.host == null && uri.fragment == null)
        require(
            expected.scheme.equals("http", ignoreCase = true) &&
                expected.host == "127.0.0.1" &&
                expected.port in 1..65_535 &&
                expected.rawPath == "/callback" &&
                expected.rawQuery == null &&
                expected.fragment == null &&
                expected.userInfo == null,
        ) { "expected redirect must be an exact loopback callback URI" }
        require(uri.rawPath == expected.rawPath) { "callback path mismatch" }
        val values = parseQuery(uri.rawQuery)
        return AuthorizationCallback(
            code = values["code"],
            state = values["state"],
            issuer = values["iss"],
            resource = values["resource"],
            redirectUri = values["redirect_uri"],
            error = values["error"],
            errorDescription = values["error_description"]?.take(512),
        )
    }

    fun validate(
        callback: AuthorizationCallback,
        transaction: PkceAuthTransaction,
        nowEpochMillis: Long,
    ): AuthorizationCallbackResult {
        if (transaction.isExpired(nowEpochMillis)) {
            return AuthorizationCallbackResult.Failure("expired_transaction")
        }
        if (callback.state != transaction.state) {
            return AuthorizationCallbackResult.Failure("state_mismatch")
        }
        if (callback.issuer != transaction.issuer) {
            return AuthorizationCallbackResult.Failure("issuer_mismatch")
        }
        if (callback.resource != transaction.resource) {
            return AuthorizationCallbackResult.Failure("resource_mismatch")
        }
        if (callback.redirectUri != transaction.redirectUri) {
            return AuthorizationCallbackResult.Failure("redirect_mismatch")
        }
        if (callback.error != null && callback.code != null) {
            return AuthorizationCallbackResult.Failure("ambiguous_callback")
        }
        callback.error?.let {
            return AuthorizationCallbackResult.Failure(it, callback.errorDescription)
        }
        val code = callback.code?.takeIf { it.isNotBlank() }
            ?: return AuthorizationCallbackResult.Failure("missing_code")
        return AuthorizationCallbackResult.Success(code, transaction)
    }

    private fun parseQuery(rawQuery: String?): Map<String, String> {
        if (rawQuery.isNullOrEmpty()) return emptyMap()
        require(!rawQuery.startsWith('&') && !rawQuery.endsWith('&')) {
            "empty callback query parameter"
        }
        val values = LinkedHashMap<String, String>()
        rawQuery.split('&').forEach { pair ->
            require(pair.isNotEmpty()) { "empty callback query parameter" }
            val separator = pair.indexOf('=')
            val rawName = if (separator == -1) pair else pair.substring(0, separator)
            val rawValue = if (separator == -1) "" else pair.substring(separator + 1)
            val name = decode(rawName)
            require(name in allowedParameters) { "unexpected callback parameter" }
            require(!values.containsKey(name)) { "duplicate callback parameter" }
            values[name] = decode(rawValue)
        }
        return values
    }

    private fun decode(value: String): String =
        try {
            java.net.URLDecoder.decode(value, Charsets.UTF_8.name())
        } catch (error: Exception) {
            throw IllegalArgumentException("malformed callback encoding", error)
        }

    private fun parseUri(value: String): URI =
        try {
            URI(value)
        } catch (error: Exception) {
            throw IllegalArgumentException("malformed callback request target", error)
        }
}
