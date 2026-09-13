package com.hermes.mobile.network

import com.hermes.mobile.contract.IdempotencyKey
import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.UUID

object MobileApiPaths {
    const val CAPABILITIES = "mobile/v1/capabilities"
    const val SYNC = "mobile/v1/sync"
    const val EVENTS = "mobile/v1/events"
    const val PROFILES = "mobile/v1/profiles"
    const val CONVERSATIONS = "mobile/v1/conversations"
    const val GROUPS = "mobile/v1/groups"
    const val MESSAGES = "mobile/v1/messages"
    const val RUNS = "mobile/v1/runs"
    const val ATTACHMENTS = "mobile/v1/attachments"
    const val CATALOG = "mobile/v1/catalog"
    const val ROUTINES = "mobile/v1/routines"
    const val DEVICES = "mobile/v1/devices"
    const val PUSH_TOKENS = "mobile/v1/devices/push-token"
}

fun interface DpopProofProvider {
    fun create(method: String, url: HttpUrl, accessToken: String): String
}

/** Supplies the currently authenticated mobile session without exposing token state to callers. */
fun interface HermesAuthMaterialProvider {
    fun current(): HermesAuthMaterial?
}

data class HermesDeviceToken(
    val value: String,
    val issuedAtEpochSeconds: Long,
    val expiresAtEpochSeconds: Long,
) {
    init {
        require(value.isNotBlank() && value.none { it.isISOControl() }) {
            "Hermes device token is required"
        }
        require(issuedAtEpochSeconds >= 0 && expiresAtEpochSeconds > issuedAtEpochSeconds) {
            "Hermes device token lifetime is invalid"
        }
        require(expiresAtEpochSeconds - issuedAtEpochSeconds <= MAX_LIFETIME_SECONDS) {
            "Hermes device token lifetime must not exceed five minutes"
        }
    }

    fun isUsable(nowEpochSeconds: Long): Boolean =
        nowEpochSeconds >= issuedAtEpochSeconds && nowEpochSeconds < expiresAtEpochSeconds

    companion object {
        private const val MAX_LIFETIME_SECONDS = 5 * 60L
    }
}

class HermesAuthExpiredException : IllegalStateException("Hermes device token is expired")

data class HermesAuthMaterial(
    val cloudflareAccessToken: String,
    val hermesDeviceToken: HermesDeviceToken,
    val dpopProofProvider: DpopProofProvider,
    val clockSeconds: () -> Long = { System.currentTimeMillis() / 1_000 },
) {
    init {
        require(
            cloudflareAccessToken.isNotBlank() &&
                cloudflareAccessToken.none { it.isISOControl() },
        )
    }

    fun requireUsableDeviceToken(): HermesDeviceToken {
        val now = clockSeconds()
        if (now < 0 || !hermesDeviceToken.isUsable(now)) {
            throw HermesAuthExpiredException()
        }
        return hermesDeviceToken
    }
}

object IdempotencyKeys {
    fun generate(): IdempotencyKey = IdempotencyKey(UUID.randomUUID().toString())
}

/** Builds only typed mobile routes; callers cannot supply a generic Hermes RPC method. */
class HermesRequestFactory(
    private val baseUrl: HttpUrl,
    private val auth: HermesAuthMaterial? = null,
    private val authProvider: HermesAuthMaterialProvider? = null,
) {
    init {
        require(baseUrl.scheme == "https") { "Hermes mobile traffic must use HTTPS" }
        require(baseUrl.encodedPath.isEmpty() || baseUrl.encodedPath == "/") {
            "Hermes mobile base URL must be an origin without a path prefix"
        }
        require(baseUrl.encodedUsername.isEmpty() && baseUrl.encodedPassword.isEmpty()) {
            "Hermes mobile base URL must not contain user credentials"
        }
        require(baseUrl.query == null && baseUrl.fragment == null) {
            "Hermes mobile base URL must not contain a query or fragment"
        }
    }

    fun get(path: String, query: Map<String, String> = emptyMap()): Request =
        requestBuilder("GET", path, query).get().build()

    /** Read-only GET variant for typed endpoints that require a correlation header. */
    fun getWithHeaders(
        path: String,
        headers: Map<String, String>,
        query: Map<String, String> = emptyMap(),
    ): Request = requestBuilder("GET", path, query)
        .apply { headers.forEach { (name, value) -> header(name, value) } }
        .get()
        .build()

    /** Access-only calls are limited to the enrollment/token bootstrap surface. */
    fun getWithAccessToken(
        path: String,
        accessToken: String,
        query: Map<String, String> = emptyMap(),
    ): Request = requestBuilder("GET", path, query, includeAuth = false)
        .also { requireAccessBootstrapPath(path) }
        .header("Authorization", "Bearer ${validatedAccessToken(accessToken)}")
        .get()
        .build()

    fun postJson(
        path: String,
        jsonBody: String,
        idempotencyKey: IdempotencyKey,
        headers: Map<String, String> = emptyMap(),
    ): Request = mutation("POST", path, jsonBody, idempotencyKey, headers)

    fun postJsonWithAccessToken(
        path: String,
        jsonBody: String,
        accessToken: String,
    ): Request = requestBuilder("POST", path, includeAuth = false)
        .also { requireAccessBootstrapPath(path) }
        .header("Authorization", "Bearer ${validatedAccessToken(accessToken)}")
        .post(jsonBody.toRequestBody(JSON))
        .build()

    fun putJson(
        path: String,
        jsonBody: String,
        idempotencyKey: IdempotencyKey,
    ): Request = mutation("PUT", path, jsonBody, idempotencyKey)

    fun patchJson(
        path: String,
        jsonBody: String,
        idempotencyKey: IdempotencyKey,
        headers: Map<String, String> = emptyMap(),
    ): Request = mutation("PATCH", path, jsonBody, idempotencyKey, headers)

    fun delete(
        path: String,
        idempotencyKey: IdempotencyKey,
        headers: Map<String, String> = emptyMap(),
    ): Request = mutation("DELETE", path, null, idempotencyKey, headers)

    fun putBytes(
        path: String,
        body: ByteArray,
        mediaType: okhttp3.MediaType,
        idempotencyKey: IdempotencyKey,
        headers: Map<String, String> = emptyMap(),
    ): Request = requestBuilder("PUT", path)
        .header("Idempotency-Key", idempotencyKey.value)
        .apply { headers.forEach { (name, value) -> header(name, value) } }
        .put(body.toRequestBody(mediaType))
        .build()

    private fun mutation(
        method: String,
        path: String,
        jsonBody: String?,
        idempotencyKey: IdempotencyKey,
        headers: Map<String, String> = emptyMap(),
    ): Request {
        val builder = requestBuilder(method, path)
            .header("Idempotency-Key", idempotencyKey.value)
            .apply { headers.forEach { (name, value) -> header(name, value) } }
        when (method) {
            "POST" -> builder.post(jsonBody.orEmpty().toRequestBody(JSON))
            "PUT" -> builder.put(jsonBody.orEmpty().toRequestBody(JSON))
            "PATCH" -> builder.patch(jsonBody.orEmpty().toRequestBody(JSON))
            "DELETE" -> builder.delete()
            else -> error("unsupported mobile mutation")
        }
        return builder.build()
    }

    private fun requestBuilder(
        method: String,
        path: String,
        query: Map<String, String> = emptyMap(),
        includeAuth: Boolean = true,
    ): Request.Builder {
        require(path.matches(ROUTE_PATTERN)) { "request path must be a typed mobile route" }
        val url = baseUrl.newBuilder()
            .addPathSegments(path)
            .apply { query.forEach { (key, value) -> addQueryParameter(key, value) } }
            .build()
        require(url.scheme == "https") { "Hermes mobile traffic must use HTTPS" }
        return Request.Builder()
            .url(url)
            .header("Accept", "application/json")
            .apply {
                if (!includeAuth) return@apply
                (authProvider?.current() ?: auth)?.let {
                    val deviceToken = it.requireUsableDeviceToken()
                    header("Authorization", "Bearer ${it.cloudflareAccessToken}")
                    header("X-Hermes-Device-Token", deviceToken.value)
                    // DPoP ``ath`` binds the proof to the short-lived Hermes device
                    // token, not to the separately-issued Cloudflare bearer token.
                    val proof = it.dpopProofProvider.create(method, url, deviceToken.value)
                    require(proof.isNotBlank()) { "DPoP proof provider returned an empty proof" }
                    header("DPoP", proof)
                }
            }
    }

    private fun validatedAccessToken(value: String): String {
        require(value.isNotBlank() && value.none { it.isISOControl() }) {
            "Cloudflare Access token is required"
        }
        return value
    }

    private fun requireAccessBootstrapPath(path: String) {
        require(
            path == MobileApiPaths.DEVICES ||
                path.matches(ACCESS_TOKEN_PATH_PATTERN),
        ) { "access-only calls are limited to device enrollment and token bootstrap" }
    }

    private companion object {
        val JSON = "application/json; charset=utf-8".toMediaType()
        val ROUTE_PATTERN = Regex("^mobile/v1/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*$")
        val ACCESS_TOKEN_PATH_PATTERN = Regex(
            "^mobile/v1/devices/[A-Za-z0-9_-]{16,256}/token(?:/challenge)?$",
        )
    }
}
