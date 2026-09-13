package com.hermes.mobile.auth

import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import okhttp3.FormBody
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.HttpUrl.Companion.toHttpUrl

@Serializable
data class OAuthTokenResponse(
    @SerialName("access_token") val accessToken: String,
    @SerialName("token_type") val tokenType: String,
    @SerialName("expires_in") val expiresInSeconds: Long? = null,
    @SerialName("scope") val scope: String? = null,
) {
    init {
        require(accessToken.isNotBlank() && accessToken.none { it.isISOControl() }) {
            "OAuth access token is required"
        }
        require(tokenType.equals("Bearer", ignoreCase = true)) {
            "only bearer OAuth tokens are supported"
        }
        require(expiresInSeconds == null || expiresInSeconds in 1..86_400) {
            "OAuth token lifetime is invalid"
        }
    }
}

class PkceTokenExchange(
    private val httpClient: OkHttpClient,
    private val json: Json = Json { ignoreUnknownKeys = true; explicitNulls = false },
) {
    suspend fun exchange(
        transaction: PkceAuthTransaction,
        tokenEndpoint: String,
        authorizationCode: String,
    ): OAuthTokenResponse = withContext(Dispatchers.IO) {
        require(authorizationCode.isNotBlank() && authorizationCode.none { it.isISOControl() }) {
            "authorization code is required"
        }
        val endpoint = validatedEndpoint(tokenEndpoint)
        val form = FormBody.Builder()
            .add("grant_type", "authorization_code")
            .add("code", authorizationCode)
            .add("client_id", transaction.clientId)
            .add("redirect_uri", transaction.redirectUri)
            .add("code_verifier", transaction.codeVerifier)
            .add("resource", transaction.resource)
            .build()
        val request = Request.Builder()
            .url(endpoint)
            .header("Accept", "application/json")
            .post(form)
            .build()
        httpClient.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw IOException("OAuth token exchange failed with HTTP ${response.code}")
            }
            val body = response.body?.string() ?: throw IOException("OAuth response body is missing")
            json.decodeFromString<OAuthTokenResponse>(body)
        }
    }

    private fun validatedEndpoint(raw: String): HttpUrl {
        val endpoint = raw.toHttpUrl()
        require(
            endpoint.scheme == "https" &&
                endpoint.username.isEmpty() &&
                endpoint.password.isEmpty() &&
                endpoint.fragment == null,
        ) { "OAuth token endpoint must be HTTPS without credentials or fragments" }
        return endpoint
    }
}
