package com.hermes.mobile.security

import java.net.URI
import java.util.Locale

data class DeviceProofPayload(
    val method: String,
    val normalizedUrl: String,
    val tokenThumbprint: String,
    val nonce: String,
    val issuedAtEpochSeconds: Long,
    val requestId: String,
) {
    init {
        require(method.isNotBlank()) { "proof method is required" }
        require(normalizedUrl.startsWith("https://")) { "proof URL must be HTTPS" }
        require(tokenThumbprint.isNotBlank()) { "proof token thumbprint is required" }
        require(nonce.isNotBlank()) { "proof nonce is required" }
        require(requestId.isNotBlank()) { "proof request ID is required" }
    }

    fun canonical(): String = listOf(
        method.trim().uppercase(Locale.ROOT),
        normalizedUrl,
        tokenThumbprint,
        nonce,
        issuedAtEpochSeconds.toString(),
        requestId,
    ).joinToString("\n")

    fun isWithinClockSkew(nowEpochSeconds: Long, allowedSkewSeconds: Long = 300): Boolean {
        require(allowedSkewSeconds >= 0)
        return kotlin.math.abs(nowEpochSeconds - issuedAtEpochSeconds) <= allowedSkewSeconds
    }
}

object ProofUrl {
    fun normalize(raw: String): String {
        val uri = URI(raw)
        require(uri.scheme.equals("https", ignoreCase = true)) { "proof URL must use HTTPS" }
        require(uri.host?.isNotBlank() == true) { "proof URL host is required" }
        require(uri.userInfo == null) { "proof URL must not include user information" }
        val port = when {
            uri.port == -1 || uri.port == 443 -> -1
            else -> uri.port
        }
        return URI(
            "https",
            null,
            uri.host.lowercase(Locale.ROOT),
            port,
            uri.rawPath?.ifBlank { "/" } ?: "/",
            uri.rawQuery,
            null,
        ).normalize().toASCIIString()
    }
}

/** In-memory request-ID replay guard; the server remains the source of truth. */
class ProofReplayGuard(
    private val maxEntries: Int = 2_048,
    private val clockSeconds: () -> Long = { System.currentTimeMillis() / 1_000 },
) {
    private val seen = LinkedHashMap<String, Long>()

    init {
        require(maxEntries > 0)
    }

    @Synchronized
    fun accept(proof: DeviceProofPayload, allowedSkewSeconds: Long = 300): Boolean {
        val now = clockSeconds()
        if (!proof.isWithinClockSkew(now, allowedSkewSeconds)) return false
        val cutoff = now - allowedSkewSeconds
        seen.entries.removeIf { it.value < cutoff }
        if (seen.containsKey(proof.requestId)) return false
        if (seen.size >= maxEntries) seen.remove(seen.entries.first().key)
        seen[proof.requestId] = proof.issuedAtEpochSeconds
        return true
    }
}
