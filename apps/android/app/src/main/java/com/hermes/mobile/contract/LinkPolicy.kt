package com.hermes.mobile.contract

import java.net.URI
import java.util.Locale

/** Client-side policy for links arriving from messages, shares, and deep links. */
object LinkPolicy {
    const val MAX_EXTERNAL_URL_LENGTH = 16_384

    fun normalizeExternalUrl(raw: String): String? {
        val candidate = raw.trim()
        if (candidate.isEmpty() || candidate.length > MAX_EXTERNAL_URL_LENGTH) return null
        if (candidate.any { it.isISOControl() }) return null
        val uri = runCatching { URI(candidate) }.getOrNull() ?: return null
        val scheme = uri.scheme?.lowercase(Locale.ROOT) ?: return null
        if (scheme != "https" && scheme != "http") return null
        if (uri.host.isNullOrBlank() || !uri.userInfo.isNullOrBlank()) return null
        if (uri.isOpaque) return null
        if (uri.fragment?.contains("javascript:", ignoreCase = true) == true) return null
        return uri.normalize().toASCIIString()
    }
}
