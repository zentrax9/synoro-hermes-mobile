package com.hermes.mobile.contract

/**
 * The small, data-only boundary for intents arriving from Android shares and explicit links.
 *
 * The Android activity deliberately maps an accepted value to a draft. This policy never
 * returns an intent to launch, an attachment URI, or a host route, so an untrusted inbound
 * intent cannot make the app open arbitrary content or perform a mutation.
 */
data class InboundIntentPayload(
    val action: String?,
    val mimeType: String?,
    val text: String?,
    val dataUri: String?,
    val hasStream: Boolean = false,
)

sealed interface InboundIntentDecision {
    data class Draft(val text: String) : InboundIntentDecision

    data class Rejected(val reason: RejectionReason) : InboundIntentDecision

    data object Ignored : InboundIntentDecision
}

enum class RejectionReason {
    EMPTY_TEXT,
    UNSUPPORTED_MIME_TYPE,
    ATTACHMENT_NOT_SUPPORTED,
    UNSAFE_LINK,
    CONTROL_CHARACTER,
    TOO_LARGE,
    MALFORMED_PAYLOAD,
}

/** Pure policy for the subset of Android inbound intents Hermes can safely turn into a draft. */
object InboundIntentPolicy {
    const val ACTION_SEND = "android.intent.action.SEND"
    const val ACTION_VIEW = "android.intent.action.VIEW"
    const val MIME_TEXT_PLAIN = "text/plain"

    /** Keep untrusted Android extras bounded before they reach Compose or the encrypted cache. */
    const val MAX_DRAFT_LENGTH = 16_384

    fun resolve(payload: InboundIntentPayload): InboundIntentDecision = when (payload.action) {
        ACTION_SEND -> resolveShare(payload)
        ACTION_VIEW -> resolveDeepLink(payload)
        else -> InboundIntentDecision.Ignored
    }

    /** Normalizes a share containing exactly one web URL, or preserves safe plain text. */
    fun sanitizeShareText(raw: String?): String? {
        val value = raw?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        if (value.length > MAX_DRAFT_LENGTH) return null
        if (value.any { it.isISOControl() && it !in SAFE_CONTROLS }) return null

        LinkPolicy.normalizeExternalUrl(value)?.let { return it }

        // A malformed HTTP(S) URL, or an explicitly actionable URI, must not be silently
        // converted into a draft that another layer might later treat as a link.
        if (value.startsWith("http:", ignoreCase = true) ||
            value.startsWith("https:", ignoreCase = true) ||
            DANGEROUS_SCHEME_PREFIXES.any { value.startsWith(it, ignoreCase = true) }
        ) {
            return null
        }
        return value
    }

    /** Accepts only an HTTP(S) deep link; the caller still renders it as a draft. */
    fun sanitizeDeepLink(raw: String?): String? {
        val value = raw?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        if (value.length > MAX_DRAFT_LENGTH) return null
        if (value.any { it.isISOControl() }) return null
        return LinkPolicy.normalizeExternalUrl(value)
    }

    private fun resolveShare(payload: InboundIntentPayload): InboundIntentDecision {
        if (payload.hasStream) {
            // Files and content:// URIs stay on the explicit SAF picker path. Do not open or
            // stage an arbitrary stream just because another app put it in a share intent.
            return InboundIntentDecision.Rejected(RejectionReason.ATTACHMENT_NOT_SUPPORTED)
        }
        if (!payload.mimeType.isNullOrBlank() &&
            !payload.mimeType.equals(MIME_TEXT_PLAIN, ignoreCase = true)
        ) {
            return InboundIntentDecision.Rejected(RejectionReason.UNSUPPORTED_MIME_TYPE)
        }
        val rawText = payload.text?.trim()?.takeIf { it.isNotEmpty() }
            ?: return InboundIntentDecision.Rejected(RejectionReason.EMPTY_TEXT)
        val sanitized = sanitizeShareText(rawText)
            ?: return InboundIntentDecision.Rejected(
                when {
                    rawText.length > MAX_DRAFT_LENGTH -> RejectionReason.TOO_LARGE
                    rawText.any { it.isISOControl() && it !in SAFE_CONTROLS } -> RejectionReason.CONTROL_CHARACTER
                    else -> RejectionReason.UNSAFE_LINK
                },
            )
        return InboundIntentDecision.Draft(sanitized)
    }

    private fun resolveDeepLink(payload: InboundIntentPayload): InboundIntentDecision {
        val sanitized = sanitizeDeepLink(payload.dataUri)
            ?: return InboundIntentDecision.Rejected(RejectionReason.UNSAFE_LINK)
        return InboundIntentDecision.Draft(sanitized)
    }

    private val SAFE_CONTROLS = setOf('\t', '\n', '\r')
    private val DANGEROUS_SCHEME_PREFIXES = setOf(
        "javascript:",
        "data:",
        "file:",
        "content:",
        "intent:",
        "android-app:",
    )
}
