package com.hermes.mobile.contract

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class InboundIntentPolicyTest {
    @Test
    fun plainTextShareBecomesDraftWithoutOpeningContent() {
        val result = InboundIntentPolicy.resolve(
            InboundIntentPayload(
                action = InboundIntentPolicy.ACTION_SEND,
                mimeType = InboundIntentPolicy.MIME_TEXT_PLAIN,
                text = "  Please summarize this  ",
                dataUri = null,
            ),
        )

        assertEquals(
            InboundIntentDecision.Draft("Please summarize this"),
            result,
        )
    }

    @Test
    fun directUrlShareAndExplicitViewLinkUseLinkPolicyNormalization() {
        val share = InboundIntentPolicy.resolve(
            InboundIntentPayload(
                action = InboundIntentPolicy.ACTION_SEND,
                mimeType = "TEXT/PLAIN",
                text = " https://example.com/a/../b ",
                dataUri = null,
            ),
        )
        val view = InboundIntentPolicy.resolve(
            InboundIntentPayload(
                action = InboundIntentPolicy.ACTION_VIEW,
                mimeType = null,
                text = null,
                dataUri = "HTTPS://Example.com/a/../b",
            ),
        )

        assertEquals(InboundIntentDecision.Draft("https://example.com/b"), share)
        assertEquals(InboundIntentDecision.Draft("HTTPS://Example.com/b"), view)
    }

    @Test
    fun arbitraryViewSchemesAndMalformedWebUrlsAreRejected() {
        val intent = InboundIntentPolicy.resolve(
            InboundIntentPayload(
                action = InboundIntentPolicy.ACTION_VIEW,
                mimeType = null,
                text = null,
                dataUri = "intent://settings",
            ),
        )
        val malformedShare = InboundIntentPolicy.resolve(
            InboundIntentPayload(
                action = InboundIntentPolicy.ACTION_SEND,
                mimeType = InboundIntentPolicy.MIME_TEXT_PLAIN,
                text = "javascript:alert(1)",
                dataUri = null,
            ),
        )

        assertEquals(
            InboundIntentDecision.Rejected(RejectionReason.UNSAFE_LINK),
            intent,
        )
        assertEquals(
            InboundIntentDecision.Rejected(RejectionReason.UNSAFE_LINK),
            malformedShare,
        )
    }

    @Test
    fun streamsAndUnsupportedTypesStayOnExplicitAttachmentPath() {
        val stream = InboundIntentPolicy.resolve(
            InboundIntentPayload(
                action = InboundIntentPolicy.ACTION_SEND,
                mimeType = InboundIntentPolicy.MIME_TEXT_PLAIN,
                text = "ignore the stream",
                dataUri = "content://provider/private-file",
                hasStream = true,
            ),
        )
        val html = InboundIntentPolicy.resolve(
            InboundIntentPayload(
                action = InboundIntentPolicy.ACTION_SEND,
                mimeType = "text/html",
                text = "<script>alert(1)</script>",
                dataUri = null,
            ),
        )

        assertEquals(
            InboundIntentDecision.Rejected(RejectionReason.ATTACHMENT_NOT_SUPPORTED),
            stream,
        )
        assertEquals(
            InboundIntentDecision.Rejected(RejectionReason.UNSUPPORTED_MIME_TYPE),
            html,
        )
    }

    @Test
    fun oversizedAndControlCharacterPayloadsAreRejected() {
        val oversized = InboundIntentPolicy.resolve(
            InboundIntentPayload(
                action = InboundIntentPolicy.ACTION_SEND,
                mimeType = InboundIntentPolicy.MIME_TEXT_PLAIN,
                text = "x".repeat(InboundIntentPolicy.MAX_DRAFT_LENGTH + 1),
                dataUri = null,
            ),
        )
        val control = InboundIntentPolicy.resolve(
            InboundIntentPayload(
                action = InboundIntentPolicy.ACTION_SEND,
                mimeType = InboundIntentPolicy.MIME_TEXT_PLAIN,
                text = "hello\u0000world",
                dataUri = null,
            ),
        )

        assertTrue(oversized is InboundIntentDecision.Rejected)
        assertEquals(
            InboundIntentDecision.Rejected(RejectionReason.CONTROL_CHARACTER),
            control,
        )
    }

    @Test
    fun unrelatedActionsAreIgnored() {
        assertEquals(
            InboundIntentDecision.Ignored,
            InboundIntentPolicy.resolve(
                InboundIntentPayload(
                    action = "android.intent.action.MAIN",
                    mimeType = null,
                    text = null,
                    dataUri = null,
                ),
            ),
        )
    }
}
