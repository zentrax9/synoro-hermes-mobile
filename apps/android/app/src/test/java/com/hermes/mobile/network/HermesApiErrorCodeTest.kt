package com.hermes.mobile.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class HermesApiErrorCodeTest {
    @Test
    fun parsesOnlyTheKnownDirectSendCodes() {
        assertEquals(
            MobileApiErrorCodes.IDEMPOTENCY_KEY_CONFLICT,
            parseMobileErrorCode("{\"detail\":\"idempotency key conflict\"}"),
        )
        assertEquals(
            MobileApiErrorCodes.MESSAGE_INDETERMINATE,
            parseMobileErrorCode("{\"error_code\":\"mobile_message_indeterminate\"}"),
        )
        assertEquals(
            MobileApiErrorCodes.MESSAGE_INDETERMINATE,
            parseMobileErrorCode("{\"detail\":\"mobile mutation is indeterminate\"}"),
        )
        assertNull(parseMobileErrorCode("{\"detail\":\"internal path /secret\"}"))
    }

    @Test
    fun malformedOrNonObjectErrorBodiesDoNotBecomeCodes() {
        assertNull(parseMobileErrorCode("not-json"))
        assertNull(parseMobileErrorCode("[\"idempotency key conflict\"]"))
        assertNull(parseMobileErrorCode("{}"))
    }
}
