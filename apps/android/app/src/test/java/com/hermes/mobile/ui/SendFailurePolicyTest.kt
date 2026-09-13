package com.hermes.mobile.ui

import com.hermes.mobile.data.MobileOperationStates
import com.hermes.mobile.data.classifyMobileSendFailure
import org.junit.Assert.assertEquals
import org.junit.Test

class SendFailurePolicyTest {
    @Test
    fun authenticationFailuresRemainRetryable() {
        assertEquals(
            MobileOperationStates.UNCERTAIN,
            classifyMobileSendFailure(401, null),
        )
    }

    @Test
    fun deterministicClientFailuresRemainTerminal() {
        assertEquals(
            MobileOperationStates.REJECTED,
            classifyMobileSendFailure(422, null),
        )
    }
}
