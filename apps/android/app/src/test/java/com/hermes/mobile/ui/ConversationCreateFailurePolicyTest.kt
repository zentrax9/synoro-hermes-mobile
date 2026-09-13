package com.hermes.mobile.ui

import com.hermes.mobile.data.MobileOperationStates
import com.hermes.mobile.data.classifyMobileConversationCreateFailure
import com.hermes.mobile.network.MobileApiErrorCodes
import org.junit.Assert.assertEquals
import org.junit.Test

class ConversationCreateFailurePolicyTest {
    @Test
    fun conflictsAreTerminalAndMustNotBeRetriedBlindly() {
        assertEquals(
            MobileOperationStates.CONFLICT,
            classifyMobileConversationCreateFailure(409, null),
        )
        assertEquals(
            MobileOperationStates.CONFLICT,
            classifyMobileConversationCreateFailure(400, MobileApiErrorCodes.IDEMPOTENCY_KEY_CONFLICT),
        )
    }

    @Test
    fun deterministicClientRejectionsAreTerminal() {
        assertEquals(
            MobileOperationStates.REJECTED,
            classifyMobileConversationCreateFailure(403, null),
        )
    }

    @Test
    fun transportFailuresRemainExplicitlyUncertain() {
        assertEquals(
            MobileOperationStates.UNCERTAIN,
            classifyMobileConversationCreateFailure(503, null),
        )
    }

    @Test
    fun authenticationFailuresStayRetryableUntilSessionIsRestored() {
        assertEquals(
            MobileOperationStates.UNCERTAIN,
            classifyMobileConversationCreateFailure(401, null),
        )
    }
}
