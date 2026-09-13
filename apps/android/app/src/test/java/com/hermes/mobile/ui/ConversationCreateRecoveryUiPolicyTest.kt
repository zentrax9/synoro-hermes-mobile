package com.hermes.mobile.ui

import com.hermes.mobile.data.MobileOperationStates
import com.hermes.mobile.data.PendingConversationCreate
import org.junit.Assert.assertEquals
import org.junit.Test

class ConversationCreateRecoveryUiPolicyTest {
    @Test
    fun noPendingOperationAllowsOneFreshCreate() {
        assertEquals(
            ConversationCreateRecoveryAction.NONE,
            conversationCreateRecoveryAction(null),
        )
    }

    @Test
    fun uncertainOperationIsTheOnlyCreateThatMayBeRetried() {
        val pending = PendingConversationCreate("create-1", MobileOperationStates.UNCERTAIN)

        assertEquals(
            ConversationCreateRecoveryAction.RETRY_ORIGINAL,
            conversationCreateRecoveryAction(pending),
        )
    }

    @Test
    fun inFlightOperationBlocksBothFreshCreateAndExplicitRetry() {
        for (state in listOf(MobileOperationStates.PENDING, MobileOperationStates.SENDING)) {
            assertEquals(
                ConversationCreateRecoveryAction.WAIT,
                conversationCreateRecoveryAction(PendingConversationCreate("create-1", state)),
            )
        }
    }
}
