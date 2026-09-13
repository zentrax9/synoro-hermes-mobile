package com.hermes.mobile.ui

import com.hermes.mobile.data.MobileOperationStates
import org.junit.Assert.assertEquals
import org.junit.Test

class SendRecoveryUiPolicyTest {
    @Test
    fun onlyUncertainCanReplayTheOriginalOperation() {
        assertEquals(SendRecoveryAction.RETRY_ORIGINAL, sendRecoveryAction(MobileOperationStates.UNCERTAIN))
        assertEquals(SendRecoveryAction.EDIT_AS_NEW, sendRecoveryAction(MobileOperationStates.REJECTED))
        assertEquals(SendRecoveryAction.EDIT_AS_NEW, sendRecoveryAction(MobileOperationStates.CONFLICT))
        assertEquals(SendRecoveryAction.EDIT_AS_NEW, sendRecoveryAction(MobileOperationStates.INDETERMINATE))
        assertEquals(SendRecoveryAction.NONE, sendRecoveryAction(MobileOperationStates.COMPLETED))
    }
}
