package com.hermes.mobile.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalLockStateTest {
    @Test
    fun defaultStateIsLocked() {
        assertTrue(LocalLockState().isLocked(0))
    }

    @Test
    fun unlockExpiresAtFiveMinutesAndOnClockRollback() {
        val unlocked = LocalLockState().recordUnlock(10_000)
        assertFalse(unlocked.isLocked(10_000 + LocalLockState.DEFAULT_TIMEOUT_MILLIS - 1))
        assertTrue(unlocked.isLocked(10_000 + LocalLockState.DEFAULT_TIMEOUT_MILLIS))
        assertTrue(unlocked.isLocked(9_999))
    }
}
