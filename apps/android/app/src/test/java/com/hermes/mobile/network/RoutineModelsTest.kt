package com.hermes.mobile.network

import kotlinx.serialization.json.JsonNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class RoutineModelsTest {
    @Test
    fun routineWireRejectsInvalidIdentityAndRevision() {
        assertThrows(IllegalArgumentException::class.java) {
            RoutineWire("../routine", "Safe", "summary", false, 1, "\"routine-1\"")
        }
        assertThrows(IllegalArgumentException::class.java) {
            RoutineWire("routine-123456", "Safe", "summary", false, 0, "\"routine-0\"")
        }
    }

    @Test
    fun routineRunResponseAllowsDurableTerminalStatesOnly() {
        assertEquals(
            "indeterminate",
            RoutineRunResponse("run-123456", "routine-123456", "indeterminate", JsonNull).state,
        )
        assertThrows(IllegalArgumentException::class.java) {
            RoutineRunResponse("run-123456", "routine-123456", "executing", null)
        }
    }
}
