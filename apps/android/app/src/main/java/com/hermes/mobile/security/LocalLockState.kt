package com.hermes.mobile.security

data class LocalLockState(
    val lastUnlockedAtEpochMillis: Long? = null,
    val timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS,
) {
    init {
        require(timeoutMillis > 0) { "lock timeout must be positive" }
        require(lastUnlockedAtEpochMillis == null || lastUnlockedAtEpochMillis >= 0) {
            "unlock timestamp must not be negative"
        }
    }

    fun isLocked(nowEpochMillis: Long): Boolean {
        require(nowEpochMillis >= 0) { "current timestamp must not be negative" }
        val last = lastUnlockedAtEpochMillis ?: return true
        if (nowEpochMillis < last) return true
        return nowEpochMillis - last >= timeoutMillis
    }

    fun recordUnlock(nowEpochMillis: Long): LocalLockState {
        require(nowEpochMillis >= 0) { "unlock timestamp must not be negative" }
        return copy(lastUnlockedAtEpochMillis = nowEpochMillis)
    }

    companion object {
        const val DEFAULT_TIMEOUT_MILLIS: Long = 5 * 60 * 1_000
    }
}
