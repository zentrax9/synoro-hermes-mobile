package com.hermes.mobile.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.hermesPreferences: DataStore<Preferences> by preferencesDataStore(
    name = "hermes_preferences",
)

data class AppPreferences(
    val blockScreenshots: Boolean = true,
    val lastUnlockedAtEpochMillis: Long? = null,
)

class AppPreferencesRepository(private val dataStore: DataStore<Preferences>) {
    val preferences: Flow<AppPreferences> = dataStore.data.map { values ->
        AppPreferences(
            blockScreenshots = values[Keys.BLOCK_SCREENSHOTS] ?: true,
            lastUnlockedAtEpochMillis = values[Keys.LAST_UNLOCKED_AT],
        )
    }

    suspend fun setBlockScreenshots(enabled: Boolean) {
        dataStore.edit { it[Keys.BLOCK_SCREENSHOTS] = enabled }
    }

    suspend fun recordUnlock(nowEpochMillis: Long) {
        require(nowEpochMillis >= 0)
        dataStore.edit { it[Keys.LAST_UNLOCKED_AT] = nowEpochMillis }
    }

    suspend fun clearUnlock() {
        dataStore.edit { it.remove(Keys.LAST_UNLOCKED_AT) }
    }

    private object Keys {
        val BLOCK_SCREENSHOTS = booleanPreferencesKey("block_screenshots")
        val LAST_UNLOCKED_AT = longPreferencesKey("last_unlocked_at")
    }
}

fun Context.appPreferencesRepository(): AppPreferencesRepository =
    AppPreferencesRepository(hermesPreferences)
