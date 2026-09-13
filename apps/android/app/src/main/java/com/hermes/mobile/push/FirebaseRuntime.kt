package com.hermes.mobile.push

import android.content.Context
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.hermes.mobile.BuildConfig

/**
 * Initializes Firebase only when the release build supplied a complete installation config.
 *
 * The host and the Android client must remain useful without Google Play Services, so an
 * unconfigured or malformed Firebase setup is a disabled push transport rather than an app-start
 * failure. FCM is only a wake hint; authenticated foreground/WorkManager reconciliation remains
 * the source of truth.
 */
object FirebaseRuntime {
    fun initialize(context: Context): Boolean {
        if (isInitialized(context)) return true
        if (!BuildConfig.FIREBASE_CONFIGURED) return false

        return runCatching {
            FirebaseApp.initializeApp(
                context,
                FirebaseOptions.Builder()
                    .setProjectId(BuildConfig.FIREBASE_PROJECT_ID)
                    .setApplicationId(BuildConfig.FIREBASE_APPLICATION_ID)
                    .setApiKey(BuildConfig.FIREBASE_API_KEY)
                    .setGcmSenderId(BuildConfig.FIREBASE_SENDER_ID)
                    .build(),
            )
            isInitialized(context)
        }.getOrDefault(false)
    }

    fun isInitialized(context: Context): Boolean =
        FirebaseApp.getApps(context).any { app -> app.name == FirebaseApp.DEFAULT_APP_NAME }
}
