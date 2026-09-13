package com.hermes.mobile.push

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build

/**
 * The relay sends fixed, generic status text. Keep that system-rendered notification on one
 * named channel so Android users can control its importance and DND behavior. Hermes does not
 * invent an app-level quiet-hours schedule; the host contract currently exposes only `enabled`.
 */
object HermesNotificationChannels {
    const val ATTENTION_CHANNEL_ID = "hermes_attention"

    fun ensureCreated(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        if (manager.getNotificationChannel(ATTENTION_CHANNEL_ID) != null) return
        manager.createNotificationChannel(
            NotificationChannel(
                ATTENTION_CHANNEL_ID,
                context.getString(com.hermes.mobile.R.string.notification_channel_attention_name),
                NotificationManager.IMPORTANCE_DEFAULT,
            ).apply {
                description = context.getString(
                    com.hermes.mobile.R.string.notification_channel_attention_description,
                )
                setShowBadge(true)
            },
        )
    }
}
