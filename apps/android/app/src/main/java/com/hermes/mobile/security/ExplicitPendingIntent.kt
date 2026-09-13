package com.hermes.mobile.security

import android.app.Activity
import android.app.PendingIntent
import android.content.Context
import android.content.Intent

/** Creates only explicit, immutable activity intents for notification and system surfaces. */
object ExplicitPendingIntents {
    fun activity(
        context: Context,
        requestCode: Int,
        destination: Class<out Activity>,
        route: String? = null,
    ): PendingIntent {
        val safeRoute = route?.let(RoutePolicy::sanitize)
            ?: if (route == null) null else error("unsupported Hermes route payload")
        val intent = Intent(context, destination).apply {
            safeRoute?.let { putExtra(EXTRA_ROUTE, it) }
        }
        return PendingIntent.getActivity(
            context,
            requestCode,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    private const val EXTRA_ROUTE = "com.hermes.mobile.extra.ROUTE"
}

object RoutePolicy {
    private val allowed = Regex("^(conversation|run|approval):[A-Za-z0-9_-]{8,256}$")

    fun sanitize(raw: String): String? = raw.trim().takeIf(allowed::matches)
}
