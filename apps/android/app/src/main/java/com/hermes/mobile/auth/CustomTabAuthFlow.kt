package com.hermes.mobile.auth

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import com.hermes.mobile.data.AuthTransactionStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean

data class AuthorizationStart(
    val issuer: String,
    val resource: String,
    val clientId: String,
    val authorizationEndpoint: String,
    val nowEpochMillis: Long,
    val ttlMillis: Long = 5 * 60 * 1_000,
)

/**
 * Starts OAuth in an external Custom Tab only after the loopback listener and encrypted PKCE
 * transaction are ready. The caller must keep the returned pending flow and await it exactly once.
 */
class CustomTabPkceFlow(
    private val transactions: AuthTransactionStore,
    private val callbackFactory: () -> EphemeralLoopbackCallback = {
        EphemeralLoopbackCallback.open()
    },
) {
    suspend fun begin(context: Context, start: AuthorizationStart): PendingAuthorization {
        val callback = callbackFactory()
        val transaction = try {
            val value = PkceS256.newTransaction(
                issuer = start.issuer,
                resource = start.resource,
                clientId = start.clientId,
                authorizationEndpoint = start.authorizationEndpoint,
                redirectUri = callback.redirectUri,
                nowEpochMillis = start.nowEpochMillis,
                ttlMillis = start.ttlMillis,
            )
            transactions.persist(value)
            value
        } catch (error: Throwable) {
            callback.close()
            throw error
        }

        try {
            withContext(Dispatchers.Main.immediate) {
                val customTabs = CustomTabsIntent.Builder().build()
                // MainViewModel is intentionally scoped to the application, so enrollment may
                // receive an application context. Custom Tabs requires NEW_TASK in that case.
                if (context !is Activity) {
                    customTabs.intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                customTabs.launchUrl(
                    context,
                    Uri.parse(transaction.authorizationUrl().toString()),
                )
            }
        } catch (error: Throwable) {
            callback.close()
            transactions.delete(transaction.transactionId)
            throw error
        }
        return PendingAuthorization(callback, transaction, transactions)
    }
}

class PendingAuthorization internal constructor(
    private val callback: EphemeralLoopbackCallback,
    val transaction: PkceAuthTransaction,
    private val transactions: AuthTransactionStore,
) {
    private val finished = AtomicBoolean(false)

    suspend fun await(nowEpochMillis: () -> Long): AuthorizationCallbackResult {
        check(finished.compareAndSet(false, true)) { "authorization callback already awaited" }
        return try {
            callback.await(transaction, nowEpochMillis)
        } finally {
            callback.close()
            transactions.delete(transaction.transactionId)
        }
    }

    suspend fun cancel() {
        if (!finished.compareAndSet(false, true)) return
        callback.close()
        transactions.delete(transaction.transactionId)
    }
}
