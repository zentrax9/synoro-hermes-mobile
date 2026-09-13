package com.hermes.mobile.push

import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import com.hermes.mobile.data.FcmTokenRepository
import com.hermes.mobile.data.AuthenticationCacheInvalidatedException
import com.hermes.mobile.data.PushRegistrationCoordinator
import com.hermes.mobile.security.CacheWiper
import com.hermes.mobile.sync.SyncWorkScheduler
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking

/**
 * FCM carries only a generic wake hint. It never renders a transcript or performs a mutation;
 * foreground/WorkManager reconciliation remains the authenticated source of truth.
 */
@AndroidEntryPoint
class HermesFirebaseMessagingService : FirebaseMessagingService() {
    @Inject
    lateinit var tokenRepository: FcmTokenRepository

    @Inject
    lateinit var pushRegistration: PushRegistrationCoordinator

    override fun onNewToken(token: String) {
        if (!FirebaseRuntime.isInitialized(this)) return
        // The callback is short-lived; persist first, then let the authenticated startup path
        // register the encrypted token with the relay. No bearer/device credential is logged.
        try {
            runBlocking(Dispatchers.IO) {
                tokenRepository.save(token, System.currentTimeMillis())
                // Registration succeeds only when an approved encrypted session is already
                // active. Otherwise startup/foreground refresh will retry it later.
                try {
                    pushRegistration.registerIfAuthenticated()
                } catch (error: AuthenticationCacheInvalidatedException) {
                    // A keystore/Room failure means the encrypted session cannot be trusted;
                    // fail closed and force a clean enrollment on the next foreground launch.
                    throw error
                } catch (_: Exception) {
                    // Startup refresh will retry once an approved session is available.
                }
            }
        } catch (error: AuthenticationCacheInvalidatedException) {
            CacheWiper.wipeUnreadableCache(applicationContext)
        } catch (_: Exception) {
            // FCM retries are not a transport contract; foreground refresh will retry registration.
        }
    }

    override fun onMessageReceived(_message: RemoteMessage) {
        if (!FirebaseRuntime.isInitialized(this)) return
        // The relay deliberately sends a global wake.  Scope-looking FCM fields are untrusted and
        // are ignored; WorkManager reconciles every locally approved target through profile-scoped
        // authenticated cursor requests.
        SyncWorkScheduler.enqueue(
            context = applicationContext,
        )
    }

    override fun onDeletedMessages() {
        if (!FirebaseRuntime.isInitialized(this)) return
        // FCM may discard a backlog. The next read must rebuild from the server snapshot;
        // notification payloads are never treated as application state.
        SyncWorkScheduler.enqueue(
            context = applicationContext,
            fullReconcile = true,
        )
    }
}
