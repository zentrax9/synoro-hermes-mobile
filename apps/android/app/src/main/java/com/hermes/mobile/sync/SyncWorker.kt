package com.hermes.mobile.sync

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.Constraints
import androidx.work.Data
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.hermes.mobile.data.AuthTransactionStore
import com.hermes.mobile.data.EncryptedAttachmentStager
import com.hermes.mobile.data.HermesDao
import com.hermes.mobile.data.AuthenticationCacheInvalidatedException
import com.hermes.mobile.data.PushRegistrationCoordinator
import com.hermes.mobile.network.HermesApiException
import com.hermes.mobile.network.HermesAuthExpiredException
import com.hermes.mobile.security.CacheWiper
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject

/**
 * WorkManager entry point for authenticated reconciliation. FCM is a wake hint, never the
 * source of truth; SyncReconciler restores encrypted sessions and refreshes device tokens.
 */
@HiltWorker
class SyncWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted workerParams: WorkerParameters,
    private val authTransactions: AuthTransactionStore,
    private val attachmentStager: EncryptedAttachmentStager,
    private val dao: HermesDao,
    private val reconciler: SyncReconciler,
    private val pushRegistration: PushRegistrationCoordinator,
) : CoroutineWorker(appContext, workerParams) {
    override suspend fun doWork(): Result {
        authTransactions.deleteExpired(System.currentTimeMillis())
        attachmentStager.cleanup(System.currentTimeMillis())
        val targets = try {
            // Push is a global wake hint, never a source of profile authorization.  Every target
            // is revalidated by the authenticated profile-scoped API before its cursor advances.
            dao.listSyncTargets().map { SyncTarget(it.instanceId, it.opaqueProfileId) }
        } catch (_: IllegalArgumentException) {
            // Corrupt local identity material must not crash a worker or widen its scope.
            return Result.failure()
        }
        if (targets.isEmpty()) return Result.success()
        return try {
            try {
                pushRegistration.registerIfAuthenticated()
            } catch (_: AuthenticationCacheInvalidatedException) {
                CacheWiper.wipeUnreadableCache(applicationContext)
                return Result.failure()
            } catch (_: Exception) {
                // Push registration is a best-effort wake channel; cursor sync remains authoritative.
            }
            for (target in targets) {
                reconciler.reconcile(
                    target = target,
                    nowEpochMillis = System.currentTimeMillis(),
                    forceSnapshot = inputData.getBoolean(SyncWorkScheduler.KEY_FULL, false),
                )
            }
            Result.success()
        } catch (_: HermesAuthExpiredException) {
            Result.failure()
        } catch (_: AuthenticationCacheInvalidatedException) {
            CacheWiper.wipeUnreadableCache(applicationContext)
            Result.failure()
        } catch (error: HermesApiException) {
            if (error.statusCode in 500..599) Result.retry() else Result.failure()
        } catch (_: java.io.IOException) {
            Result.retry()
        } catch (_: IllegalArgumentException) {
            Result.failure()
        }
    }
}

/** FCM and foreground callers enqueue a read-only wake; mutation workers remain explicit. */
object SyncWorkScheduler {
    const val KEY_FULL = "full_reconcile"
    const val KEY_WAKE = "hermes_sync_wake"
    const val WAKE_VALUE = "1"
    private const val UNIQUE_NAME = "hermes.sync.wake"

    fun enqueue(
        context: Context,
        fullReconcile: Boolean = false,
    ) {
        val data = Data.Builder()
            .apply {
                putBoolean(KEY_FULL, fullReconcile)
            }
            .build()
        val work = OneTimeWorkRequestBuilder<SyncWorker>()
            .setInputData(data)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build(),
            )
            .build()
        // A provider backlog loss is a stronger signal than an ordinary wake. Replace a queued
        // incremental pass so the forced snapshot cannot be hidden behind stale work; ordinary
        // duplicate wakes remain coalesced while one reconciliation is already pending/running.
        val policy = if (fullReconcile) ExistingWorkPolicy.REPLACE else ExistingWorkPolicy.KEEP
        WorkManager.getInstance(context).enqueueUniqueWork(UNIQUE_NAME, policy, work)
    }
}
