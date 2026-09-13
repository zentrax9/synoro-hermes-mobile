package com.hermes.mobile.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface HermesDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertConversation(value: ConversationEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertMessage(value: MessageEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertRun(value: RunEntity)

    @Query(
        "SELECT * FROM runs WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND conversationId = :conversationId " +
            "AND runId = :runId LIMIT 1",
    )
    suspend fun findRun(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
        runId: String,
    ): RunEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun saveSelectedConversation(value: SelectedConversationEntity)

    @Query(
        "SELECT * FROM selected_conversations WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId LIMIT 1",
    )
    suspend fun findSelectedConversation(
        instanceId: String,
        opaqueProfileId: String,
    ): SelectedConversationEntity?

    @Query("DELETE FROM selected_conversations")
    suspend fun clearSelectedConversations()

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun saveMobileOperation(value: MobileOperationEntity)

    @Query(
        "SELECT * FROM mobile_operations WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND operationId = :operationId LIMIT 1",
    )
    suspend fun findMobileOperation(
        instanceId: String,
        opaqueProfileId: String,
        operationId: String,
    ): MobileOperationEntity?

    @Query(
        "SELECT * FROM mobile_operations WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND conversationId = :conversationId " +
            "AND kind = :kind AND state IN (:activeStates) " +
            "ORDER BY createdAtEpochMillis DESC LIMIT 1",
    )
    suspend fun findActiveMobileOperation(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
        kind: String,
        activeStates: List<String>,
    ): MobileOperationEntity?

    @Query(
        "SELECT * FROM mobile_operations WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND conversationId = :conversationId " +
            "AND kind = :kind AND resourceId = :resourceId AND state IN (:activeStates) " +
            "ORDER BY createdAtEpochMillis DESC LIMIT 1",
    )
    suspend fun findActiveMobileOperationForResource(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
        kind: String,
        resourceId: String,
        activeStates: List<String>,
    ): MobileOperationEntity?

    @Query(
        "SELECT * FROM mobile_operations WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND kind = :kind " +
            "AND resourceId = :resourceId AND state IN (:activeStates) " +
            "ORDER BY createdAtEpochMillis DESC LIMIT 1",
    )
    suspend fun findActiveMobileOperationForAnyConversation(
        instanceId: String,
        opaqueProfileId: String,
        kind: String,
        resourceId: String,
        activeStates: List<String>,
    ): MobileOperationEntity?

    @Query(
        "SELECT * FROM mobile_operations WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND runId = :runId " +
            "ORDER BY updatedAtEpochMillis DESC LIMIT 1",
    )
    suspend fun findMobileOperationForRun(
        instanceId: String,
        opaqueProfileId: String,
        runId: String,
    ): MobileOperationEntity?

    @Query(
        "SELECT * FROM mobile_operations WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND state IN ('pending', 'sending') " +
            "ORDER BY createdAtEpochMillis ASC",
    )
    suspend fun listInFlightMobileOperations(
        instanceId: String,
        opaqueProfileId: String,
    ): List<MobileOperationEntity>

    @Query(
        "SELECT * FROM mobile_operations WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND conversationId = :conversationId " +
            "AND kind = :kind ORDER BY createdAtEpochMillis DESC",
    )
    suspend fun listMobileOperations(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
        kind: String,
    ): List<MobileOperationEntity>

    @Query("DELETE FROM mobile_operations WHERE instanceId = :instanceId AND opaqueProfileId = :opaqueProfileId AND operationId = :operationId")
    suspend fun deleteMobileOperation(instanceId: String, opaqueProfileId: String, operationId: String)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertDraft(value: DraftEntity)

    @Query(
        "SELECT * FROM drafts WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND conversationId = :conversationId LIMIT 1",
    )
    suspend fun findDraft(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
    ): DraftEntity?

    @Query(
        "DELETE FROM drafts WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND conversationId = :conversationId",
    )
    suspend fun deleteDraft(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
    )

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun saveIdempotency(value: IdempotencyEntity)

    @Query(
        "SELECT * FROM idempotency_keys WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND conversationId = :conversationId " +
            "AND scope = :scope AND idempotencyKey = :idempotencyKey LIMIT 1",
    )
    suspend fun findIdempotency(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
        scope: String,
        idempotencyKey: String,
    ): IdempotencyEntity?

    @Query(
        "SELECT * FROM idempotency_keys WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND conversationId = :conversationId " +
            "AND scope = :scope ORDER BY createdAtEpochMillis DESC LIMIT 1",
    )
    suspend fun findLatestIdempotency(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
        scope: String,
    ): IdempotencyEntity?

    @Query(
        "SELECT * FROM idempotency_keys WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId ORDER BY createdAtEpochMillis ASC",
    )
    suspend fun listIdempotencyForTarget(
        instanceId: String,
        opaqueProfileId: String,
    ): List<IdempotencyEntity>

    @Query(
        "DELETE FROM idempotency_keys WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND conversationId = :conversationId " +
            "AND scope = :scope AND idempotencyKey = :idempotencyKey",
    )
    suspend fun deleteIdempotency(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
        scope: String,
        idempotencyKey: String,
    )

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun saveSecret(value: SessionSecretEntity)

    @Query(
        "SELECT * FROM session_secrets WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND secretKind = :secretKind LIMIT 1",
    )
    suspend fun findSecret(
        instanceId: String,
        opaqueProfileId: String,
        secretKind: String,
    ): SessionSecretEntity?

    @Query(
        "DELETE FROM session_secrets WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND secretKind = :secretKind",
    )
    suspend fun deleteSecret(instanceId: String, opaqueProfileId: String, secretKind: String)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun saveAuthenticationTransaction(value: AuthenticationTransactionEntity)

    @Query("SELECT * FROM auth_transactions WHERE transactionId = :transactionId LIMIT 1")
    suspend fun findAuthenticationTransaction(transactionId: String): AuthenticationTransactionEntity?

    @Query("DELETE FROM auth_transactions WHERE transactionId = :transactionId")
    suspend fun deleteAuthenticationTransaction(transactionId: String)

    @Query("SELECT transactionId FROM auth_transactions WHERE expiresAtEpochMillis <= :nowEpochMillis")
    suspend fun findExpiredAuthenticationTransactionIds(nowEpochMillis: Long): List<String>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun saveStagedAttachment(value: StagedAttachmentEntity)

    @Query("SELECT * FROM staged_attachments WHERE uploadId = :uploadId LIMIT 1")
    suspend fun findStagedAttachment(uploadId: String): StagedAttachmentEntity?

    @Query("SELECT * FROM staged_attachments WHERE expiresAtEpochMillis <= :nowEpochMillis")
    suspend fun findExpiredStagedAttachments(nowEpochMillis: Long): List<StagedAttachmentEntity>

    @Query("SELECT uploadId FROM staged_attachments")
    suspend fun listStagedAttachmentIds(): List<String>

    @Query("DELETE FROM staged_attachments WHERE uploadId = :uploadId")
    suspend fun deleteStagedAttachment(uploadId: String)

    @androidx.room.Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun saveSyncCursor(value: SyncCursorEntity)

    @Query(
        "SELECT * FROM sync_cursors WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId LIMIT 1",
    )
    suspend fun findSyncCursor(instanceId: String, opaqueProfileId: String): SyncCursorEntity?

    @Query("SELECT * FROM sync_cursors ORDER BY instanceId, opaqueProfileId")
    suspend fun listSyncTargets(): List<SyncCursorEntity>

    @androidx.room.Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun saveSyncEvent(value: SyncEventEntity)

    @Query(
        "SELECT * FROM sync_events WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND cursor > :afterCursor " +
            "ORDER BY cursor ASC, eventId ASC",
    )
    suspend fun listSyncEventsAfter(
        instanceId: String,
        opaqueProfileId: String,
        afterCursor: Long,
    ): List<SyncEventEntity>

    @Query(
        "DELETE FROM sync_events WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId",
    )
    suspend fun deleteSyncEventsForTarget(instanceId: String, opaqueProfileId: String)

    @Query(
        "DELETE FROM runs WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId",
    )
    suspend fun deleteRunsForTarget(instanceId: String, opaqueProfileId: String)

    @Query(
        "SELECT EXISTS(SELECT 1 FROM sync_events WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND (aggregateType = '' OR aggregateId = ''))",
    )
    suspend fun hasLegacySyncEvents(instanceId: String, opaqueProfileId: String): Boolean

    @Query(
        "DELETE FROM sync_events WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND createdAtEpochMillis < :cutoff",
    )
    suspend fun deleteOldSyncEvents(
        instanceId: String,
        opaqueProfileId: String,
        cutoff: Long,
    ): Int

    @androidx.room.Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun saveUploadSession(value: UploadSessionEntity)

    @Query("SELECT * FROM upload_sessions WHERE uploadId = :uploadId LIMIT 1")
    suspend fun findUploadSession(uploadId: String): UploadSessionEntity?

    @Query("DELETE FROM upload_sessions WHERE uploadId = :uploadId")
    suspend fun deleteUploadSession(uploadId: String)

    @Query("SELECT * FROM upload_sessions WHERE status = :status ORDER BY updatedAtEpochMillis ASC")
    suspend fun listUploadSessions(status: String): List<UploadSessionEntity>

    @androidx.room.Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun saveFcmRegistration(value: FcmRegistrationEntity)

    @Query("SELECT * FROM fcm_registrations WHERE registrationId = :registrationId LIMIT 1")
    suspend fun findFcmRegistration(registrationId: String): FcmRegistrationEntity?

    @Query("DELETE FROM fcm_registrations WHERE registrationId = :registrationId")
    suspend fun deleteFcmRegistration(registrationId: String)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun saveApprovalMutation(value: ApprovalMutationEntity)

    @Query(
        "SELECT * FROM approval_mutations WHERE approvalId = :approvalId " +
            "AND action = :action LIMIT 1",
    )
    suspend fun findApprovalMutation(approvalId: String, action: String): ApprovalMutationEntity?

    @Query("DELETE FROM approval_mutations WHERE approvalId = :approvalId AND action = :action")
    suspend fun deleteApprovalMutation(approvalId: String, action: String)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun saveGroupCache(value: GroupCacheEntity)

    @Query("SELECT * FROM group_caches ORDER BY updatedAtEpochMillis DESC")
    suspend fun listGroupCaches(): List<GroupCacheEntity>

    @Query("DELETE FROM group_caches WHERE instanceId = :instanceId AND groupId = :groupId")
    suspend fun deleteGroupCache(instanceId: String, groupId: String)

    @Query(
        "SELECT * FROM conversations " +
            "WHERE instanceId = :instanceId AND opaqueProfileId = :opaqueProfileId " +
            "ORDER BY updatedAtEpochMillis DESC",
    )
    fun observeConversations(instanceId: String, opaqueProfileId: String): Flow<List<ConversationEntity>>

    @Query(
        "SELECT * FROM messages WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND conversationId = :conversationId " +
            "ORDER BY createdAtEpochMillis ASC",
    )
    fun observeMessages(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
    ): Flow<List<MessageEntity>>

    @Query(
        "SELECT * FROM runs WHERE instanceId = :instanceId " +
            "AND opaqueProfileId = :opaqueProfileId AND conversationId = :conversationId " +
            "ORDER BY updatedAtEpochMillis DESC",
    )
    fun observeRuns(
        instanceId: String,
        opaqueProfileId: String,
        conversationId: String,
    ): Flow<List<RunEntity>>

    @Query("DELETE FROM conversations")
    suspend fun clearConversations()

    @Query("DELETE FROM messages")
    suspend fun clearMessages()

    @Query("DELETE FROM runs")
    suspend fun clearRuns()

    @Query("DELETE FROM drafts")
    suspend fun clearDrafts()

    @Query("DELETE FROM idempotency_keys")
    suspend fun clearIdempotencyKeys()

    @Query("DELETE FROM session_secrets")
    suspend fun clearSecrets()

    @Query("DELETE FROM auth_transactions")
    suspend fun clearAuthenticationTransactions()

    @Query("DELETE FROM staged_attachments")
    suspend fun clearStagedAttachments()

    @Query("DELETE FROM sync_cursors")
    suspend fun clearSyncCursors()

    @Query("DELETE FROM sync_events")
    suspend fun clearSyncEvents()

    @Query("DELETE FROM upload_sessions")
    suspend fun clearUploadSessions()

    @Query("DELETE FROM fcm_registrations")
    suspend fun clearFcmRegistrations()

    @Query("DELETE FROM approval_mutations")
    suspend fun clearApprovalMutations()

    @Query("DELETE FROM group_caches")
    suspend fun clearGroupCaches()

    @Query("DELETE FROM mobile_operations")
    suspend fun clearMobileOperations()
}
