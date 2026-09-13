package com.hermes.mobile.data

import androidx.room.Database
import androidx.room.migration.Migration
import androidx.room.RoomDatabase
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(
    entities = [
        ConversationEntity::class,
        MessageEntity::class,
        RunEntity::class,
        DraftEntity::class,
        IdempotencyEntity::class,
        SessionSecretEntity::class,
        AuthenticationTransactionEntity::class,
        StagedAttachmentEntity::class,
        SyncCursorEntity::class,
        SyncEventEntity::class,
        SelectedConversationEntity::class,
        MobileOperationEntity::class,
        UploadSessionEntity::class,
        FcmRegistrationEntity::class,
        ApprovalMutationEntity::class,
        GroupCacheEntity::class,
    ],
    version = 6,
    exportSchema = true,
)
abstract class HermesDatabase : RoomDatabase() {
    abstract fun hermesDao(): HermesDao
}

val MIGRATION_1_2 = object : Migration(1, 2) {
    override fun migrate(database: SupportSQLiteDatabase) {
        database.execSQL(
            "CREATE TABLE IF NOT EXISTS auth_transactions (" +
                "transactionId TEXT NOT NULL, " +
                "payloadCiphertext BLOB NOT NULL, " +
                "createdAtEpochMillis INTEGER NOT NULL, " +
                "expiresAtEpochMillis INTEGER NOT NULL, " +
                "PRIMARY KEY(transactionId))",
        )
        database.execSQL(
            "CREATE TABLE IF NOT EXISTS staged_attachments (" +
                "uploadId TEXT NOT NULL, " +
                "metadataCiphertext BLOB NOT NULL, " +
                "createdAtEpochMillis INTEGER NOT NULL, " +
                "expiresAtEpochMillis INTEGER NOT NULL, " +
                "plaintextBytes INTEGER NOT NULL, " +
                "PRIMARY KEY(uploadId))",
        )
    }
}

val MIGRATION_2_3 = object : Migration(2, 3) {
    override fun migrate(database: SupportSQLiteDatabase) {
        database.execSQL(
            "CREATE TABLE IF NOT EXISTS sync_cursors (" +
                "instanceId TEXT NOT NULL, " +
                "opaqueProfileId TEXT NOT NULL, " +
                "cursor INTEGER NOT NULL, " +
                "updatedAtEpochMillis INTEGER NOT NULL, " +
                "PRIMARY KEY(instanceId, opaqueProfileId))",
        )
        database.execSQL(
            "CREATE TABLE IF NOT EXISTS sync_events (" +
                "instanceId TEXT NOT NULL, " +
                "opaqueProfileId TEXT NOT NULL, " +
                "cursor INTEGER NOT NULL, " +
                "eventId TEXT NOT NULL, " +
                "eventType TEXT NOT NULL, " +
                "payloadCiphertext BLOB NOT NULL, " +
                "createdAtEpochMillis INTEGER NOT NULL, " +
                "PRIMARY KEY(instanceId, opaqueProfileId, cursor, eventId))",
        )
        database.execSQL(
            "CREATE TABLE IF NOT EXISTS upload_sessions (" +
                "uploadId TEXT NOT NULL, " +
                "instanceId TEXT NOT NULL, " +
                "opaqueProfileId TEXT NOT NULL, " +
                "conversationId TEXT NOT NULL, " +
                "stagedUploadId TEXT NOT NULL, " +
                "declarationBodyCiphertext BLOB NOT NULL, " +
                "declarationIdempotencyKey TEXT NOT NULL, " +
                "completionIdempotencyKey TEXT NOT NULL, " +
                "serverUploadId TEXT, " +
                "chunkBytes INTEGER NOT NULL, " +
                "nextByte INTEGER NOT NULL, " +
                "totalBytes INTEGER NOT NULL, " +
                "status TEXT NOT NULL, " +
                "updatedAtEpochMillis INTEGER NOT NULL, " +
                "PRIMARY KEY(uploadId))",
        )
        database.execSQL(
            "CREATE TABLE IF NOT EXISTS fcm_registrations (" +
                "registrationId TEXT NOT NULL, " +
                "tokenCiphertext BLOB NOT NULL, " +
                "updatedAtEpochMillis INTEGER NOT NULL, " +
                "PRIMARY KEY(registrationId))",
        )
    }
}

val MIGRATION_3_4 = object : Migration(3, 4) {
    override fun migrate(database: SupportSQLiteDatabase) {
        database.execSQL(
            "CREATE TABLE IF NOT EXISTS approval_mutations (" +
                "approvalId TEXT NOT NULL, " +
                "action TEXT NOT NULL, " +
                "idempotencyKey TEXT NOT NULL, " +
                "proofCiphertext BLOB NOT NULL, " +
                "createdAtEpochMillis INTEGER NOT NULL, " +
                "PRIMARY KEY(approvalId, action))",
        )
    }
}

val MIGRATION_4_5 = object : Migration(4, 5) {
    override fun migrate(database: SupportSQLiteDatabase) {
        database.execSQL(
            "CREATE TABLE IF NOT EXISTS group_caches (" +
                "instanceId TEXT NOT NULL, " +
                "groupId TEXT NOT NULL, " +
                "anchorProfileId TEXT NOT NULL, " +
                "updatedAtEpochMillis INTEGER NOT NULL, " +
                "PRIMARY KEY(instanceId, groupId))",
        )
    }
}

/**
 * Adds the durable presentation and mutation metadata needed by the first mobile feature sprint.
 * Existing ciphertext is untouched; new columns default to conservative terminal/empty values.
 */
val MIGRATION_5_6 = object : Migration(5, 6) {
    override fun migrate(database: SupportSQLiteDatabase) {
        database.execSQL(
            "ALTER TABLE conversations ADD COLUMN canonical INTEGER NOT NULL DEFAULT 0",
        )
        database.execSQL(
            "ALTER TABLE runs ADD COLUMN cancelRequested INTEGER NOT NULL DEFAULT 0",
        )
        database.execSQL(
            "ALTER TABLE runs ADD COLUMN completedExternalSideEffectsNotUndone INTEGER NOT NULL DEFAULT 0",
        )
        database.execSQL(
            "ALTER TABLE sync_events ADD COLUMN aggregateType TEXT NOT NULL DEFAULT ''",
        )
        database.execSQL(
            "ALTER TABLE sync_events ADD COLUMN aggregateId TEXT NOT NULL DEFAULT ''",
        )
        database.execSQL(
            "ALTER TABLE sync_events ADD COLUMN tombstone INTEGER NOT NULL DEFAULT 0",
        )
        database.execSQL(
            "CREATE TABLE IF NOT EXISTS selected_conversations (" +
                "instanceId TEXT NOT NULL, " +
                "opaqueProfileId TEXT NOT NULL, " +
                "conversationId TEXT NOT NULL, " +
                "updatedAtEpochMillis INTEGER NOT NULL, " +
                "PRIMARY KEY(instanceId, opaqueProfileId))",
        )
        database.execSQL(
            "CREATE TABLE IF NOT EXISTS mobile_operations (" +
                "instanceId TEXT NOT NULL, " +
                "opaqueProfileId TEXT NOT NULL, " +
                "operationId TEXT NOT NULL, " +
                "kind TEXT NOT NULL, " +
                "conversationId TEXT NOT NULL, " +
                "resourceId TEXT, " +
                "idempotencyScope TEXT NOT NULL, " +
                "idempotencyKey TEXT NOT NULL, " +
                "originalEtagCiphertext BLOB, " +
                "state TEXT NOT NULL, " +
                "runId TEXT, " +
                "cancelRequested INTEGER NOT NULL, " +
                "completedExternalSideEffectsNotUndone INTEGER NOT NULL, " +
                "createdAtEpochMillis INTEGER NOT NULL, " +
                "updatedAtEpochMillis INTEGER NOT NULL, " +
                "PRIMARY KEY(instanceId, opaqueProfileId, operationId))",
        )
        database.execSQL(
            "CREATE INDEX IF NOT EXISTS index_mobile_operations_target_conversation_kind " +
                "ON mobile_operations(instanceId, opaqueProfileId, conversationId, kind)",
        )
        database.execSQL(
            "CREATE INDEX IF NOT EXISTS index_mobile_operations_target_state " +
                "ON mobile_operations(instanceId, opaqueProfileId, state)",
        )
    }
}
