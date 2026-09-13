package com.hermes.mobile.data

import android.content.Context
import android.net.Uri
import com.hermes.mobile.security.EncryptedValue
import com.hermes.mobile.security.EncryptedValueStore
import java.io.File
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.UUID
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable
private data class StagedAttachmentMetadata(
    val originalFileName: String,
    val mimeType: String,
    val sha256: String,
)

data class StagedAttachment(
    val uploadId: String,
    val file: File,
    val originalFileName: String,
    val mimeType: String,
    val sha256: String,
    val plaintextBytes: Long,
    val createdAtEpochMillis: Long,
)

/**
 * Copies a user-selected URI directly into app-private AES-GCM storage. The temporary and final
 * files contain only ciphertext; metadata is encrypted in Room so a process death can resume or
 * clean up the staged upload without retaining a provider URI or server path.
 */
class EncryptedAttachmentStager @Inject constructor(
    @androidx.hilt.android.qualifiers.ApplicationContext private val context: Context,
    private val dao: HermesDao,
    private val crypto: EncryptedValueStore,
) {
    private val root: File
        get() = File(context.filesDir, STAGING_DIRECTORY)

    suspend fun stageFromUri(
        uri: Uri,
        originalFileName: String,
        mimeType: String,
        createdAtEpochMillis: Long,
    ): StagedAttachment = withContext(Dispatchers.IO) {
        val input = context.contentResolver.openInputStream(uri)
            ?: error("selected content could not be opened")
        try {
            stageFromInput(input, originalFileName, mimeType, createdAtEpochMillis)
        } finally {
            input.close()
        }
    }

    private suspend fun stageFromInput(
        input: InputStream,
        originalFileName: String,
        mimeType: String,
        createdAtEpochMillis: Long,
    ): StagedAttachment {
        require(createdAtEpochMillis >= 0)
        require(createdAtEpochMillis <= Long.MAX_VALUE - STAGED_RETENTION_MILLIS)
        val uploadId = UUID.randomUUID().toString()
        val safeOriginalName = sanitizeFileName(originalFileName)
        val safeMimeType = sanitizeMimeType(mimeType)
        val directory = ensureRoot()
        val finalFile = safePath(directory, "$uploadId.bin")
        val temporaryFile = safePath(directory, "$uploadId.tmp")
        val aad = "staged:$uploadId".toByteArray(StandardCharsets.UTF_8)

        try {
            val result = temporaryFile.outputStream().use { output ->
                crypto.encryptStream(
                    input = input,
                    output = output,
                    associatedData = aad,
                    maxPlaintextBytes = MAX_PLAINTEXT_BYTES,
                )
            }

            moveIntoPlace(temporaryFile, finalFile)
            val metadata = StagedAttachmentMetadata(
                originalFileName = safeOriginalName,
                mimeType = safeMimeType,
                sha256 = result.sha256.toHexString(),
            )
            val metadataCiphertext = crypto.encrypt(
                Json.encodeToString(metadata).toByteArray(StandardCharsets.UTF_8),
                aad,
            ).toByteArray()
            dao.saveStagedAttachment(
                StagedAttachmentEntity(
                    uploadId = uploadId,
                    metadataCiphertext = metadataCiphertext,
                    createdAtEpochMillis = createdAtEpochMillis,
                    expiresAtEpochMillis = createdAtEpochMillis + STAGED_RETENTION_MILLIS,
                    plaintextBytes = result.plaintextBytes,
                ),
            )
            StagedAttachment(
                uploadId = uploadId,
                file = finalFile,
                originalFileName = metadata.originalFileName,
                mimeType = metadata.mimeType,
                sha256 = metadata.sha256,
                plaintextBytes = result.plaintextBytes,
                createdAtEpochMillis = createdAtEpochMillis,
            )
        } catch (error: Throwable) {
            temporaryFile.delete()
            finalFile.delete()
            throw error
        }
    }

    /** Stage a recorder output without exposing an app-private file URI to another app. */
    suspend fun stageFromFile(
        file: File,
        originalFileName: String,
        mimeType: String,
        createdAtEpochMillis: Long,
    ): StagedAttachment {
        val canonical = file.canonicalFile
        val cacheRoot = context.cacheDir.canonicalFile
        val filesRoot = context.filesDir.canonicalFile
        require(
            canonical.path == cacheRoot.path || canonical.path.startsWith(cacheRoot.path + File.separator) ||
                canonical.path == filesRoot.path || canonical.path.startsWith(filesRoot.path + File.separator),
        ) { "voice note source must remain app-private" }
        require(canonical.isFile) { "voice note source is missing" }
        return withContext(Dispatchers.IO) {
            val input = canonical.inputStream()
            try {
                stageFromInput(input, originalFileName, mimeType, createdAtEpochMillis)
            } finally {
                input.close()
            }
        }
    }

    suspend fun load(uploadId: String): StagedAttachment? = withContext(Dispatchers.IO) {
        requireValidUploadId(uploadId)
        val row = dao.findStagedAttachment(uploadId) ?: return@withContext null
        require(row.plaintextBytes in 0..MAX_PLAINTEXT_BYTES) {
            "staged attachment size is invalid"
        }
        val file = safePath(ensureRoot(), "$uploadId.bin")
        val path = file.toPath()
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            dao.deleteStagedAttachment(uploadId)
            return@withContext null
        }
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            "staged attachment path is not a regular file"
        }
        val aad = "staged:$uploadId".toByteArray(StandardCharsets.UTF_8)
        val metadata = Json.decodeFromString<StagedAttachmentMetadata>(
            String(
                crypto.decrypt(EncryptedValue.fromByteArray(row.metadataCiphertext), aad),
                StandardCharsets.UTF_8,
            ),
        )
        StagedAttachment(
            uploadId = uploadId,
            file = file,
            originalFileName = metadata.originalFileName,
            mimeType = metadata.mimeType,
            sha256 = metadata.sha256,
            plaintextBytes = row.plaintextBytes,
            createdAtEpochMillis = row.createdAtEpochMillis,
        )
    }

    /** Delete only a derived staged file and its metadata after upload completion/cancellation. */
    suspend fun delete(uploadId: String) = withContext(Dispatchers.IO) {
        requireValidUploadId(uploadId)
        val file = safePath(ensureRoot(), "$uploadId.bin")
        file.delete()
        dao.deleteStagedAttachment(uploadId)
    }

    /**
     * Streams one staged file as plaintext without materializing the attachment in memory.
     *
     * AES-GCM authenticates the file only when the decrypting stream reaches EOF. Verify a full
     * pass, including the authenticated tag and recorded size/hash, before handing any plaintext
     * to the network upload callback. The second pass keeps plaintext out of durable storage.
     */
    suspend fun <T> usePlaintext(
        uploadId: String,
        block: suspend (StagedAttachment, InputStream) -> T,
    ): T = withContext(Dispatchers.IO) {
        val attachment = load(uploadId) ?: error("staged attachment is missing")
        val aad = "staged:$uploadId".toByteArray(StandardCharsets.UTF_8)
        verifyPlaintext(attachment, aad)
        val encryptedInput = attachment.file.inputStream()
        val plaintextInput = try {
            crypto.openDecryptingStream(encryptedInput, aad)
        } catch (error: Throwable) {
            encryptedInput.close()
            throw error
        }
        try {
            block(attachment, plaintextInput)
        } finally {
            plaintextInput.close()
        }
    }

    private fun verifyPlaintext(attachment: StagedAttachment, aad: ByteArray) {
        val encryptedInput = attachment.file.inputStream()
        val plaintextInput = try {
            crypto.openDecryptingStream(encryptedInput, aad)
        } catch (error: Throwable) {
            encryptedInput.close()
            throw error
        }
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(VERIFY_BUFFER_BYTES)
            var bytesRead = 0L
            while (true) {
                val count = plaintextInput.read(buffer)
                if (count == -1) break
                require(count > 0) { "staged attachment returned an invalid read" }
                bytesRead += count
                require(bytesRead <= attachment.plaintextBytes) {
                    "staged attachment is larger than its authenticated metadata"
                }
                digest.update(buffer, 0, count)
            }
            require(bytesRead == attachment.plaintextBytes) {
                "staged attachment size does not match its authenticated metadata"
            }
            require(digest.digest().toHexString().equals(attachment.sha256, ignoreCase = true)) {
                "staged attachment hash does not match its authenticated metadata"
            }
        } finally {
            plaintextInput.close()
        }
    }

    /** Removes expired rows and orphaned temp/final files after process death. */
    suspend fun cleanup(nowEpochMillis: Long): Int = withContext(Dispatchers.IO) {
        require(nowEpochMillis >= 0)
        val directory = ensureRoot()
        val expired = dao.findExpiredStagedAttachments(nowEpochMillis)
        for (row in expired) {
            if (row.uploadId.matches(UPLOAD_ID)) {
                safePath(directory, "${row.uploadId}.bin").delete()
            }
            dao.deleteStagedAttachment(row.uploadId)
        }

        val knownIds = dao.listStagedAttachmentIds().toHashSet()
        val orphanCutoff = nowEpochMillis - ORPHAN_RETENTION_MILLIS
        directory.listFiles()?.forEach { file ->
            val name = file.name
            val uploadId = name.removeSuffix(".bin").removeSuffix(".tmp")
            if ((name.endsWith(".bin") || name.endsWith(".tmp")) &&
                uploadId.matches(UPLOAD_ID) &&
                uploadId !in knownIds && file.lastModified() <= orphanCutoff
            ) {
                safePath(directory, name).delete()
            }
        }
        expired.size
    }

    private fun ensureRoot(): File {
        val directory = root
        if (!directory.exists()) require(directory.mkdirs()) { "cannot create staging directory" }
        require(directory.isDirectory)
        val canonical = directory.canonicalFile
        require(canonical.name == STAGING_DIRECTORY && canonical.parentFile == context.filesDir.canonicalFile) {
            "staging directory escaped app-private files"
        }
        return directory
    }

    private fun safePath(directory: File, name: String): File {
        require(name.matches(Regex("^[A-Za-z0-9-]+\\.(bin|tmp)$")))
        val file = File(directory, name)
        require(file.parentFile?.canonicalFile == directory.canonicalFile)
        return file
    }

    private fun moveIntoPlace(from: File, to: File) {
        try {
            Files.move(
                from.toPath(),
                to.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(from.toPath(), to.toPath(), StandardCopyOption.REPLACE_EXISTING)
        }
    }

    private fun sanitizeFileName(raw: String): String {
        val leaf = raw.substringAfterLast('/').substringAfterLast('\\')
        val sanitized = leaf.map { char ->
            if (char.isISOControl() || char == '\u0000') '_' else char
        }.joinToString("").trim()
        return sanitized.take(MAX_FILE_NAME_LENGTH).ifBlank { "attachment" }
    }

    private fun sanitizeMimeType(raw: String): String {
        val candidate = raw.trim().take(MAX_MIME_TYPE_LENGTH)
        return if (candidate.isNotBlank() && candidate.none { it.isISOControl() }) {
            candidate
        } else {
            "application/octet-stream"
        }
    }

    private fun requireValidUploadId(uploadId: String) {
        require(uploadId.matches(UPLOAD_ID)) { "invalid staged upload ID" }
    }

    private fun ByteArray.toHexString(): String = joinToString(separator = "") { byte ->
        "%02x".format(java.util.Locale.ROOT, byte.toInt() and 0xff)
    }

    companion object {
        const val MAX_PLAINTEXT_BYTES: Long = 25_000_000
        const val STAGED_RETENTION_MILLIS: Long = 24 * 60 * 60 * 1_000
        const val ORPHAN_RETENTION_MILLIS: Long = 60 * 60 * 1_000
        private const val STAGING_DIRECTORY = "staged_uploads"
        private const val MAX_FILE_NAME_LENGTH = 255
        private const val MAX_MIME_TYPE_LENGTH = 128
        private const val VERIFY_BUFFER_BYTES = 32 * 1024
        private val UPLOAD_ID = Regex("^[A-Za-z0-9-]{36}$")
    }
}
