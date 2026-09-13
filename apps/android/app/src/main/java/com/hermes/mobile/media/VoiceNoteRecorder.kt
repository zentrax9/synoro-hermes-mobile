package com.hermes.mobile.media

import android.media.MediaRecorder
import java.io.Closeable
import java.io.File

data class VoiceNoteCapture(
    val file: File,
    val durationMillis: Long,
    val mimeType: String = "audio/mp4",
) {
    init {
        require(file.isFile) { "voice note output is missing" }
        require(durationMillis in 1..MAX_DURATION_MILLIS) {
            "voice note duration is outside the ten-minute limit"
        }
    }

    companion object {
        const val MAX_DURATION_MILLIS = 10 * 60 * 1_000L
    }
}

/**
 * Records AAC-LC/M4A only while the owning chat screen is visible.
 *
 * This class deliberately does not request RECORD_AUDIO.  The UI must request that runtime
 * permission from the explicit microphone-tap action, then create/start the recorder.  The
 * resulting file is app-private and should be handed to EncryptedAttachmentStager before upload.
 */
class VoiceNoteRecorder(
    private val appFilesDirectory: File,
    private val clockMillis: () -> Long = { System.currentTimeMillis() },
) : Closeable {
    private var recorder: MediaRecorder? = null
    private var output: File? = null
    private var startedAtMillis: Long? = null

    @Synchronized
    fun start(): File {
        check(recorder == null) { "voice note recording is already active" }
        val root = File(appFilesDirectory, "voice_notes").apply {
            require(exists() || mkdirs()) { "voice note directory could not be created" }
            require(isDirectory) { "voice note directory is invalid" }
        }
        val staleBefore = clockMillis().coerceAtLeast(0) - STALE_FILE_RETENTION_MILLIS
        root.listFiles()?.forEach { candidate ->
            if (candidate.isFile && candidate.extension == "m4a" && candidate.lastModified() <= staleBefore) {
                candidate.delete()
            }
        }
        val file = File.createTempFile("voice-", ".m4a", root)
        val active = MediaRecorder()
        try {
            active.setAudioSource(MediaRecorder.AudioSource.MIC)
            active.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
            active.setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
            active.setAudioEncodingBitRate(128_000)
            active.setAudioSamplingRate(44_100)
            active.setMaxDuration(VoiceNoteCapture.MAX_DURATION_MILLIS.toInt())
            active.setOutputFile(file.absolutePath)
            active.prepare()
            active.start()
        } catch (error: Throwable) {
            active.release()
            file.delete()
            throw error
        }
        recorder = active
        output = file
        startedAtMillis = clockMillis().coerceAtLeast(0)
        return file
    }

    @Synchronized
    fun stop(): VoiceNoteCapture {
        val active = recorder ?: error("voice note recording is not active")
        val file = output ?: error("voice note output is missing")
        val started = startedAtMillis ?: error("voice note start time is missing")
        try {
            active.stop()
        } catch (error: Throwable) {
            file.delete()
            throw IllegalStateException("voice note could not be finalized", error)
        } finally {
            active.reset()
            active.release()
            recorder = null
            output = null
            startedAtMillis = null
        }
        val duration = (clockMillis().coerceAtLeast(started) - started)
            .coerceIn(1L, VoiceNoteCapture.MAX_DURATION_MILLIS)
        return VoiceNoteCapture(file=file, durationMillis=duration)
    }

    @Synchronized
    fun discard() {
        val active = recorder
        val file = output
        if (active != null) {
            runCatching { active.stop() }
            active.reset()
            active.release()
        }
        recorder = null
        file?.delete()
        output = null
        startedAtMillis = null
    }

    override fun close() = discard()

    private companion object {
        const val STALE_FILE_RETENTION_MILLIS = 60 * 60 * 1_000L
    }
}
