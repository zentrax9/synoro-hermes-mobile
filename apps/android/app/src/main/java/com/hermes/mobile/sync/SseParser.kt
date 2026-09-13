package com.hermes.mobile.sync

data class SseFrame(
    val id: String?,
    val event: String?,
    val data: String,
)

/** Small bounded SSE parser for semantic event streams; comments and retry hints are ignored. */
class SseParser {
    private var id: String? = null
    private var event: String? = null
    private val data = StringBuilder()

    fun feed(line: String): SseFrame? {
        require(line.length <= MAX_LINE_BYTES) { "SSE line is too long" }
        if (line.isEmpty()) return flush()
        if (line.startsWith(':')) return null
        val separator = line.indexOf(':')
        val field = if (separator == -1) line else line.substring(0, separator)
        val value = if (separator == -1) "" else line.substring(separator + 1).removePrefix(" ")
        when (field) {
            "id" -> {
                require(value.length <= MAX_ID_BYTES && value.none { it.isISOControl() })
                id = value
            }
            "event" -> {
                require(value.length <= MAX_EVENT_BYTES && value.isNotBlank())
                event = value
            }
            "data" -> {
                require(data.length + value.length + 1 <= MAX_DATA_BYTES)
                if (data.isNotEmpty()) data.append('\n')
                data.append(value)
            }
            "retry" -> Unit
            else -> Unit
        }
        return null
    }

    fun finish(): SseFrame? = flush()

    private fun flush(): SseFrame? {
        if (id == null && event == null && data.isEmpty()) return null
        val frame = SseFrame(id = id, event = event, data = data.toString())
        id = null
        event = null
        data.clear()
        return frame
    }

    companion object {
        private const val MAX_LINE_BYTES = 8_192
        private const val MAX_ID_BYTES = 256
        private const val MAX_EVENT_BYTES = 128
        private const val MAX_DATA_BYTES = 1_048_576
    }
}
