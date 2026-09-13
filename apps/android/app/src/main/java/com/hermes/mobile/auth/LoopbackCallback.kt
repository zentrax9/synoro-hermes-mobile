package com.hermes.mobile.auth

import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** RFC 8252 loopback listener: OS-selected port, loopback-only bind, one request, then close. */
class EphemeralLoopbackCallback private constructor(
    private val serverSocket: ServerSocket,
    private val timeoutMillis: Int,
) : Closeable {
    private val consumed = AtomicBoolean(false)

    val redirectUri: String = "http://127.0.0.1:${serverSocket.localPort}/callback"
    private val expectedHost: String = "127.0.0.1:${serverSocket.localPort}"

    init {
        require(serverSocket.inetAddress.hostAddress == "127.0.0.1") {
            "loopback callback must bind to 127.0.0.1"
        }
    }

    suspend fun await(transaction: PkceAuthTransaction, nowEpochMillis: () -> Long): AuthorizationCallbackResult =
        withContext(Dispatchers.IO) {
            check(consumed.compareAndSet(false, true)) { "loopback callback already consumed" }
            try {
                serverSocket.soTimeout = timeoutMillis
                serverSocket.accept().use { socket ->
                    socket.soTimeout = timeoutMillis
                    process(socket, transaction, nowEpochMillis)
                }
            } catch (_: SocketTimeoutException) {
                AuthorizationCallbackResult.Failure("callback_timeout")
            } catch (_: IOException) {
                AuthorizationCallbackResult.Failure("callback_io_error")
            } finally {
                close()
            }
        }

    override fun close() {
        if (!serverSocket.isClosed) serverSocket.close()
    }

    private fun process(
        socket: Socket,
        transaction: PkceAuthTransaction,
        nowEpochMillis: () -> Long,
    ): AuthorizationCallbackResult {
        return try {
            require(socket.inetAddress.hostAddress == "127.0.0.1") {
                "callback peer is not IPv4 loopback"
            }
            val requestLine = readLineBounded(socket)
            val request = requestLine.split(' ')
            require(request.size == 3 && request[0] == "GET" && request[2] == "HTTP/1.1") {
                "invalid callback request line"
            }
            val headers = readHeaders(socket)
            require(headers["host"] == expectedHost) { "callback host mismatch" }
            val callback = AuthorizationCallbackParser.parseRequestTarget(
                requestTarget = request[1],
                expectedRedirectUri = transaction.redirectUri,
            )
            val result = AuthorizationCallbackParser.validate(
                callback = callback,
                transaction = transaction,
                nowEpochMillis = nowEpochMillis(),
            )
            writeResponse(socket, status = 200, body = "You may return to Hermes Mobile.")
            result
        } catch (_: IllegalArgumentException) {
            writeResponse(socket, status = 400, body = "Invalid callback.")
            AuthorizationCallbackResult.Failure("invalid_callback")
        }
    }

    private fun readHeaders(socket: Socket): Map<String, String> {
        val headers = LinkedHashMap<String, String>()
        repeat(MAX_HEADERS) {
            val line = readLineBounded(socket, allowEmpty = true)
            if (line.isEmpty()) return headers
            val separator = line.indexOf(':')
            require(separator > 0) { "invalid callback header" }
            val name = line.substring(0, separator).lowercase()
            require(!headers.containsKey(name)) { "duplicate callback header" }
            headers[name] = line.substring(separator + 1).trim()
        }
        throw IllegalArgumentException("too many callback headers")
    }

    private fun readLineBounded(socket: Socket, allowEmpty: Boolean = false): String {
        val bytes = ByteArrayOutputStream()
        val input = socket.getInputStream()
        while (true) {
            val next = input.read()
            if (next == -1) break
            if (next == '\n'.code) break
            if (next == '\r'.code) {
                require(input.read() == '\n'.code) { "callback lines must use CRLF" }
                break
            }
            require(next in 0..0x7f && (next >= 0x20 || next == '\t'.code)) {
                "callback request must contain ASCII header-safe bytes"
            }
            bytes.write(next)
            require(bytes.size() <= MAX_LINE_BYTES) { "callback line is too long" }
        }
        require(allowEmpty || bytes.size() > 0) { "callback line is missing" }
        return String(bytes.toByteArray(), StandardCharsets.US_ASCII)
    }

    private fun writeResponse(socket: Socket, status: Int, body: String) {
        val payload = body.toByteArray(StandardCharsets.UTF_8)
        val response = buildString {
            append("HTTP/1.1 ").append(status).append(if (status == 200) " OK" else " Bad Request")
            append("\r\nContent-Type: text/plain; charset=utf-8\r\n")
            append("Content-Length: ").append(payload.size).append("\r\nConnection: close\r\n\r\n")
        }.toByteArray(StandardCharsets.US_ASCII)
        socket.getOutputStream().use { output ->
            output.write(response)
            output.write(payload)
            output.flush()
        }
    }

    companion object {
        private const val MAX_LINE_BYTES = 8_192
        private const val MAX_HEADERS = 32

        fun open(timeoutMillis: Int = 120_000): EphemeralLoopbackCallback {
            require(timeoutMillis in 1_000..300_000)
            val socket = ServerSocket(
                0,
                1,
                InetAddress.getByName("127.0.0.1"),
            )
            return try {
                EphemeralLoopbackCallback(socket, timeoutMillis)
            } catch (error: Throwable) {
                socket.close()
                throw error
            }
        }
    }
}
