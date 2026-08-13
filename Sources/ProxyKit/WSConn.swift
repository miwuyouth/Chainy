// WSConn.swift
//
// A minimal RFC 6455 WebSocket client that runs over *any* `ProxyTransport`
// -- a fresh `TCPConn` exactly as easily as a `TLSConn` already wrapped
// around one -- the same "layer over whatever's already open" shape
// `TLSConn` itself uses. This is what lets VMess/VLESS/Trojan speak "ws" and
// "ws+tls" transport (the single most common way real-world nodes disguise
// themselves as ordinary HTTPS traffic behind a CDN), by slotting in one
// layer further out than TLS: dial -> TLS (if any) -> **WS (if any)** ->
// the protocol's own handshake.
//
// Deliberately narrow, matching every other Core module's own scope here:
// only what a proxy tunnel actually needs (an HTTP/1.1 upgrade handshake,
// then binary data frames relayed as one opaque byte pipe), not a general
// WebSocket library. Ping is answered with Pong (some servers expect
// liveness replies on a long-idle tunnel); Close is treated as clean EOF;
// text frames are accepted as data (a `ProxyTransport` doesn't distinguish
// "text" from "binary", it's all just bytes to relay onward); continuation
// frames aren't split by any server this client's own protocols talk to, so
// aren't specially handled -- an unfragmented single data frame per message
// is what v2ray-core/Xray-core's own ws transport emits.

import Foundation

public enum WSError: Error, Equatable {
    /// The server didn't respond with `101 Switching Protocols`, or its
    /// `Sec-WebSocket-Accept` didn't match what RFC 6455 says it must
    /// derive from this client's own `Sec-WebSocket-Key` -- not skipped or
    /// assumed, since a mismatch there means this isn't really talking to a
    /// WebSocket server (or is talking to the wrong one, e.g. a
    /// misconfigured CDN front).
    case handshakeFailed(String)
    /// A frame's payload length or opcode was outside what this client
    /// (relaying one client's own proxy traffic) ever expects.
    case malformedFrame
}

public final class WSConn: ByteStreamSource, ByteStreamSink, ByteStreamAvailableReader, ByteStreamCloser {
    private let underlying: any ProxyTransport
    /// Raw (still WS-framed) bytes already read from `underlying` but not
    /// yet consumed by the frame parser -- same "leftover" buffering every
    /// other `Session`/`Conn` in this codebase uses, one level below here
    /// (`rawBuffered`) since this class also needs to buffer *decoded*
    /// payload bytes (`plainBuffered`) for `readExactly`.
    private var rawBuffered: [UInt8] = []
    private var plainBuffered: [UInt8] = []

    private init(underlying: any ProxyTransport) {
        self.underlying = underlying
    }

    // MARK: - Handshake

    /// Sends the HTTP/1.1 `Upgrade: websocket` request and validates the
    /// server's `101` response (including `Sec-WebSocket-Accept`) before
    /// this connection is usable. `host` is the `Host:` header value (a
    /// node's own `wsHost` override, or its server address) -- separate from
    /// whatever hostname/IP `underlying` actually dialed, the same
    /// front-vs-real-address distinction Trojan/VLESS's own `sni` already
    /// makes for TLS.
    public static func handshake(over underlying: any ProxyTransport, host: String, path: String, timeout: TimeInterval? = 10) async throws -> WSConn {
        let keyBytes = (0..<16).map { _ in UInt8.random(in: 0...255) }
        let key = Data(keyBytes).base64EncodedString()
        let request =
            "GET \(path) HTTP/1.1\r\n" +
            "Host: \(host)\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            "Sec-WebSocket-Key: \(key)\r\n" +
            "Sec-WebSocket-Version: 13\r\n" +
            "\r\n"
        try await underlying.send(Array(request.utf8), timeout: timeout)

        let conn = WSConn(underlying: underlying)
        let headBytes = try await conn.readRaw(until: Array("\r\n\r\n".utf8), timeout: timeout)
        let headText = String(decoding: headBytes, as: UTF8.self)
        let lines = headText.components(separatedBy: "\r\n")

        guard let statusLine = lines.first, statusLine.contains(" 101 ") else {
            throw WSError.handshakeFailed("expected 101 Switching Protocols, got: \(lines.first ?? "<empty response>")")
        }

        var acceptHeader: String?
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[line.startIndex..<colon].trimmingCharacters(in: .whitespaces)
            if name.caseInsensitiveCompare("Sec-WebSocket-Accept") == .orderedSame {
                acceptHeader = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            }
        }
        let expectedAccept = Data(sha1(Array((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").utf8))).base64EncodedString()
        guard acceptHeader == expectedAccept else {
            throw WSError.handshakeFailed("Sec-WebSocket-Accept mismatch (got \(acceptHeader ?? "<missing>"))")
        }
        return conn
    }

    // MARK: - Sending (one binary frame per call, masked per RFC 6455 4.6/5.3)

    /// Client-to-server frames MUST be masked -- a fresh random 4-byte key
    /// per frame, XORed over the payload, exactly as RFC 6455 5.3 requires
    /// (a server that doesn't reject unmasked frames outright would still
    /// misinterpret a client that skipped this, since masking isn't
    /// optional camouflage here, it's part of the wire format itself).
    public func send(_ bytes: [UInt8], timeout: TimeInterval? = nil) async throws {
        try await underlying.send(Self.encodeFrame(opcode: 0x2, payload: bytes), timeout: timeout)
    }

    static func encodeFrame(opcode: UInt8, payload: [UInt8]) -> [UInt8] {
        var frame: [UInt8] = [0x80 | opcode] // FIN=1, RSV=0
        let length = payload.count
        if length <= 125 {
            frame.append(0x80 | UInt8(length))
        } else if length <= 0xFFFF {
            frame.append(0x80 | 126)
            frame += UInt16(length).bigEndianBytes
        } else {
            frame.append(0x80 | 127)
            frame += (0..<8).reversed().map { UInt8((UInt64(length) >> ($0 * 8)) & 0xFF) }
        }
        let maskKey = (0..<4).map { _ in UInt8.random(in: 0...255) }
        frame += maskKey
        frame += payload.enumerated().map { $0.element ^ maskKey[$0.offset % 4] }
        return frame
    }

    // MARK: - Receiving

    /// Reads (and unmasks, if the -- server-to-client, so normally unmasked
    /// -- frame happens to have the mask bit set anyway) the next frame,
    /// replying to a Ping with a Pong and looping past it/an unsolicited
    /// Pong rather than surfacing either as data.
    private func readNextDataFrame(timeout: TimeInterval?) async throws -> [UInt8] {
        while true {
            let firstTwo = try await readRawExactly(2, timeout: timeout)
            let opcode = firstTwo[0] & 0x0F
            let masked = firstTwo[1] & 0x80 != 0
            var length = Int(firstTwo[1] & 0x7F)
            if length == 126 {
                let extended = try await readRawExactly(2, timeout: timeout)
                length = Int(extended[0]) << 8 | Int(extended[1])
            } else if length == 127 {
                let extended = try await readRawExactly(8, timeout: timeout)
                length = extended.reduce(0) { ($0 << 8) | Int($1) }
            }
            let maskKey = masked ? try await readRawExactly(4, timeout: timeout) : []
            let rawPayload = length > 0 ? try await readRawExactly(length, timeout: timeout) : []
            let payload = masked ? rawPayload.enumerated().map { $0.element ^ maskKey[$0.offset % 4] } : rawPayload

            switch opcode {
            case 0x1, 0x2: // text/binary data frame
                return payload
            case 0x8: // close
                return []
            case 0x9: // ping -> reply pong, then keep waiting for real data
                try await underlying.send(Self.encodeFrame(opcode: 0xA, payload: payload), timeout: timeout)
            case 0xA: // pong -- nothing to do
                break
            default:
                throw WSError.malformedFrame
            }
        }
    }

    public func readAvailable(timeout: TimeInterval? = nil) async throws -> [UInt8] {
        if !plainBuffered.isEmpty {
            let result = plainBuffered
            plainBuffered = []
            return result
        }
        return try await readNextDataFrame(timeout: timeout)
    }

    /// Exact-length read for a protocol stacked *on top of* this WS hop:
    /// buffers across as many decoded data frames as needed, same pattern
    /// every other `Session` here uses over its own `readAvailable`.
    public func readExactly(_ n: Int, timeout: TimeInterval? = nil) async throws -> [UInt8] {
        while plainBuffered.count < n {
            let chunk = try await readNextDataFrame(timeout: timeout)
            if chunk.isEmpty { throw ProxyError.connectionClosed }
            plainBuffered += chunk
        }
        let result = Array(plainBuffered.prefix(n))
        plainBuffered.removeFirst(n)
        return result
    }

    public func close() { underlying.close() }

    // MARK: - Raw byte buffering (below the frame layer)

    private func readRawExactly(_ n: Int, timeout: TimeInterval?) async throws -> [UInt8] {
        while rawBuffered.count < n {
            let chunk = try await underlying.readAvailable(timeout: timeout)
            if chunk.isEmpty { throw ProxyError.connectionClosed }
            rawBuffered += chunk
        }
        let result = Array(rawBuffered.prefix(n))
        rawBuffered.removeFirst(n)
        return result
    }

    /// Reads (and buffers) raw bytes one chunk at a time until `delimiter`
    /// has appeared, returning everything up to and including it -- only
    /// used once, for the handshake's HTTP response head (terminated by a
    /// blank line), where the length isn't known ahead of time the way a WS
    /// frame's own length field gives it for every later read.
    private func readRaw(until delimiter: [UInt8], timeout: TimeInterval?) async throws -> [UInt8] {
        while true {
            if let range = rawBuffered.firstRange(of: delimiter) {
                let result = Array(rawBuffered[..<range.upperBound])
                rawBuffered.removeFirst(range.upperBound)
                return result
            }
            let chunk = try await underlying.readAvailable(timeout: timeout)
            if chunk.isEmpty { throw ProxyError.connectionClosed }
            rawBuffered += chunk
        }
    }
}
