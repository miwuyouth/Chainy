// HTTPProxyClient.swift
//
// Client (outbound) side of the HTTP CONNECT proxy protocol -- the
// counterpart to HTTPProxyServer.swift's accept side, letting Chainy treat
// a plain HTTP proxy as just another ChainCore hop protocol alongside
// SOCKS5/Shadowsocks/VMess/Trojan (see ChainCore's `ProxyHopProtocol.http`).
//
// Only CONNECT is sent (asking the proxy to relay raw TCP toward
// `targetHost:targetPort`, exactly like every other protocol's Session
// here) -- this client never sends an absolute-form "GET http://..." plain
// request itself, since ChainCore's chaining model always wants a raw byte
// tunnel to hand off to the next hop or the terminal caller, not an
// HTTP-specific response. Once the server replies with a 2xx status, the
// tunnel is a plain byte pipe.
//
// Auth: optional HTTP Basic (RFC 7617) via "Proxy-Authorization" -- the
// overwhelmingly common case for real-world HTTP proxies (Squid,
// tinyproxy, corporate proxies); no Digest/NTLM.

import Foundation
import ProxyKit

// MARK: - Configuration

public enum HTTPProxyAuth: Equatable {
    case none
    case usernamePassword(username: String, password: String)
}

public struct HTTPProxyServerConfig {
    public let host: String
    public let port: UInt16
    public let auth: HTTPProxyAuth

    public init(host: String, port: UInt16, auth: HTTPProxyAuth = .none) {
        self.host = host
        self.port = port
        self.auth = auth
    }
}

// MARK: - Errors

public enum HTTPProxyClientError: Error, Equatable {
    /// The response's first line didn't parse as "HTTP/version status reason".
    case malformedStatusLine
    /// The CONNECT request's status code wasn't 2xx.
    case requestFailed(statusCode: Int, statusLine: String)
    /// The status line/headers exceeded the internal size cap without a
    /// terminating blank line -- bounds a server that never sends one.
    case headersTooLarge
}

// MARK: - Transport

public typealias HTTPProxyClientTransport = ByteStreamSource & ByteStreamSink

// MARK: - Reusable HTTP CONNECT session
//
// Encapsulates one HTTP-CONNECT-proxied connection: send the CONNECT
// request (with an optional Proxy-Authorization header), read and validate
// the status line + headers, then expose a plain send/receive byte pipe --
// callers don't need to know anything about the handshake to relay their
// own application data.
//
// `HTTPProxySession` conforms to `ProxyTransport` itself, so it can serve
// as the transport for a *further* hop's handshake, the same way every
// other protocol's `Session` here does.

public final class HTTPProxySession: ByteStreamSource, ByteStreamSink, ByteStreamAvailableReader, ByteStreamCloser {
    private let conn: any ProxyTransport
    private var buffered: [UInt8] = []

    private init(conn: any ProxyTransport) { self.conn = conn }

    /// Sends a CONNECT request for `targetHost:targetPort` over an
    /// already-open `transport` and validates the reply. This is the
    /// primitive `open(server:)` below reduces to -- `transport` is a fresh
    /// `TCPConn` when HTTP is the first hop of a chain, or a previous hop's
    /// already-open `Session` when it's stacked on top of it.
    public static func open(over transport: any ProxyTransport, auth: HTTPProxyAuth = .none, targetHost: String, targetPort: UInt16, timeout: TimeInterval? = 10) async throws -> HTTPProxySession {
        let target = requestTarget(host: targetHost, port: targetPort)
        var head = "CONNECT \(target) HTTP/1.1\r\nHost: \(target)\r\n"
        if case .usernamePassword(let username, let password) = auth {
            let credentials = Data("\(username):\(password)".utf8).base64EncodedString()
            head += "Proxy-Authorization: Basic \(credentials)\r\n"
        }
        head += "\r\n"
        try await transport.send(Array(head.utf8), timeout: timeout)

        try await readStatusLineAndDiscardHeaders(transport: transport, timeout: timeout)
        return HTTPProxySession(conn: transport)
    }

    /// Dials `server` directly over TCP, then sends the CONNECT request.
    /// `connectTimeout` guards both the TCP handshake and the CONNECT
    /// round trip against a firewalled/unresponsive server (mirrors every
    /// other protocol's `open(server:)` here).
    public static func open(server: HTTPProxyServerConfig, targetHost: String, targetPort: UInt16, connectTimeout: TimeInterval? = 10) async throws -> HTTPProxySession {
        let conn = TCPConn(host: server.host, port: server.port)
        try await conn.connect(timeout: connectTimeout)
        do {
            return try await open(over: conn, auth: server.auth, targetHost: targetHost, targetPort: targetPort, timeout: connectTimeout)
        } catch {
            // `conn` already connected above -- without this, a failure in
            // `open(over:)`'s own handshake would leak that socket, since
            // nothing else still references `conn` once this rethrows.
            conn.close()
            throw error
        }
    }

    /// "host:port" for the request line and Host header -- an IPv6 literal
    /// needs bracketing (RFC 7230 5.4) or it's indistinguishable from its
    /// own port separator; a domain or IPv4 literal is used verbatim.
    private static func requestTarget(host: String, port: UInt16) -> String {
        if case .ipv6 = ProxyAddress.parse(host) {
            return "[\(host)]:\(port)"
        }
        return "\(host):\(port)"
    }

    /// Reads the status line, confirms it's 2xx, then reads and discards
    /// headers up to the blank line -- this client has no use for any of
    /// them (no chunked/length-prefixed body to worry about: a successful
    /// CONNECT reply carries no body at all, just the tunnel that follows).
    private static func readStatusLineAndDiscardHeaders(transport: any HTTPProxyClientTransport, timeout: TimeInterval?) async throws {
        let statusLine = try await readLine(transport, timeout: timeout)
        let parts = statusLine.split(separator: " ", omittingEmptySubsequences: true)
        guard parts.count >= 2, parts[0].hasPrefix("HTTP/"), let statusCode = Int(parts[1]) else {
            throw HTTPProxyClientError.malformedStatusLine
        }
        guard (200...299).contains(statusCode) else {
            throw HTTPProxyClientError.requestFailed(statusCode: statusCode, statusLine: statusLine)
        }

        while true {
            let line = try await readLine(transport, timeout: timeout)
            if line.isEmpty { break }
        }
    }

    /// Reads up to and including the next CRLF, returning the line without
    /// the terminator -- same byte-at-a-time approach as
    /// `HTTPProxyServer.readLine`, the accept-side counterpart of this
    /// exact framing problem.
    private static func readLine(_ transport: any HTTPProxyClientTransport, timeout: TimeInterval?) async throws -> String {
        var bytes: [UInt8] = []
        while true {
            let next = try await transport.readExactly(1, timeout: timeout)
            if next[0] == 0x0A, bytes.last == 0x0D {
                bytes.removeLast()
                break
            }
            bytes.append(next[0])
            if bytes.count > HTTPProxyServer.maxHeaderBytes { throw HTTPProxyClientError.headersTooLarge }
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// Sends raw application bytes toward `target` (no per-connection framing -- an HTTP CONNECT tunnel relays a plain byte stream once the 2xx reply arrives).
    public func send(_ bytes: [UInt8], timeout: TimeInterval? = nil) async throws {
        try await conn.send(bytes, timeout: timeout)
    }

    /// Reads raw application bytes coming back from `target` ([] once the stream ends).
    public func receive(timeout: TimeInterval? = nil) async throws -> [UInt8] {
        try await readAvailable(timeout: timeout)
    }

    public func readAvailable(timeout: TimeInterval? = nil) async throws -> [UInt8] {
        if !buffered.isEmpty {
            let result = buffered
            buffered = []
            return result
        }
        return try await conn.readAvailable(timeout: timeout)
    }

    /// Exact-length read for a protocol stacked *on top of* this HTTP hop:
    /// buffers across as many underlying `readAvailable` calls as needed,
    /// the same pattern `SOCKS5Session`/`TCPConn` use.
    public func readExactly(_ n: Int, timeout: TimeInterval? = nil) async throws -> [UInt8] {
        while buffered.count < n {
            let chunk = try await conn.readAvailable(timeout: timeout)
            if chunk.isEmpty { throw ProxyError.connectionClosed }
            buffered += chunk
        }
        let result = Array(buffered.prefix(n))
        buffered.removeFirst(n)
        return result
    }

    public func close() { conn.close() }
}
