// HTTPProxyServer.swift
//
// Server-side accept path for one HTTP proxy request over an already-accepted
// local connection -- the HTTP counterpart to SOCKS5Core's `SOCKS5Server`, so
// Chainy's local listener can speak either protocol on the same port (see
// `LocalProxyServer`'s protocol sniff on the first byte, which picks SOCKS5
// for 0x05 and this module for anything else). Handles both shapes a real
// HTTP proxy client sends:
//
//   - `CONNECT host:port HTTP/1.1`, what browsers use to tunnel HTTPS/WSS --
//     reply 200, then the caller relays a raw byte stream exactly like a
//     SOCKS5 CONNECT tunnel, no further HTTP parsing involved.
//   - `GET http://host/path HTTP/1.1` (absolute-form, RFC 7230 5.3.2), a
//     plain HTTP request -- rewritten to origin-form and handed back as
//     `replayToOutbound` for the caller to forward before relaying continues,
//     since the request line/headers were already consumed off the client
//     socket to find the destination and can't be un-read.
//
// v1: no `Proxy-Authorization` support -- same loopback-only trust model as
// `SOCKS5Server` (see its own doc comment on why that's fine here).
//
// This file is the accept side only. See HTTPProxyClient.swift in this same
// module for the outbound (dial) side -- `HTTPProxySession`, used as a
// ChainCore hop protocol (`ProxyHopProtocol.http`) exactly like SOCKS5/
// Shadowsocks/VMess/Trojan.

import Foundation
import ProxyKit

public struct HTTPProxyIncomingRequest: Equatable, Hashable {
    public let host: String
    public let port: UInt16
    /// Bytes the caller must send to the outbound hop, verbatim, before
    /// relaying continues raw in both directions. Empty for CONNECT --
    /// nothing to replay, the tunnel starts clean once "200 Connection
    /// Established" has gone back to the client.
    public let replayToOutbound: [UInt8]

    public init(host: String, port: UInt16, replayToOutbound: [UInt8] = []) {
        self.host = host
        self.port = port
        self.replayToOutbound = replayToOutbound
    }
}

public enum HTTPProxyServerError: Error, Equatable {
    /// The request line didn't parse as "METHOD target HTTP/version".
    case malformedRequestLine
    /// A non-CONNECT request's target wasn't an absolute-form URI
    /// ("http://host/path") with a host -- this proxy only relays
    /// proxy-style requests, not origin-form ones a browser would only ever
    /// send directly to an origin server.
    case notAbsoluteFormURI
    /// The URI's scheme was something other than "http" (e.g. "https:",
    /// "ftp:") -- only plain HTTP is relayed this way; HTTPS goes through
    /// CONNECT instead.
    case unsupportedScheme(String)
    /// The request line/headers exceeded the internal size cap without a
    /// terminating blank line -- bounds a client that never sends one.
    case headersTooLarge
}

public typealias HTTPProxyTransport = ByteStreamSource & ByteStreamSink

public enum HTTPProxyServer {
    /// Caps total bytes read for the request line + headers combined --
    /// plenty for any real client, and bounds one that never sends a
    /// terminating blank line.
    static let maxHeaderBytes = 16 * 1024

    /// Reads one HTTP proxy request off `transport` (request line + headers,
    /// stopping at the blank line -- never touches any request body, which
    /// is left on the wire for the caller's raw relay to pick up). For
    /// CONNECT, also sends the "200 Connection Established" reply here,
    /// mirroring `SOCKS5Server.acceptConnect` replying to the CONNECT request
    /// itself before returning.
    public static func acceptConnect(over transport: any HTTPProxyTransport, timeout: TimeInterval? = 10) async throws -> HTTPProxyIncomingRequest {
        let requestLine = try await readLine(transport, timeout: timeout)
        let parts = requestLine.split(separator: " ", omittingEmptySubsequences: true)
        guard parts.count >= 2 else { throw HTTPProxyServerError.malformedRequestLine }
        let method = String(parts[0])
        let target = String(parts[1])

        var headerLines: [String] = []
        while true {
            let line = try await readLine(transport, timeout: timeout)
            if line.isEmpty { break }
            headerLines.append(line)
        }

        if method.caseInsensitiveCompare("CONNECT") == .orderedSame {
            let (host, port) = parseHostPort(target, defaultPort: 443)
            try await transport.send(Array("HTTP/1.1 200 Connection Established\r\n\r\n".utf8), timeout: timeout)
            return HTTPProxyIncomingRequest(host: host, port: port)
        }

        guard let url = URL(string: target), let scheme = url.scheme, let host = url.host else {
            throw HTTPProxyServerError.notAbsoluteFormURI
        }
        guard scheme.caseInsensitiveCompare("http") == .orderedSame else {
            throw HTTPProxyServerError.unsupportedScheme(scheme)
        }
        let port: UInt16
        if let urlPort = url.port {
            guard let exact = UInt16(exactly: urlPort) else { throw HTTPProxyServerError.malformedRequestLine }
            port = exact
        } else {
            port = 80
        }

        var originForm = url.path.isEmpty ? "/" : url.path
        if let query = url.query { originForm += "?\(query)" }

        // Hop-by-hop, proxy-addressed headers that make no sense once this
        // request is replayed straight to the origin -- everything else
        // (Host, User-Agent, cookies, etc.) is forwarded unchanged.
        let filteredHeaders = headerLines.filter {
            !$0.lowercased().hasPrefix("proxy-connection:") && !$0.lowercased().hasPrefix("proxy-authorization:")
        }
        var headBytes = Array("\(method) \(originForm) HTTP/1.1\r\n".utf8)
        for header in filteredHeaders { headBytes += Array("\(header)\r\n".utf8) }
        headBytes += Array("\r\n".utf8)

        return HTTPProxyIncomingRequest(host: host, port: port, replayToOutbound: headBytes)
    }

    /// Reads up to and including the next CRLF, returning the line without
    /// the terminator. Byte-at-a-time is deliberate, same as SOCKS5Core's own
    /// small fixed-size reads: a real client's whole request typically
    /// arrives in one TCP segment, already sitting in `TCPConn`'s internal
    /// buffer, so this costs no extra round trips in practice -- it's simply
    /// the only way to find a variable-length, self-delimited line through
    /// `ByteStreamSource`'s exact-length-only read interface.
    private static func readLine(_ transport: any HTTPProxyTransport, timeout: TimeInterval?) async throws -> String {
        var bytes: [UInt8] = []
        while true {
            let next = try await transport.readExactly(1, timeout: timeout)
            if next[0] == 0x0A, bytes.last == 0x0D {
                bytes.removeLast()
                break
            }
            bytes.append(next[0])
            if bytes.count > maxHeaderBytes { throw HTTPProxyServerError.headersTooLarge }
        }
        return String(decoding: bytes, as: UTF8.self)
    }
}
