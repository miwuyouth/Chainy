// TrojanCore.swift
//
// A minimal Trojan (https://trojan-gfw.github.io/trojan/protocol) TCP client,
// built on ProxyKit's shared networking/crypto/address primitives.
//
// Trojan's whole design goal is to be indistinguishable from ordinary HTTPS
// on the wire: every byte -- including the client's own credential header --
// is *meant* to travel inside a real TLS session (see ProxyKit's `TLSConn`),
// to a server that, on a failed/absent credential, is expected to fall
// through to proxying the connection as plain HTTPS to some innocuous site
// instead of responding with anything protocol-specific an observer could
// fingerprint. `TrojanServerConfig.tls` defaults to `true` to match that --
// but some real-world deployments run the trojan handshake directly over
// plain TCP regardless (`security=none` in a subscription link; confirmed
// live against one such node, which drops any real TLS ClientHello but
// accepts this exact header unencrypted), so `tls: false` is supported too.
// Consequently there's no separate handshake step or server ack the way
// SOCKS5/VMess have one: once the header below is sent, the (TLS or plain)
// session *is* the relay -- send/receive are a completely plain byte pipe.
//
// Wire format of that one header (sent as the first bytes of the TLS
// session, verified against the reference `trojan` and `trojan-go`
// implementations):
//
//   hex(SHA224(password)) + CRLF + [CMD][ATYP+DST.ADDR+DST.PORT] + CRLF
//
// CMD is 0x01 (Connect) by default; 0x03 (UDP Associate) is also
// implemented (see `TrojanCommand.udpAssociate`) for ChainCore's
// `TrojanUDPRelay` -- ATYP+address is the exact RFC 1928 encoding
// SOCKS5/Shadowsocks already share (see ProxyKit's `ProxyAddress.socks5Encoded`).
//
// UDP Associate's own request line still just carries a dummy DST.ADDR/
// DST.PORT (same convention this codebase's own SOCKS5 ASSOCIATE accept side
// already uses, see `SOCKS5Server.acceptRequest`) -- the *real* per-packet
// destinations follow afterward, each framed by `trojanUDPFrame`/
// `readTrojanUDPFrame` below. Unlike VMess/VLESS's UDP mode (one target
// baked into the one-time request header), Trojan names a destination on
// *every* frame, so one open session can relay to arbitrarily many
// different destinations -- the same "any destination per packet" shape as
// Shadowsocks/SOCKS5 ASSOCIATE, just riding a TLS stream instead of a raw
// UDP socket.

import Foundation
import ProxyKit

// MARK: - Configuration

public struct TrojanServerConfig {
    public let host: String
    public let port: UInt16
    public let password: String
    /// Wraps the connection in TLS before sending the Trojan credential
    /// header -- `true` (the spec-correct default, and every mainstream
    /// deployment) matches Trojan's whole design goal of looking like
    /// ordinary HTTPS; `false` sends the header directly over the dialed
    /// (or WS-wrapped) TCP connection instead, for the rarer real-world
    /// server that skips TLS entirely -- see this file's own header comment.
    public let tls: Bool
    /// TLS SNI / certificate hostname, if different from `host` (e.g. a
    /// front domain). Defaults to `host` when `nil`. Only meaningful when `tls` is `true`.
    public let sni: String?
    /// Skips TLS certificate validation -- for self-signed deployments.
    /// See `TLSOptions.allowInsecure`. Only meaningful when `tls` is `true`.
    public let allowInsecure: Bool
    /// Wraps the connection (after TLS, if any) in a WebSocket tunnel before
    /// sending the Trojan credential header -- `nil` means directly over
    /// the TLS/plain connection, the historical default.
    public let wsPath: String?
    /// The `Host:` header sent in the WS upgrade request, if different from
    /// `sni ?? host`. Ignored when `wsPath` is `nil`.
    public let wsHost: String?

    public init(host: String, port: UInt16, password: String, tls: Bool = true, sni: String? = nil, allowInsecure: Bool = false, wsPath: String? = nil, wsHost: String? = nil) {
        self.host = host
        self.port = port
        self.password = password
        self.tls = tls
        self.sni = sni
        self.allowInsecure = allowInsecure
        self.wsPath = wsPath
        self.wsHost = wsHost
    }
}

// MARK: - Wire format

/// `public`: ChainCore's `TrojanUDPRelay` needs `.udpAssociate` to open a
/// Trojan session in UDP mode -- everything else in this module stays internal.
public enum TrojanCommand {
    public static let connect: UInt8 = 0x01
    public static let udpAssociate: UInt8 = 0x03
}
private let crlf: [UInt8] = [0x0D, 0x0A]

/// `hex(SHA224(password))`, lowercase -- the literal 56-byte credential this
/// protocol sends in place of a real HTTP request when it isn't one.
func trojanPasswordHex(_ password: String) -> String {
    sha224(Array(password.utf8)).map { String(format: "%02x", $0) }.joined()
}

/// Builds the full request header (credential + CRLF + CONNECT/UDP-Associate
/// request + CRLF) sent as the first bytes of the TLS session.
func trojanRequestHeader(password: String, target: ProxyAddress, targetPort: UInt16, command: UInt8 = TrojanCommand.connect) throws -> [UInt8] {
    let passwordHex = Array(trojanPasswordHex(password).utf8)
    let request = try [command] + target.socks5Encoded + targetPort.bigEndianBytes
    return passwordHex + crlf + request + crlf
}

// MARK: - UDP relay (per-packet framing)
//
// Sent after a request header whose CMD was `TrojanCommand.udpAssociate`:
// a stream of frames, each naming its own destination (unlike VMess/VLESS,
// which name one target once, in the request header itself). Verified
// against the reference `trojan`/`trojan-go` implementations:
//
//   ATYP + DST.ADDR + DST.PORT + Length(2 BE) + CRLF + Payload + CRLF

public enum TrojanUDPError: Error, Equatable {
    /// Shorter than the fixed ATYP+addr+port+length+CRLF prefix, or the
    /// payload ran past the end of what was available.
    case packetTooShort
    /// ATYP wasn't 0x01/0x03/0x04, or a domain's length-prefixed bytes weren't valid UTF-8.
    case malformedAddress
    /// The length-delimited CRLF (the one before the payload) wasn't literally 0x0D 0x0A.
    case missingCRLF
}

/// Builds one UDP relay frame addressed at `target:targetPort`.
///
/// No trailing CRLF after `payload` -- the wire format is exactly
/// `ATYP+ADDR+PORT+Length+CRLF+Payload`, confirmed against a real
/// xray-core Trojan server: an earlier version of this function appended
/// one (self-consistent with the matching bug in `readTrojanUDPFrame` and
/// the hand-rolled fake server this module's own tests used, so nothing
/// caught it), and a real server reads that stray `\r` as the next frame's
/// ATYP byte (0x0D, "unknown address type"), aborting the whole session
/// after relaying nothing -- see `Tests/InteropTests` for the real-server
/// reproduction.
public func trojanUDPFrame(target: ProxyAddress, targetPort: UInt16, payload: [UInt8]) throws -> [UInt8] {
    guard let length = UInt16(exactly: payload.count) else { throw TrojanUDPError.packetTooShort }
    return try target.socks5Encoded + targetPort.bigEndianBytes + length.bigEndianBytes + crlf + payload
}

/// Reads and decodes one frame off `transport` (an already-open Trojan
/// session in UDP mode) -- the inverse of `trojanUDPFrame`.
public func readTrojanUDPFrame(from transport: any ByteStreamSource, timeout: TimeInterval? = nil) async throws -> (target: ProxyAddress, targetPort: UInt16, payload: [UInt8]) {
    let atyp = try await transport.readExactly(1, timeout: timeout)
    let target: ProxyAddress
    switch atyp[0] {
    case 0x01:
        target = .ipv4(try await transport.readExactly(4, timeout: timeout))
    case 0x04:
        target = .ipv6(try await transport.readExactly(16, timeout: timeout))
    case 0x03:
        let lengthByte = try await transport.readExactly(1, timeout: timeout)
        let domainBytes = try await transport.readExactly(Int(lengthByte[0]), timeout: timeout)
        guard let domain = String(bytes: domainBytes, encoding: .utf8) else { throw TrojanUDPError.malformedAddress }
        target = .domain(domain)
    default:
        throw TrojanUDPError.malformedAddress
    }

    let portBytes = try await transport.readExactly(2, timeout: timeout)
    let targetPort = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])
    let lengthBytes = try await transport.readExactly(2, timeout: timeout)
    let length = Int(lengthBytes[0]) << 8 | Int(lengthBytes[1])

    guard try await transport.readExactly(2, timeout: timeout) == crlf else { throw TrojanUDPError.missingCRLF }
    let payload = try await transport.readExactly(length, timeout: timeout)

    return (target, targetPort, payload)
}

// MARK: - Reusable Trojan session
//
// Encapsulates one Trojan-proxied connection: complete the TLS handshake,
// send the credential + CONNECT header, then expose a plain send/receive
// byte pipe over the TLS session -- callers don't need to know anything
// about the header framing to relay their own application data.
//
// `TrojanSession` conforms to `ProxyTransport` itself, so it can serve as
// the transport for a *further* hop's handshake, the same way every other
// protocol's `Session` here does.

public final class TrojanSession: ByteStreamSource, ByteStreamSink, ByteStreamAvailableReader, ByteStreamCloser {
    // `any ProxyTransport` rather than `TLSConn` specifically: holds a
    // `TLSConn` (Secure Transport, see `open(over:)`) when Trojan is stacked
    // over an already-open transport, or a `TCPConn` with TLS negotiated
    // natively (see `open(server:)`) when Trojan is dialing fresh as its own
    // first hop -- either way `send`/`readAvailable`/etc. below don't care
    // which.
    private let conn: any ProxyTransport

    private init(conn: any ProxyTransport) { self.conn = conn }

    /// Optionally completes the TLS handshake, then sends the credential +
    /// CONNECT header for `targetHost:targetPort` over an already-open
    /// `transport`, via `TLSConn`'s Secure Transport bridge -- the only way
    /// to wrap TLS around a transport that isn't a fresh connection this
    /// call dials itself (a previous hop's already-open `Session`, when
    /// Trojan is stacked on top of it mid-chain). When Trojan is dialing
    /// fresh as the very first hop instead, `open(server:)` below uses
    /// Network.framework's own native TLS directly rather than this path
    /// (confirmed live: some relays' own anti-probing filters pass a native
    /// TLS ClientHello while killing Secure Transport's for the same node).
    /// `sni` is the trojan server's own `host` unless the caller overrides it
    /// (see `TrojanServerConfig.sni`) -- unlike the other protocols here,
    /// Trojan needs this even when `transport` isn't a fresh `TCPConn`, since
    /// a stacked transport carries no `host` of its own for this hop's TLS
    /// layer to validate against (and, even with `tls: false`, `wsHost`'s own
    /// fallback to `sni` still needs it).
    public static func open(
        over transport: any ProxyTransport,
        password: String,
        tls: Bool = true,
        sni: String,
        allowInsecure: Bool = false,
        wsPath: String? = nil,
        wsHost: String? = nil,
        targetHost: ProxyAddress,
        targetPort: UInt16,
        command: UInt8 = TrojanCommand.connect,
        timeout: TimeInterval? = 10
    ) async throws -> TrojanSession {
        var conn: any ProxyTransport = transport
        if tls {
            conn = try await TLSConn.handshake(over: transport, options: TLSOptions(serverName: sni, allowInsecure: allowInsecure), timeout: timeout)
        }
        if let wsPath {
            conn = try await WSConn.handshake(over: conn, host: wsHost ?? sni, path: wsPath, timeout: timeout)
        }
        let header = try trojanRequestHeader(password: password, target: targetHost, targetPort: targetPort, command: command)
        try await conn.send(header, timeout: timeout)
        return TrojanSession(conn: conn)
    }

    /// Dials `server` directly, with TLS negotiated natively by
    /// Network.framework as part of the connection itself when `server.tls`
    /// is `true` (see this class's own doc comment, and
    /// `TCPConn.NativeTLSOptions`'s, for why -- this is the one case, a
    /// fresh dial, where that's possible at all), optionally wraps WS, then
    /// sends the header. `connectTimeout` guards the dial, the TLS handshake
    /// (if any), the WS handshake (if any), and the header send alike
    /// against a firewalled/unresponsive server (mirrors every other
    /// protocol's `open(server:)` here).
    public static func open(server: TrojanServerConfig, targetHost: ProxyAddress, targetPort: UInt16, command: UInt8 = TrojanCommand.connect, connectTimeout: TimeInterval? = 10) async throws -> TrojanSession {
        let conn = TCPConn(host: server.host, port: server.port)
        try await conn.connect(
            timeout: connectTimeout,
            tls: server.tls ? TCPConn.NativeTLSOptions(serverName: server.sni ?? server.host, allowInsecure: server.allowInsecure) : nil
        )
        do {
            var transport: any ProxyTransport = conn
            if let wsPath = server.wsPath {
                transport = try await WSConn.handshake(over: transport, host: server.wsHost ?? server.sni ?? server.host, path: wsPath, timeout: connectTimeout)
            }
            let header = try trojanRequestHeader(password: server.password, target: targetHost, targetPort: targetPort, command: command)
            try await transport.send(header, timeout: connectTimeout)
            return TrojanSession(conn: transport)
        } catch {
            // `conn` already connected (and, when `server.tls`, completed
            // native TLS) above -- without this, a failure in the WS
            // handshake or header send below would leak that socket, since
            // nothing else still references `conn` once this rethrows.
            conn.close()
            throw error
        }
    }

    /// Sends raw application bytes toward `target` (no per-connection framing beyond the one-time header -- Trojan relays a plain byte stream over TLS once it's sent).
    public func send(_ bytes: [UInt8], timeout: TimeInterval? = nil) async throws {
        try await conn.send(bytes, timeout: timeout)
    }

    /// Reads raw application bytes coming back from `target` ([] once the stream ends).
    public func receive(timeout: TimeInterval? = nil) async throws -> [UInt8] {
        try await readAvailable(timeout: timeout)
    }

    public func readAvailable(timeout: TimeInterval? = nil) async throws -> [UInt8] {
        try await conn.readAvailable(timeout: timeout)
    }

    /// Exact-length read for a protocol stacked *on top of* this Trojan hop: delegates straight to `TLSConn`, which already buffers across underlying reads.
    public func readExactly(_ n: Int, timeout: TimeInterval? = nil) async throws -> [UInt8] {
        try await conn.readExactly(n, timeout: timeout)
    }

    public func close() { conn.close() }
}
