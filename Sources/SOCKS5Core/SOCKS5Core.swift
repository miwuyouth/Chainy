// SOCKS5Core.swift
//
// A minimal SOCKS5 (RFC 1928) TCP CONNECT client, built on ProxyKit's shared
// networking/address primitives.
//
// Supported auth methods: NO AUTHENTICATION REQUIRED (0x00) and
// USERNAME/PASSWORD (RFC 1929, 0x02) -- GSSAPI and other methods aren't
// implemented, matching what real-world SOCKS5 clients (curl, browsers,
// v2ray-core's SOCKS5 client) overwhelmingly negotiate in practice.
//
// Unlike a general-purpose client, the greeting only ever offers the single
// method implied by the caller's `SOCKS5Auth` (not "every method we know
// how to speak") -- if the caller configured credentials, the server is
// expected to require them; if it configured none, the server is expected
// to accept an unauthenticated connection. That keeps the negotiation
// deterministic (one request, one expected reply) instead of adding a path
// where the server silently downgrades to a method the caller didn't ask for.
//
// Only CONNECT (0x01) and UDP ASSOCIATE (0x03) are implemented -- no BIND.
// `SOCKS5UDPAssociation` negotiates and owns ASSOCIATE's TCP control channel;
// the datagram socket or an earlier proxy chain that carries the returned
// relay endpoint remains ChainCore's responsibility.

import Foundation
import ProxyKit

// MARK: - Configuration

public enum SOCKS5Auth: Equatable {
    case none
    case usernamePassword(username: String, password: String)
}

public struct SOCKS5ServerConfig {
    public let host: String
    public let port: UInt16
    public let auth: SOCKS5Auth

    public init(host: String, port: UInt16, auth: SOCKS5Auth = .none) {
        self.host = host
        self.port = port
        self.auth = auth
    }
}

// MARK: - Errors

/// The RFC 1928 CONNECT reply codes (Section 6), used to turn a raw REP byte
/// into something readable. Codes outside 0x00...0x08 are unassigned by the
/// RFC; `SOCKS5Error.requestFailed` still carries the raw byte in that case
/// (`name(forReplyCode:)` falls back to a generic description) rather than
/// failing to decode the error itself.
public enum SOCKS5ReplyCode: UInt8 {
    case generalServerFailure = 0x01
    case connectionNotAllowedByRuleset = 0x02
    case networkUnreachable = 0x03
    case hostUnreachable = 0x04
    case connectionRefused = 0x05
    case ttlExpired = 0x06
    case commandNotSupported = 0x07
    case addressTypeNotSupported = 0x08

    public static func name(forReplyCode code: UInt8) -> String {
        SOCKS5ReplyCode(rawValue: code).map { "\($0)" } ?? "unassigned(0x\(String(format: "%02x", code)))"
    }
}

public enum SOCKS5Error: Error, Equatable {
    /// The server's greeting/request reply didn't start with version byte 0x05.
    case unsupportedServerVersion(UInt8)
    /// The server responded 0xFF to the greeting: none of the offered methods (just the one we sent) were acceptable.
    case noAcceptableAuthMethod
    /// The server selected a method we didn't offer.
    case unexpectedAuthMethod(UInt8)
    /// RFC 1929 subnegotiation failed (status byte != 0x00).
    case authenticationFailed(status: UInt8)
    /// A username or password is too long to length-prefix with a single byte (RFC 1929 caps each at 255 bytes).
    case credentialTooLong
    /// The CONNECT request's REP byte was non-zero.
    case requestFailed(replyCode: UInt8)
    /// A reply's ATYP byte (or a domain's UTF-8 bytes) didn't decode to a valid address.
    case malformedReply
}

// MARK: - Wire constants

enum SOCKS5Version { static let value: UInt8 = 0x05 }

enum SOCKS5Method: UInt8 {
    case noAuth = 0x00
    case usernamePassword = 0x02
    case noAcceptable = 0xFF
}

enum SOCKS5Command { static let connect: UInt8 = 0x01, associate: UInt8 = 0x03 }
enum SOCKS5AddressType { static let ipv4: UInt8 = 0x01, domain: UInt8 = 0x03, ipv6: UInt8 = 0x04 }

extension SOCKS5Auth {
    var offeredMethod: SOCKS5Method {
        switch self {
        case .none: return .noAuth
        case .usernamePassword: return .usernamePassword
        }
    }
}

// MARK: - Transport
//
// Handshake logic below is written against this narrow read+write interface
// (ProxyKit's `ByteStreamSource & ByteStreamSink`, not TCPConn directly) so
// it can be driven by an in-memory fake in unit tests, the same way
// ShadowsocksCore's chunk decoder is driven by a fake `ByteStreamSource` --
// no real socket needed to exercise the framing. It's also *why* chaining
// works: this same narrow interface is satisfied by a previous hop's already
// -open `Session` just as well as by a fresh `TCPConn`, so `open(over:)`
// below doesn't care which one it got.

public typealias SOCKS5Transport = ByteStreamSource & ByteStreamSink

// MARK: - Handshake steps

/// Sends the RFC 1928 greeting offering exactly the one method `auth`
/// implies, and confirms the server selected that same method.
func sendGreetingAndSelectMethod(transport: SOCKS5Transport, auth: SOCKS5Auth, timeout: TimeInterval?) async throws {
    let offered = auth.offeredMethod
    try await transport.send([SOCKS5Version.value, 0x01, offered.rawValue], timeout: timeout)

    let reply = try await transport.readExactly(2, timeout: timeout)
    guard reply[0] == SOCKS5Version.value else { throw SOCKS5Error.unsupportedServerVersion(reply[0]) }
    guard reply[1] != SOCKS5Method.noAcceptable.rawValue else { throw SOCKS5Error.noAcceptableAuthMethod }
    guard reply[1] == offered.rawValue else { throw SOCKS5Error.unexpectedAuthMethod(reply[1]) }
}

/// RFC 1929 username/password subnegotiation, run only after the server has selected method 0x02.
func performUsernamePasswordAuth(transport: SOCKS5Transport, username: String, password: String, timeout: TimeInterval?) async throws {
    let userBytes = Array(username.utf8)
    let passBytes = Array(password.utf8)
    guard let ulen = UInt8(exactly: userBytes.count), let plen = UInt8(exactly: passBytes.count) else {
        throw SOCKS5Error.credentialTooLong
    }
    try await transport.send([0x01, ulen] + userBytes + [plen] + passBytes, timeout: timeout)

    let reply = try await transport.readExactly(2, timeout: timeout)
    guard reply[1] == 0x00 else { throw SOCKS5Error.authenticationFailed(status: reply[1]) }
}

/// Reads one RFC 1928 address (ATYP already consumed by the caller) off the wire.
func readSOCKS5Address(atyp: UInt8, transport: SOCKS5Transport, timeout: TimeInterval?) async throws -> ProxyAddress {
    switch atyp {
    case SOCKS5AddressType.ipv4: return .ipv4(try await transport.readExactly(4, timeout: timeout))
    case SOCKS5AddressType.ipv6: return .ipv6(try await transport.readExactly(16, timeout: timeout))
    case SOCKS5AddressType.domain:
        let lengthByte = try await transport.readExactly(1, timeout: timeout)
        let domainBytes = try await transport.readExactly(Int(lengthByte[0]), timeout: timeout)
        guard let domain = String(bytes: domainBytes, encoding: .utf8) else { throw SOCKS5Error.malformedReply }
        return .domain(domain)
    default:
        throw SOCKS5Error.malformedReply
    }
}

/// Sends the CONNECT request for `target:targetPort` and decodes the reply,
/// returning the server-reported BND.ADDR (BND.PORT is read but discarded --
/// like VMessCore/ShadowsocksCore, this client has no use for it once the
/// relay is established).
@discardableResult
func sendConnectRequestAndAwaitReply(transport: SOCKS5Transport, target: ProxyAddress, targetPort: UInt16, timeout: TimeInterval?) async throws -> ProxyAddress {
    let request = try [SOCKS5Version.value, SOCKS5Command.connect, 0x00] + target.socks5Encoded + targetPort.bigEndianBytes
    try await transport.send(request, timeout: timeout)

    let head = try await transport.readExactly(4, timeout: timeout)
    guard head[0] == SOCKS5Version.value else { throw SOCKS5Error.unsupportedServerVersion(head[0]) }
    guard head[1] == 0x00 else { throw SOCKS5Error.requestFailed(replyCode: head[1]) }

    let boundAddress = try await readSOCKS5Address(atyp: head[3], transport: transport, timeout: timeout)
    _ = try await transport.readExactly(2, timeout: timeout) // BND.PORT, unused
    return boundAddress
}

/// Sends UDP ASSOCIATE with the conventional `0.0.0.0:0` client endpoint and
/// returns the server-advertised UDP relay endpoint. The TCP transport must
/// remain open for the lifetime of the association.
func sendAssociateRequestAndAwaitReply(transport: SOCKS5Transport, timeout: TimeInterval?) async throws -> (address: ProxyAddress, port: UInt16) {
    try await transport.send([SOCKS5Version.value, SOCKS5Command.associate, 0x00, SOCKS5AddressType.ipv4, 0, 0, 0, 0, 0, 0], timeout: timeout)

    let head = try await transport.readExactly(4, timeout: timeout)
    guard head[0] == SOCKS5Version.value else { throw SOCKS5Error.unsupportedServerVersion(head[0]) }
    guard head[1] == 0x00 else { throw SOCKS5Error.requestFailed(replyCode: head[1]) }
    let address = try await readSOCKS5Address(atyp: head[3], transport: transport, timeout: timeout)
    let portBytes = try await transport.readExactly(2, timeout: timeout)
    let port = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])
    guard port != 0 else { throw SOCKS5Error.malformedReply }
    return (address, port)
}

/// A negotiated SOCKS5 UDP ASSOCIATE control channel. Closing this object
/// invalidates the server-side UDP association as required by RFC 1928.
public final class SOCKS5UDPAssociation {
    private let control: any ProxyTransport
    public let relayAddress: ProxyAddress
    public let relayPort: UInt16

    private init(control: any ProxyTransport, relayAddress: ProxyAddress, relayPort: UInt16) {
        self.control = control
        self.relayAddress = relayAddress
        self.relayPort = relayPort
    }

    public static func open(over transport: any ProxyTransport, auth: SOCKS5Auth, timeout: TimeInterval? = 10) async throws -> SOCKS5UDPAssociation {
        try await sendGreetingAndSelectMethod(transport: transport, auth: auth, timeout: timeout)
        if case .usernamePassword(let username, let password) = auth {
            try await performUsernamePasswordAuth(transport: transport, username: username, password: password, timeout: timeout)
        }
        let endpoint = try await sendAssociateRequestAndAwaitReply(transport: transport, timeout: timeout)
        return SOCKS5UDPAssociation(control: transport, relayAddress: endpoint.address, relayPort: endpoint.port)
    }

    public func close() { control.close() }
}

// MARK: - UDP relay (ASSOCIATE) datagram framing
//
// Every UDP datagram exchanged on the relay socket a SOCKS5 ASSOCIATE
// request hands back (RFC 1928 Section 7) carries its own destination
// address inline -- unlike CONNECT's one-time address negotiated over the
// TCP control connection, ASSOCIATE is "any destination, per packet". The
// whole datagram is already in memory once received, so this is a plain
// synchronous byte-array codec, unlike `readSOCKS5Address` above (which
// frames a handshake read off an open connection one field at a time).
// The same header shape serves both directions: a client's own request
// datagram and the relay's reply datagram back to the client both use it
// (RFC 1928 doesn't distinguish them).

public enum SOCKS5UDPError: Error, Equatable {
    /// Shorter than the fixed RSV+FRAG+ATYP header, or an ATYP's address/data
    /// bytes ran past the end of the packet.
    case packetTooShort
    /// FRAG was non-zero -- fragmented UDP datagrams (RFC 1928 Section 7's
    /// optional reassembly scheme) aren't implemented; no SOCKS5 client seen
    /// in practice sends them.
    case fragmentationNotSupported(UInt8)
    /// ATYP wasn't 0x01/0x03/0x04, or a domain's length-prefixed bytes weren't valid UTF-8.
    case malformedAddress
}

/// Builds `RSV(2)=0x0000 + FRAG(1)=0x00 + ATYP+DST.ADDR+DST.PORT + DATA`.
public func socks5UDPDatagram(target: ProxyAddress, targetPort: UInt16, payload: [UInt8]) throws -> [UInt8] {
    try [0x00, 0x00, 0x00] + target.socks5Encoded + targetPort.bigEndianBytes + payload
}

/// The inverse of `socks5UDPDatagram`.
public func parseSOCKS5UDPDatagram(_ packet: [UInt8]) throws -> (target: ProxyAddress, targetPort: UInt16, payload: [UInt8]) {
    guard packet.count >= 4 else { throw SOCKS5UDPError.packetTooShort }
    guard packet[2] == 0x00 else { throw SOCKS5UDPError.fragmentationNotSupported(packet[2]) }

    var offset = 4
    let target: ProxyAddress
    switch packet[3] {
    case SOCKS5AddressType.ipv4:
        guard packet.count >= offset + 4 else { throw SOCKS5UDPError.packetTooShort }
        target = .ipv4(Array(packet[offset..<offset + 4]))
        offset += 4
    case SOCKS5AddressType.ipv6:
        guard packet.count >= offset + 16 else { throw SOCKS5UDPError.packetTooShort }
        target = .ipv6(Array(packet[offset..<offset + 16]))
        offset += 16
    case SOCKS5AddressType.domain:
        guard packet.count > offset else { throw SOCKS5UDPError.packetTooShort }
        let length = Int(packet[offset])
        offset += 1
        guard packet.count >= offset + length else { throw SOCKS5UDPError.packetTooShort }
        guard let domain = String(bytes: packet[offset..<offset + length], encoding: .utf8) else { throw SOCKS5UDPError.malformedAddress }
        target = .domain(domain)
        offset += length
    default:
        throw SOCKS5UDPError.malformedAddress
    }

    guard packet.count >= offset + 2 else { throw SOCKS5UDPError.packetTooShort }
    let targetPort = UInt16(packet[offset]) << 8 | UInt16(packet[offset + 1])
    offset += 2
    return (target, targetPort, Array(packet[offset...]))
}

// MARK: - Reusable SOCKS5 session
//
// Encapsulates one SOCKS5-proxied connection: negotiate the auth method,
// authenticate if configured, send the CONNECT request for `target`, then
// expose a plain send/receive byte pipe -- callers don't need to know
// anything about the handshake to relay their own application data.
//
// `SOCKS5Session` conforms to `ProxyTransport` itself, so it can serve as the
// transport for a *further* hop's handshake (e.g. Shadowsocks or VMess
// tunneled through this SOCKS5 proxy): `readExactly` buffers across
// underlying reads the same way `TCPConn.readExactly` buffers partial TCP
// reads, just one layer up over whatever `conn` (a raw socket, or yet
// another hop) hands back from `readAvailable`.

public final class SOCKS5Session: ByteStreamSource, ByteStreamSink, ByteStreamAvailableReader, ByteStreamCloser {
    private let conn: any ProxyTransport
    private var buffered: [UInt8] = []

    private init(conn: any ProxyTransport) { self.conn = conn }

    /// Completes the SOCKS5 handshake (auth + CONNECT for `targetHost:targetPort`)
    /// over an already-open `transport`. This is the primitive every other
    /// `open` overload reduces to -- `transport` is a fresh `TCPConn` when
    /// SOCKS5 is the first hop of a chain, or a previous hop's already-open
    /// `Session` when SOCKS5 is stacked on top of it.
    public static func open(over transport: any ProxyTransport, auth: SOCKS5Auth, targetHost: ProxyAddress, targetPort: UInt16, timeout: TimeInterval? = 10) async throws -> SOCKS5Session {
        try await sendGreetingAndSelectMethod(transport: transport, auth: auth, timeout: timeout)
        if case .usernamePassword(let username, let password) = auth {
            try await performUsernamePasswordAuth(transport: transport, username: username, password: password, timeout: timeout)
        }
        try await sendConnectRequestAndAwaitReply(transport: transport, target: targetHost, targetPort: targetPort, timeout: timeout)
        return SOCKS5Session(conn: transport)
    }

    /// Dials `server` directly over TCP, then completes the handshake.
    /// `connectTimeout` guards both the TCP handshake and every handshake
    /// step against a firewalled/unresponsive server (mirrors
    /// VMessSession/ShadowsocksSession's use of `ProxyError.timedOut`).
    public static func open(server: SOCKS5ServerConfig, targetHost: ProxyAddress, targetPort: UInt16, connectTimeout: TimeInterval? = 10) async throws -> SOCKS5Session {
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

    /// Sends raw application bytes toward `target` (no per-connection framing/encryption -- SOCKS5 relays a plain byte stream once CONNECT succeeds).
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

    /// Exact-length read for a protocol stacked *on top of* this SOCKS5 hop:
    /// buffers across as many underlying `readAvailable` calls as needed,
    /// the same pattern `TCPConn.readExactly` uses over raw socket reads.
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
