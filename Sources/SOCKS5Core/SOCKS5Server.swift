// SOCKS5Server.swift
//
// Server-side accept path for one SOCKS5 CONNECT handshake, over an
// already-accepted local connection. Built for Chainy's local loopback
// SOCKS5 listener: something outside this codebase (a browser, curl, etc.)
// plays the client role `SOCKS5Session.open` already speaks; this plays the
// server role.
//
// v1 supports only `SOCKS5Auth.none`: this is a loopback-only listener
// (bound to 127.0.0.1 by ProxyKit's `TCPListener`), not a proxy exposed to
// the network, so there's no untrusted-network reason yet to require local
// callers to authenticate. CONNECT (0x01) and UDP ASSOCIATE (0x03) are
// handled -- no BIND. `acceptConnect` is CONNECT-only (kept exactly as it
// was, for callers that never need to tell CONNECT and ASSOCIATE apart);
// `acceptRequest`/`replyAssociate` below are the ones a caller that also
// wants UDP ASSOCIATE (Chainy's local listener) actually uses.

import Foundation
import ProxyKit

public struct SOCKS5IncomingRequest: Equatable, Hashable {
    public let host: String
    public let port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }
}

public enum SOCKS5ServerError: Error, Equatable {
    /// The client's greeting/request didn't start with version byte 0x05.
    case unsupportedVersion(UInt8)
    /// The client's greeting didn't offer NO AUTHENTICATION REQUIRED (0x00).
    case noAcceptableMethodOffered
    /// The client asked for something `acceptConnect`/`acceptRequest` don't handle (BIND, or anything unassigned).
    case unsupportedCommand(UInt8)
}

/// The two commands `acceptRequest` understands. `.connect` carries the
/// decoded target, same shape as `acceptConnect`'s own return value;
/// `.associate` carries nothing of its own -- see `acceptRequest`'s doc
/// comment on why the client's stated source address/port is discarded, and
/// `replyAssociate` for how the caller replies once it has something to
/// reply with.
public enum SOCKS5IncomingCommand: Equatable {
    case connect(SOCKS5IncomingRequest)
    case associate
}

public enum SOCKS5Server {
    /// Runs the server side of one SOCKS5 handshake over `transport`: reads
    /// the greeting and replies selecting NO AUTH if the client offered it
    /// (0xFF, then throws, otherwise), reads the CONNECT request head +
    /// address (reusing this module's own `readSOCKS5Address` -- already
    /// module-visible, no re-decoding needed), replies success with a dummy
    /// bound address (0.0.0.0:0 -- meaningless once relaying starts, same as
    /// what a real server's CONNECT reply carries once the tunnel is up),
    /// and returns the decoded destination for the caller to actually relay
    /// traffic to.
    public static func acceptConnect(over transport: any SOCKS5Transport, timeout: TimeInterval? = 10) async throws -> SOCKS5IncomingRequest {
        let greeting = try await transport.readExactly(2, timeout: timeout)
        guard greeting[0] == SOCKS5Version.value else { throw SOCKS5ServerError.unsupportedVersion(greeting[0]) }
        let methods = try await transport.readExactly(Int(greeting[1]), timeout: timeout)
        guard methods.contains(SOCKS5Method.noAuth.rawValue) else {
            try? await transport.send([SOCKS5Version.value, SOCKS5Method.noAcceptable.rawValue], timeout: timeout)
            throw SOCKS5ServerError.noAcceptableMethodOffered
        }
        try await transport.send([SOCKS5Version.value, SOCKS5Method.noAuth.rawValue], timeout: timeout)

        let head = try await transport.readExactly(4, timeout: timeout) // ver, cmd, rsv, atyp
        guard head[0] == SOCKS5Version.value else { throw SOCKS5ServerError.unsupportedVersion(head[0]) }
        guard head[1] == SOCKS5Command.connect else {
            try? await transport.send(
                [SOCKS5Version.value, SOCKS5ReplyCode.commandNotSupported.rawValue, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
                timeout: timeout
            )
            throw SOCKS5ServerError.unsupportedCommand(head[1])
        }

        let address = try await readSOCKS5Address(atyp: head[3], transport: transport, timeout: timeout)
        let portBytes = try await transport.readExactly(2, timeout: timeout)
        let port = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])

        try await transport.send([SOCKS5Version.value, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0], timeout: timeout)
        return SOCKS5IncomingRequest(host: address.displayHost, port: port)
    }

    /// Like `acceptConnect`, but also accepts UDP ASSOCIATE (0x03) --
    /// `acceptConnect` itself is left untouched (and still rejects
    /// ASSOCIATE) since plenty of callers/tests only ever want CONNECT; this
    /// is the entry point for a caller (Chainy's local listener) that needs
    /// to tell the two apart. ASSOCIATE's own success reply isn't sent here
    /// the way CONNECT's is: CONNECT's BND.ADDR/BND.PORT is a meaningless
    /// dummy (0.0.0.0:0, same as `acceptConnect` sends) since the tunnel is
    /// already established by the time it's sent, but ASSOCIATE's reply is
    /// the address the client will actually send its UDP datagrams to --
    /// genuinely load-bearing, and not known until the caller has bound its
    /// own local UDP relay socket. See `replyAssociate` below for that step.
    public static func acceptRequest(over transport: any SOCKS5Transport, timeout: TimeInterval? = 10) async throws -> SOCKS5IncomingCommand {
        let greeting = try await transport.readExactly(2, timeout: timeout)
        guard greeting[0] == SOCKS5Version.value else { throw SOCKS5ServerError.unsupportedVersion(greeting[0]) }
        let methods = try await transport.readExactly(Int(greeting[1]), timeout: timeout)
        guard methods.contains(SOCKS5Method.noAuth.rawValue) else {
            try? await transport.send([SOCKS5Version.value, SOCKS5Method.noAcceptable.rawValue], timeout: timeout)
            throw SOCKS5ServerError.noAcceptableMethodOffered
        }
        try await transport.send([SOCKS5Version.value, SOCKS5Method.noAuth.rawValue], timeout: timeout)

        let head = try await transport.readExactly(4, timeout: timeout) // ver, cmd, rsv, atyp
        guard head[0] == SOCKS5Version.value else { throw SOCKS5ServerError.unsupportedVersion(head[0]) }
        guard head[1] == SOCKS5Command.connect || head[1] == SOCKS5Command.associate else {
            try? await transport.send(
                [SOCKS5Version.value, SOCKS5ReplyCode.commandNotSupported.rawValue, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
                timeout: timeout
            )
            throw SOCKS5ServerError.unsupportedCommand(head[1])
        }

        if head[1] == SOCKS5Command.associate {
            // A client's stated source address/port here is conventionally
            // advisory only -- many clients send 0.0.0.0:0 since they don't
            // know their own outbound address/port yet, and real servers
            // (this one included) neither require nor validate it. Still
            // has to be consumed off the wire before the request head is
            // fully read, though.
            _ = try await readSOCKS5Address(atyp: head[3], transport: transport, timeout: timeout)
            _ = try await transport.readExactly(2, timeout: timeout)
            return .associate
        }

        let address = try await readSOCKS5Address(atyp: head[3], transport: transport, timeout: timeout)
        let portBytes = try await transport.readExactly(2, timeout: timeout)
        let port = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])

        try await transport.send([SOCKS5Version.value, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0], timeout: timeout)
        return .connect(SOCKS5IncomingRequest(host: address.displayHost, port: port))
    }

    /// Sends the UDP ASSOCIATE success reply: BND.ADDR/BND.PORT =
    /// `127.0.0.1:boundPort`, the address of the local `UDPListener` the
    /// caller already bound for this association -- the client dials that
    /// next to actually send/receive its relayed UDP datagrams.
    public static func replyAssociate(over transport: any SOCKS5Transport, boundPort: UInt16, timeout: TimeInterval? = 10) async throws {
        try await transport.send([SOCKS5Version.value, 0x00, 0x00, 0x01, 127, 0, 0, 1] + boundPort.bigEndianBytes, timeout: timeout)
    }

    /// Sends the same "command not supported" (0x07) reply `acceptRequest`
    /// itself sends for a command it doesn't understand at all -- exposed
    /// separately for a caller that accepted an ASSOCIATE request but then
    /// discovered *after the fact* that it can't actually serve it (e.g. the
    /// active chain isn't all-Shadowsocks -- see `ShadowsocksUDPRelay`),
    /// once it's too late to have `acceptRequest` reject it up front.
    public static func replyCommandNotSupported(over transport: any SOCKS5Transport, timeout: TimeInterval? = 10) async throws {
        try await transport.send([SOCKS5Version.value, SOCKS5ReplyCode.commandNotSupported.rawValue, 0x00, 0x01, 0, 0, 0, 0, 0, 0], timeout: timeout)
    }
}
