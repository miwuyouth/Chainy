// VLESSCore.swift
//
// A minimal VLESS (https://xtls.github.io) client, built on ProxyKit's
// shared networking/crypto/address primitives.
//
// Unlike VMess, VLESS's own wire protocol carries no encryption of its own
// at all -- Version + UUID + (empty) Addons + Command + Port + Address is
// sent as plain bytes, and the connection body that follows is a completely
// raw pipe with no per-chunk framing either: the protocol's own design
// deliberately defers all confidentiality to whatever transport carries it,
// typically TLS. That's why `VLESSSession.open` can optionally wrap the
// connection in TLS itself (`tls: true`, using the same `TLSConn`/native-TLS
// machinery TrojanCore uses) -- the common "VLESS + TLS" deployment -- while
// still supporting a bare `tls: false` connection for the same reason
// VMessCore supports Security=none: this app's own chaining model can
// already stack another hop's encryption underneath, or the caller is
// deliberately testing/relaying over an already-trusted link.
//
// Command = 0x01 (TCP) is the default; Command = 0x02 (UDP) is also
// implemented (see `VLESSCommand.udp`) for ChainCore's `TunneledUDPRelay`,
// which frames the body into per-datagram chunks itself -- this module has
// no UDP-specific logic beyond accepting the command byte as a parameter.
// Still no Mux, and no request "addons" (the field that would carry XTLS's
// "flow" value for xtls-rprx-vision, which needs transport-level stream
// splicing this client doesn't implement -- a node requiring it is expected
// to be filtered out before reaching this module, see SubscriptionCore's
// vless parsing).
//
// Wire format verified against Xray-core's proxy/vless/encoding package:
//
//   Request:  [0x00 Ver][16-byte UUID][0x00 AddonsLen][0x01 Cmd]
//             [Port: 2 bytes BE][ATYP: 1=IPv4/2=Domain/3=IPv6][Address]
//   Response: [Ver][AddonsLen][Addons (AddonsLen bytes)]
//
// The response header, like VMess's, is not sent as a separate handshake
// ack -- a real server only writes it piggybacked with the first real data
// it has to relay back (see `VLESSSession.consumeResponseHeader`'s doc
// comment, mirroring `VMessSession.readResponseHeader`'s).

import Foundation
import ProxyKit

// MARK: - Configuration

public struct VLESSServerConfig {
    public let host: String
    public let port: UInt16
    public let uuid: String
    /// Wraps the connection in TLS before sending the VLESS request header
    /// -- the common "VLESS + TLS" deployment. `false` sends the request
    /// (and the fully unencrypted body that follows) directly over the
    /// dialed TCP connection, matching VMessCore's Security=none.
    public let tls: Bool
    /// TLS SNI / certificate hostname, if different from `host` (defaults
    /// to `host` when `nil`). Ignored when `tls` is `false`.
    public let sni: String?
    /// Skips TLS certificate validation -- for self-signed deployments.
    /// Ignored when `tls` is `false`. See `TLSOptions.allowInsecure`.
    public let allowInsecure: Bool
    /// Wraps the (possibly TLS-wrapped) connection in a WebSocket tunnel
    /// before sending the VLESS request header -- `nil` means plain TCP.
    public let wsPath: String?
    /// The `Host:` header sent in the WS upgrade request, if different from
    /// `sni ?? host`. Ignored when `wsPath` is `nil`.
    public let wsHost: String?

    public init(host: String, port: UInt16, uuid: String, tls: Bool = false, sni: String? = nil, allowInsecure: Bool = false, wsPath: String? = nil, wsHost: String? = nil) {
        self.host = host
        self.port = port
        self.uuid = uuid
        self.tls = tls
        self.sni = sni
        self.allowInsecure = allowInsecure
        self.wsPath = wsPath
        self.wsHost = wsHost
    }
}

public struct VLESSTarget {
    public let host: String   // domain, IPv4 literal, or IPv6 literal
    public let port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }
}

/// Parses a canonical UUID string into its 16 raw bytes -- the shape
/// VLESS's own request header embeds verbatim (unlike VMess, which hashes
/// the UUID into an MD5 `cmdKey` instead; VLESS sends it as-is). Named
/// distinctly from VMessCore's own `parseUUID` so importing both into the
/// same file (as ChainCore does) never risks an ambiguous bare-name call.
public func parseVLESSUUID(_ s: String) -> [UInt8] {
    let hex = s.replacingOccurrences(of: "-", with: "")
    precondition(hex.count == 32, "invalid uuid")
    var bytes = [UInt8]()
    var idx = hex.startIndex
    while idx < hex.endIndex {
        let next = hex.index(idx, offsetBy: 2)
        bytes.append(UInt8(hex[idx..<next], radix: 16)!)
        idx = next
    }
    return bytes
}

// MARK: - VLESS's own address wire encoding
//
// Same type-tag values (1=IPv4, 2=Domain, 3=IPv6) as VMessCore's own
// `vmessEncoded` -- VLESS's request format was deliberately modeled on
// VMess's -- but defined again here rather than shared, per ProxyAddress's
// own doc comment: each protocol module owns its own wire encoding.

extension ProxyAddress {
    fileprivate var vlessEncoded: [UInt8] {
        get throws {
            switch self {
            case .ipv4(let b): return [0x01] + b
            case .domain(let d): return try [0x02] + ProxyAddress.lengthPrefixedDomain(d)
            case .ipv6(let b): return [0x03] + b
            }
        }
    }
}

// MARK: - Request header

/// `public`: ChainCore's `TunneledUDPRelay` needs `.udp` to open a VLESS
/// session in UDP mode -- everything else in this module stays internal.
public enum VLESSCommand {
    public static let tcp: UInt8 = 0x01
    /// UDP-over-this-connection: the body that follows is framed into
    /// per-datagram chunks (see ChainCore's `TunneledUDPRelay`) instead of
    /// being the completely raw pipe `tcp` mode is -- the request header
    /// shape and response-header decode are otherwise identical.
    public static let udp: UInt8 = 0x02
}

/// Builds the VLESS request header: Version + UUID + (empty) Addons +
/// Command + Port + Address -- sent as the first bytes of the connection
/// (over a fresh TCP dial or an already-open transport, optionally wrapped
/// in TLS first; see `VLESSSession.open`).
func vlessRequestHeader(uuid: [UInt8], target: VLESSTarget, command: UInt8 = VLESSCommand.tcp) throws -> [UInt8] {
    var header: [UInt8] = [0x00]          // Version
    header += uuid                         // 16 bytes
    header.append(0x00)                    // Addons length (none -- no flow)
    header.append(command)
    header += target.port.bigEndianBytes
    header += try ProxyAddress.parse(target.host).vlessEncoded
    return header
}

// MARK: - Reusable VLESS session
//
// Encapsulates one VLESS-proxied connection: optionally negotiate TLS, send
// the request header for `target`, then expose a plain send/receive byte
// pipe so callers don't need to know any protocol internals to relay their
// own application data.
//
// `VLESSSession` conforms to `ProxyTransport` itself, so it can serve as
// the transport for a *further* hop's handshake (e.g. SOCKS5 or Shadowsocks
// tunneled through this VLESS proxy), the same way every other protocol's
// `Session` here does.

public final class VLESSSession: ByteStreamSource, ByteStreamSink, ByteStreamAvailableReader, ByteStreamCloser {
    private let conn: any ProxyTransport
    private var buffered: [UInt8] = []
    private var responseHeaderConsumed = false
    /// The 2-byte header, once read, cached here until the addons that
    /// follow it are *also* successfully read -- see `consumeResponseHeader`.
    private var pendingHeaderBytes: [UInt8] = []

    private init(conn: any ProxyTransport) { self.conn = conn }

    /// Optionally completes a TLS handshake (`tls: true`, via `TLSConn`'s
    /// Secure Transport bridge -- the only way to wrap TLS around a
    /// transport that isn't a fresh connection this call dials itself: a
    /// previous hop's already-open `Session`, when VLESS is stacked on top
    /// of it mid-chain), then sends the request header for `target` over
    /// `transport`. `sni` is only meaningful when `tls` is `true` -- callers
    /// that want TLS should always pass it explicitly (this hop's own
    /// server hostname, or a front domain), the same way `TrojanSession.open(over:)`
    /// requires its own `sni`, since this generic entry point has no `host`
    /// of its own to fall back to.
    public static func open(
        over transport: any ProxyTransport,
        uuid: String,
        target: VLESSTarget,
        tls: Bool = false,
        sni: String = "",
        allowInsecure: Bool = false,
        wsPath: String? = nil,
        wsHost: String? = nil,
        command: UInt8 = VLESSCommand.tcp,
        timeout: TimeInterval? = 10
    ) async throws -> VLESSSession {
        var conn: any ProxyTransport = transport
        if tls {
            conn = try await TLSConn.handshake(over: conn, options: TLSOptions(serverName: sni, allowInsecure: allowInsecure), timeout: timeout)
        }
        if let wsPath {
            // Same "caller already resolved a real hostname into `sni`"
            // discipline as VMessCore's own `open(over:)` -- this generic
            // entry point has no `host` of its own to fall back to further.
            conn = try await WSConn.handshake(over: conn, host: wsHost ?? sni, path: wsPath, timeout: timeout)
        }
        let header = try vlessRequestHeader(uuid: parseVLESSUUID(uuid), target: target, command: command)
        try await conn.send(header, timeout: timeout)
        return VLESSSession(conn: conn)
    }

    /// Dials `server` directly over TCP, with TLS negotiated natively by
    /// Network.framework as part of the connection itself when `server.tls`
    /// is set (see `TCPConn.NativeTLSOptions`, and `TrojanSession.open(server:)`'s
    /// doc comment for why that's preferable to `TLSConn` for a fresh dial),
    /// then optionally wraps WS, then sends the request header.
    /// `connectTimeout` guards the dial, the TLS handshake (if any), the WS
    /// handshake (if any), and the header send alike against a
    /// firewalled/unresponsive server.
    public static func open(server: VLESSServerConfig, target: VLESSTarget, command: UInt8 = VLESSCommand.tcp, connectTimeout: TimeInterval? = 10) async throws -> VLESSSession {
        let conn = TCPConn(host: server.host, port: server.port)
        if server.tls {
            try await conn.connect(timeout: connectTimeout, tls: TCPConn.NativeTLSOptions(serverName: server.sni ?? server.host, allowInsecure: server.allowInsecure))
        } else {
            try await conn.connect(timeout: connectTimeout)
        }
        do {
            var transport: any ProxyTransport = conn
            if let wsPath = server.wsPath {
                transport = try await WSConn.handshake(over: transport, host: server.wsHost ?? server.sni ?? server.host, path: wsPath, timeout: connectTimeout)
            }
            let header = try vlessRequestHeader(uuid: parseVLESSUUID(server.uuid), target: target, command: command)
            try await transport.send(header, timeout: connectTimeout)
            return VLESSSession(conn: transport)
        } catch {
            // `conn` already connected (and, when `server.tls`, completed
            // native TLS) above -- without this, a failure in the WS
            // handshake or header send below would leak that socket, since
            // nothing else still references `conn` once this rethrows.
            conn.close()
            throw error
        }
    }

    /// Sends raw application bytes toward `target` (no per-chunk framing/encryption -- VLESS relays a plain byte stream, optionally over TLS, once the header is sent).
    public func send(_ bytes: [UInt8], timeout: TimeInterval? = nil) async throws {
        try await conn.send(bytes, timeout: timeout)
    }

    /// Consumes the server's response header (Version + AddonsLength +
    /// Addons) the first time any read happens, never eagerly right after
    /// `open` -- mirrors `VMessSession.readResponseHeader`'s doc comment: a
    /// real server has nothing to send back yet at that point, and reading
    /// it before this session's caller has sent anything (its own request
    /// body, or -- when VLESS sits mid-chain -- the next hop's handshake
    /// bytes) would deadlock against a real server, which only ever writes
    /// its response header piggybacked with the first real data it has to
    /// relay back.
    private func consumeResponseHeader(timeout: TimeInterval?) async throws {
        guard !responseHeaderConsumed else { return }
        // `pendingHeaderBytes` carries the 2-byte header across retries: if
        // a prior call already read it but then threw while reading the
        // addons that follow, those 2 bytes are gone from `conn` for good
        // (already consumed off the wire) -- re-reading them here on retry
        // would actually consume the *next* 2 bytes of real data instead,
        // desyncing every read after. Skipping the re-read once it's cached
        // keeps a retry resuming exactly where the last attempt left off.
        let head: [UInt8]
        if pendingHeaderBytes.isEmpty {
            head = try await conn.readExactly(2, timeout: timeout)
            pendingHeaderBytes = head
        } else {
            head = pendingHeaderBytes
        }
        let addonsLength = Int(head[1])
        if addonsLength > 0 {
            _ = try await conn.readExactly(addonsLength, timeout: timeout)
        }
        // Only marked consumed *after* both reads above actually succeed --
        // otherwise a transient failure (e.g. a timeout because the real
        // server hasn't produced anything yet) would permanently wedge this
        // flag `true` on a header that was never actually read, and a later
        // retry would hand the still-unread header bytes to the caller as
        // ordinary application data instead of ever reading them here.
        responseHeaderConsumed = true
        pendingHeaderBytes = []
    }

    /// Reads raw application bytes coming back from `target` ([] once the stream ends).
    public func receive() async throws -> [UInt8] {
        try await readAvailable(timeout: nil)
    }

    public func readAvailable(timeout: TimeInterval? = nil) async throws -> [UInt8] {
        try await consumeResponseHeader(timeout: timeout ?? 10)
        if !buffered.isEmpty {
            let result = buffered
            buffered = []
            return result
        }
        return try await conn.readAvailable(timeout: timeout)
    }

    /// Exact-length read for a protocol stacked *on top of* this VLESS hop:
    /// buffers across as many underlying `readAvailable` calls as needed,
    /// the same pattern every other `Session.readExactly` here uses.
    public func readExactly(_ n: Int, timeout: TimeInterval? = nil) async throws -> [UInt8] {
        try await consumeResponseHeader(timeout: timeout ?? 10)
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
