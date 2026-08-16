// ChainCore.swift
//
// Combines SOCKS5Core/ShadowsocksCore/VMessCore into an ordered proxy chain,
// in any order and any length: SOCKS5 -> Shadowsocks -> VMess -> target,
// VMess -> SOCKS5 -> target, three Shadowsocks hops in a row, etc.
//
// This module exists only because each protocol's `Session.open(over:)`
// already accepts *any* `ProxyTransport` as what it dials its handshake
// over (see ProxyKit's `ProxyTransport` and each Core module's own
// `open(over:)`/`open(server:)` pair) -- a previous hop's already-open
// `Session` satisfies that just as well as a fresh `TCPConn`. ChainCore is
// just the fold over an ordered hop list that wires that up, plus the one
// piece of chain-specific bookkeeping VMess needs (see `openHop` below).

import Foundation
import ProxyKit
import SOCKS5Core
import ShadowsocksCore
import VMessCore
import TrojanCore
import VLESSCore
import HTTPProxyCore

// MARK: - Hop description

/// Which protocol a hop speaks, and the credentials it needs -- everything
/// about it *except* where it is (see `ProxyHop.host`/`port`) and what it
/// should be asked to reach (determined by the hop's position in the chain,
/// not stored here).
public enum ProxyHopProtocol: Equatable {
    case socks5(auth: SOCKS5Auth = .none)
    case shadowsocks(password: String, cipher: ShadowsocksCipher)
    /// Unlike Trojan/VLESS, VMess's own AEAD handshake/body encryption is a
    /// symmetric pre-shared-key scheme with no forward secrecy or server
    /// authentication -- `tls` opts into wrapping the connection in TLS first
    /// (the common "VMess + WS + TLS" deployment, disguising the traffic as ordinary HTTPS behind a CDN),
    /// same meaning as VLESS's own `tls`. `wsPath` non-`nil` additionally
    /// wraps a WebSocket tunnel between the TLS layer (if any) and the
    /// VMess handshake -- `wsHost` is the WS upgrade request's `Host:`
    /// header, if different from `sni ?? host` (`nil` means use that).
    case vmess(uuid: String, security: VMessSecurity = .auto, tls: Bool = false, sni: String? = nil, allowInsecure: Bool = false, wsPath: String? = nil, wsHost: String? = nil)
    /// `tls` defaults to `true` (Trojan's whole design goal is to look like
    /// ordinary HTTPS) -- `false` opts out for the rarer real-world server
    /// that runs the trojan handshake directly over plain TCP instead (a
    /// `security=none` subscription link; see `TrojanServerConfig.tls`).
    /// `sni` overrides the TLS SNI/certificate hostname sent to the hop's
    /// own `host` (`nil` means "use `host`" -- see `TrojanServerConfig.sni`),
    /// only meaningful when `tls` is `true`. `wsPath`/`wsHost` mean the same
    /// as VMess's own (WS rides between TLS, if any, and Trojan's handshake).
    case trojan(password: String, tls: Bool = true, sni: String? = nil, allowInsecure: Bool = false, wsPath: String? = nil, wsHost: String? = nil)
    /// Unlike Trojan, VLESS's own wire protocol carries no encryption at all
    /// -- `tls` opts into wrapping the connection in TLS before the request
    /// header (the common "VLESS + TLS" deployment); `false` sends the
    /// request, and the fully unencrypted body that follows, directly (see
    /// `VLESSCore`'s own doc comment). `sni`/`allowInsecure` are only
    /// meaningful when `tls` is `true`, same meaning as Trojan's. `wsPath`/
    /// `wsHost` mean the same as VMess's own.
    case vless(uuid: String, tls: Bool = false, sni: String? = nil, allowInsecure: Bool = false, wsPath: String? = nil, wsHost: String? = nil)
    /// A plain HTTP CONNECT proxy (see HTTPProxyCore's `HTTPProxySession`).
    case http(auth: HTTPProxyAuth = .none)
}

/// One link in a proxy chain: a server (`host`/`port`) speaking `protocolConfig`.
/// The first hop is dialed directly over TCP; every later hop is layered on
/// top of the previous hop's already-open session instead of dialing again,
/// so an N-hop chain still rides exactly one real TCP connection (to the
/// first hop's server).
public struct ProxyHop: Equatable {
    public let host: String
    public let port: UInt16
    public let protocolConfig: ProxyHopProtocol

    public init(host: String, port: UInt16, protocolConfig: ProxyHopProtocol) {
        self.host = host
        self.port = port
        self.protocolConfig = protocolConfig
    }
}

extension ProxyHopProtocol {
    /// Short protocol name for log lines -- kept here rather than reusing
    /// Chainy's own UI-facing `displayName` (a different target), since
    /// ChainCore has no dependency on it. `internal` (not `fileprivate`)
    /// since `TunneledUDPRelay.swift` also needs it for its own UDP-relay
    /// error messages.
    var logName: String {
        switch self {
        case .socks5: return "SOCKS5"
        case .shadowsocks: return "Shadowsocks"
        case .vmess: return "VMess"
        case .trojan: return "Trojan"
        case .vless: return "VLESS"
        case .http: return "HTTP"
        }
    }
}

public enum ProxyChainError: Error, Equatable {
    /// `ProxyChain.open` needs at least one hop to dial anything at all.
    case emptyChain
    /// `ShadowsocksUDPRelay.open` needs *every* hop to be Shadowsocks --
    /// unlike TCP chaining, UDP relay in this codebase has no notion of a
    /// mid-chain protocol switch yet (see that type's own doc comment).
    case udpUnsupportedHop(index: Int, protocolName: String)
    /// `ProxyChain.openUDPRelay` needs the *last* hop specifically to
    /// support UDP (VMess/VLESS/Trojan/SOCKS5, or an all-Shadowsocks chain,
    /// which takes priority when it applies).
    case udpUnsupportedLastHop(protocolName: String)
    /// A hop *is* Shadowsocks (so it passes `udpUnsupportedHop`'s check),
    /// but its cipher is a 2022-edition one, whose UDP packet format isn't
    /// implemented yet (TCP-only for now -- see `ShadowsocksCipher.is2022Edition`'s
    /// own doc comment). Refused explicitly rather than silently sealing
    /// with the wrong (2017-only) UDP scheme under a cipher a real 2022
    /// server wouldn't even recognize.
    case udpUnsupported2022Cipher(index: Int, cipherName: String)
}

// MARK: - Chain builder

public enum ProxyChain {
    /// Opens `hops` in order, asking hop *i* to CONNECT to hop *i+1*'s
    /// `host:port` (or, for the last hop, to `finalTargetHost:finalTargetPort`
    /// -- the real destination). Each hop after the first is opened `over`
    /// the previous hop's session rather than dialed fresh, so the whole
    /// chain shares the one real TCP connection made to `hops[0]`.
    ///
    /// Returns the last hop's session, typed as `any ProxyTransport` --
    /// exactly the same shape a single, unchained `Session` already exposes
    /// (`send`/`readAvailable`/`readExactly`/`close`), so callers relay real
    /// application data through a chain exactly like they would through one
    /// protocol alone.
    ///
    /// `onTCPConnected`/`onHandshakeComplete` are optional latency-probe
    /// hooks (both default `nil`, so no existing caller needs to change):
    /// `onTCPConnected` fires the moment the raw TCP socket to `hops[0]`
    /// is up, *before* any protocol handshake runs over it -- except when
    /// the first hop is Trojan dialing fresh, where TCP connect and TLS are
    /// negotiated as one atomic step by Network.framework (see the branch
    /// below), so there's no separate "TCP connected" instant to report and
    /// this callback simply never fires for that case. `onHandshakeComplete`
    /// fires once, right before returning, once every hop's handshake --
    /// the *whole* chain, not just the first hop -- has completed and the
    /// tunnel is ready to relay.
    ///
    /// `logID` (also default `nil`) tags every "Chain"-category log line
    /// below with the caller's own per-connection identifier (e.g.
    /// `LocalProxyServer`'s short UUID prefix) so filtering the Logs view by
    /// that ID surfaces the *whole* story for one connection -- which hop,
    /// which host:port, which stage -- instead of just the generic
    /// `ProxyError.timedOut`/etc. `LocalProxyServer.relay` ends up logging on
    /// a failure too, but only with the bare `Error` it caught, which for a
    /// deadline is nothing more than the case name.
    public static func open(
        hops: [ProxyHop],
        finalTargetHost: String,
        finalTargetPort: UInt16,
        connectTimeout: TimeInterval? = 10,
        logID: String? = nil,
        onTCPConnected: (@Sendable () -> Void)? = nil,
        onHandshakeComplete: (@Sendable () -> Void)? = nil
    ) async throws -> any ProxyTransport {
        guard let first = hops.first else { throw ProxyChainError.emptyChain }
        let logPrefix = logID.map { "[\($0)] " } ?? ""

        let isFirstHopLast = hops.count == 1
        let firstHopTargetHost = isFirstHopLast ? finalTargetHost : hops[1].host
        let firstHopTargetPort = isFirstHopLast ? finalTargetPort : hops[1].port

        var transport: any ProxyTransport
        if case .trojan(let password, let tls, let sni, let allowInsecure, let wsPath, let wsHost) = first.protocolConfig {
            // Trojan as the very first hop dials with TLS (when `tls`)
            // negotiated natively by Network.framework, instead of the
            // generic dial-then-`openHop`-over-Secure-Transport path every
            // other protocol (and Trojan itself when it's *not* the first
            // hop) uses -- see `TrojanSession`'s own doc comment for why:
            // only a fresh dial (this exact case) can use it, and it's been
            // confirmed live to get past an anti-probing filter that
            // otherwise kills Secure Transport's ClientHello for the same
            // node. Logged the same way `openHop`'s own catch below logs
            // every other hop's failure, since this path bypasses it
            // entirely.
            do {
                transport = try await TrojanSession.open(
                    server: TrojanServerConfig(host: first.host, port: first.port, password: password, tls: tls, sni: sni ?? first.host, allowInsecure: allowInsecure, wsPath: wsPath, wsHost: wsHost),
                    targetHost: ProxyAddress.parse(firstHopTargetHost), targetPort: firstHopTargetPort, connectTimeout: connectTimeout
                )
            } catch {
                proxyLog(.warn, "Chain", "\(logPrefix)Hop \(first.host):\(first.port) (\(first.protocolConfig.logName)) failed to reach \(firstHopTargetHost):\(firstHopTargetPort): \(error)")
                throw error
            }
        } else {
            let root = TCPConn(host: first.host, port: first.port)
            do {
                try await root.connect(timeout: connectTimeout)
            } catch {
                // Previously silent: a plain-TCP first hop that never even
                // completes its raw connect (as opposed to connecting fine
                // and then failing its protocol handshake, which `openHop`
                // below already logs) used to propagate this error all the
                // way up with zero context anywhere in the logs.
                proxyLog(.warn, "Chain", "\(logPrefix)Hop \(first.host):\(first.port) (\(first.protocolConfig.logName)): TCP connect failed: \(error)")
                root.close()
                throw error
            }
            onTCPConnected?()
            // `openHop` already logs and rethrows its own failures -- but on
            // failure here the raw TCP connection to `first` that just
            // succeeded above would otherwise never be closed (nothing
            // still references `root` once this function rethrows), leaking
            // one real socket per failed handshake. Closing it here is
            // enough even though `openHop` may have wrapped it in TLS/WS
            // layers first: those only ever wrap `root`, never open a
            // second socket of their own, so tearing down `root` releases
            // whatever got built on top of it too.
            do {
                transport = try await openHop(first, over: root, targetHost: firstHopTargetHost, targetPort: firstHopTargetPort, timeout: connectTimeout, logID: logID)
            } catch {
                root.close()
                throw error
            }
        }

        for index in hops.indices.dropFirst() {
            let isLastHop = index == hops.index(before: hops.endIndex)
            let targetHost = isLastHop ? finalTargetHost : hops[index + 1].host
            let targetPort = isLastHop ? finalTargetPort : hops[index + 1].port

            // Same rationale as the first hop above: if this hop's handshake
            // fails, everything built up through the previous hop (which
            // `openedSoFar` still references) must be closed explicitly, or
            // it leaks -- `close()` cascades down through every wrapped
            // layer to the one real socket at the chain's root.
            let openedSoFar = transport
            do {
                transport = try await openHop(hops[index], over: transport, targetHost: targetHost, targetPort: targetPort, timeout: connectTimeout, logID: logID)
            } catch {
                openedSoFar.close()
                throw error
            }
        }
        onHandshakeComplete?()
        return transport
    }

    /// Opens one hop's session over `transport`, asking it to reach
    /// `targetHost:targetPort` (the next hop's server, or the final
    /// destination for the last hop). `logID` is threaded through purely for
    /// the failure log below -- see `open`'s own doc comment on it.
    private static func openHop(_ hop: ProxyHop, over transport: any ProxyTransport, targetHost: String, targetPort: UInt16, timeout: TimeInterval?, logID: String?) async throws -> any ProxyTransport {
        do {
            switch hop.protocolConfig {
            case .socks5(let auth):
                return try await SOCKS5Session.open(over: transport, auth: auth, targetHost: ProxyAddress.parse(targetHost), targetPort: targetPort, timeout: timeout)

            case .shadowsocks(let password, let cipher):
                return try await ShadowsocksSession.open(over: transport, password: password, cipher: cipher, targetHost: ProxyAddress.parse(targetHost), targetPort: targetPort, timeout: timeout)

            case .vmess(let uuid, let security, let tls, let sni, let allowInsecure, let wsPath, let wsHost):
                // Deliberately *not* reading/validating VMess's AEAD response
                // header here (unlike SOCKS5's CONNECT reply, fully consumed by
                // the time `open` returns): a real server has nothing to send
                // back yet at this point -- there's no
                // separate handshake ack, the response header only arrives
                // piggybacked with the first real response data. Consuming it
                // eagerly here deadlocks against a real server (confirmed
                // against xray-core; see the doc comment on
                // `VMessSession.readResponseHeader`), since nothing has been
                // sent yet for it to relay -- neither this caller's own request
                // body nor, when VMess sits mid-chain, the *next* hop's
                // handshake bytes. `VMessSession` itself now reads it lazily on
                // the first `readAvailable`/`readExactly` call instead, by
                // which point the next hop's handshake (or the terminal
                // caller's own send) has already produced something to relay.
                return try await VMessSession.open(
                    over: transport, uuid: uuid, target: VMessTarget(host: targetHost, port: targetPort), security: security,
                    tls: tls, sni: sni ?? hop.host, allowInsecure: allowInsecure, wsPath: wsPath, wsHost: wsHost, timeout: timeout
                )

            case .trojan(let password, let tls, let sni, let allowInsecure, let wsPath, let wsHost):
                return try await TrojanSession.open(
                    over: transport, password: password, tls: tls, sni: sni ?? hop.host, allowInsecure: allowInsecure,
                    wsPath: wsPath, wsHost: wsHost,
                    targetHost: ProxyAddress.parse(targetHost), targetPort: targetPort, timeout: timeout
                )

            case .vless(let uuid, let tls, let sni, let allowInsecure, let wsPath, let wsHost):
                // Same lazy-response-header rationale as `.vmess` above:
                // `VLESSSession` itself only reads it on the first
                // `readAvailable`/`readExactly` call, never eagerly here.
                return try await VLESSSession.open(
                    over: transport, uuid: uuid, target: VLESSTarget(host: targetHost, port: targetPort),
                    tls: tls, sni: sni ?? hop.host, allowInsecure: allowInsecure, wsPath: wsPath, wsHost: wsHost, timeout: timeout
                )

            case .http(let auth):
                return try await HTTPProxySession.open(over: transport, auth: auth, targetHost: targetHost, targetPort: targetPort, timeout: timeout)
            }
        } catch {
            let logPrefix = logID.map { "[\($0)] " } ?? ""
            proxyLog(.warn, "Chain", "\(logPrefix)Hop \(hop.host):\(hop.port) (\(hop.protocolConfig.logName)) failed to reach \(targetHost):\(targetPort): \(error)")
            throw error
        }
    }
}

// MARK: - UDP relay (Shadowsocks-only chains)

/// Relays UDP datagrams through a chain of Shadowsocks hops -- the local
/// SOCKS5 UDP ASSOCIATE listener's counterpart to `ProxyChain.open`/
/// `openHop` for TCP, but structured very differently: a real Shadowsocks
/// server never re-encrypts or inspects the payload it relays (it just does
/// a raw `sendto(payload, addr:port)` once it decrypts a packet's embedded
/// target), so chaining N of them needs no transport-layering at all --
/// just **one real UDP socket, to `hops[0]`**, carrying a packet nested N
/// times: build outward from the innermost layer (the real final target and
/// raw payload), wrapping each layer with that hop's own encryption
/// addressed at the *next* hop (or the real target, for the last hop).
/// Receiving is the symmetric peel, `hops[0]` through `hops[hops.count-1]`
/// in order.
///
/// Restricted to chains where *every* hop is `.shadowsocks` -- `open` throws
/// `ProxyChainError.udpUnsupportedHop` for anything else (mirroring
/// `SOCKS5Server.acceptRequest`'s own command-not-supported handling one
/// layer up, in `LocalProxyServer`). A mixed chain ending in Shadowsocks is
/// refused rather than silently only
/// tunneling through the Shadowsocks prefix of it.
public final class ShadowsocksUDPRelay {
    /// One validated hop: its Shadowsocks credentials plus where it is --
    /// captured once in `open` so `send`/`receive` never need to re-switch
    /// on `ProxyHopProtocol` (and can't ever hit a "hop wasn't Shadowsocks"
    /// case the type system doesn't already rule out).
    private struct Hop {
        let password: String
        let cipher: ShadowsocksCipher
        let host: String
        let port: UInt16
    }

    private let hops: [Hop]
    private let transport: any DatagramTransport

    private init(hops: [Hop], transport: any DatagramTransport) {
        self.hops = hops
        self.transport = transport
    }

    /// Validates every hop, then opens exactly one `UDPConn` to `hops[0]`.
    /// `makeTransport` is an injectable seam (defaults to a real `UDPConn`,
    /// connected before being handed back) so tests can fake the datagram
    /// socket the same way `ByteStreamSource`/`ByteStreamSink` fakes already
    /// drive the TCP path's tests.
    public static func open(
        hops: [ProxyHop],
        connectTimeout: TimeInterval? = 10,
        logID: String? = nil,
        makeTransport: ((ProxyHop) async throws -> any DatagramTransport)? = nil
    ) async throws -> ShadowsocksUDPRelay {
        guard let first = hops.first else { throw ProxyChainError.emptyChain }
        let logPrefix = logID.map { "[\($0)] " } ?? ""

        var validatedHops: [Hop] = []
        for (index, hop) in hops.enumerated() {
            guard case .shadowsocks(let password, let cipher) = hop.protocolConfig else {
                proxyLog(.warn, "Chain", "\(logPrefix)UDP relay refused: hop \(index) (\(hop.protocolConfig.logName)) does not support UDP")
                throw ProxyChainError.udpUnsupportedHop(index: index, protocolName: hop.protocolConfig.logName)
            }
            guard !cipher.is2022Edition else {
                proxyLog(.warn, "Chain", "\(logPrefix)UDP relay refused: hop \(index) uses 2022-edition cipher \(cipher.rawValue), UDP not yet implemented for it")
                throw ProxyChainError.udpUnsupported2022Cipher(index: index, cipherName: cipher.rawValue)
            }
            validatedHops.append(Hop(password: password, cipher: cipher, host: hop.host, port: hop.port))
        }

        let transport: any DatagramTransport
        if let makeTransport {
            transport = try await makeTransport(first)
        } else {
            let conn = UDPConn(host: first.host, port: first.port)
            try await conn.connect(timeout: connectTimeout)
            transport = conn
        }
        return ShadowsocksUDPRelay(hops: validatedHops, transport: transport)
    }

    /// Sends one datagram toward `targetHost:targetPort` (the real, final
    /// destination -- not any hop's own address). Each call can target a
    /// different destination, same as a real SOCKS5 UDP ASSOCIATE session.
    public func send(targetHost: String, targetPort: UInt16, payload: [UInt8], timeout: TimeInterval? = nil) async throws {
        var wrapped = payload
        var target = ProxyAddress.parse(targetHost)
        var port = targetPort
        for hop in hops.reversed() {
            wrapped = try shadowsocksSealUDPPacket(password: hop.password, cipher: hop.cipher, targetHost: target, targetPort: port, payload: wrapped)
            target = ProxyAddress.parse(hop.host)
            port = hop.port
        }
        try await transport.send(wrapped, timeout: timeout)
    }

    /// Receives one datagram and peels every hop's layer in order,
    /// returning the last (innermost) layer's embedded address -- the real
    /// remote address that actually replied -- alongside the raw payload.
    public func receive(timeout: TimeInterval? = nil) async throws -> (fromHost: String, fromPort: UInt16, payload: [UInt8]) {
        var packet = try await transport.receiveDatagram(timeout: timeout)
        var fromHost = ""
        var fromPort: UInt16 = 0
        for hop in hops {
            let (address, port, inner) = try shadowsocksOpenUDPPacket(password: hop.password, cipher: hop.cipher, packet: packet)
            fromHost = address.displayHost
            fromPort = port
            packet = inner
        }
        return (fromHost, fromPort, packet)
    }

    public func close() { transport.close() }
}
