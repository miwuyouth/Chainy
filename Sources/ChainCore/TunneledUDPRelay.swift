// TunneledUDPRelay.swift
//
// UDP relay for a chain whose *last* hop is VMess or VLESS -- unlike
// Shadowsocks (a separate physical UDP socket, see `ShadowsocksUDPRelay` in
// ChainCore.swift), VMess/VLESS UDP rides the *same* TCP/TLS tunnel their
// TCP relay already uses: the request header (sent once, at handshake time)
// bakes in Command=UDP and *one* target address+port, then the body is
// framed into per-datagram chunks over that stream instead of being a raw
// pipe. That has two consequences:
//
//   1. Earlier hops (`hops.dropLast()`) are plain TCP CONNECT tunnel
//      -building, identical to the TCP path -- `ProxyChain.open` already
//      handles any protocol mix/length for that, unmodified. Only the last
//      hop needs to actually support UDP, unlike Shadowsocks' "every hop
//      must match" restriction.
//   2. One physical tunnel only ever reaches *one* destination (the request
//      header names it once) -- unlike Shadowsocks/SOCKS5-ASSOCIATE's "any
//      destination per packet". So this type keeps a small per-target
//      session table, dialing a fresh tunnel the first time a given
//      (targetHost, targetPort) is seen and reusing it for later packets to
//      that same target. There is no idle-expiry for a still-open
//      association -- every per-target tunnel is torn down together when
//      the whole association ends (`close()`), same scope decision as
//      `ShadowsocksUDPRelay`.
//
// VLESS uses `[UInt16 BE length][datagram]` inside its otherwise-plain body.
// VMess does not add that inner prefix: its existing authenticated body-chunk
// boundary *is* the UDP datagram boundary. Adding another length here sends
// those two bytes to the destination as payload (e.g. corrupting DNS).

import Foundation
import os
import ProxyKit
import VMessCore
import VLESSCore
import TrojanCore

// MARK: - Shared relay interface

/// What `LocalProxyServer`'s UDP ASSOCIATE pump loop needs from either UDP
/// relay mechanism this codebase has -- `ShadowsocksUDPRelay` (ChainCore.swift)
/// and `TunneledUDPRelay` (this file) both conform, so the pump loop and its
/// caller never need to know which one is actually in play.
public protocol UDPRelay {
    func send(targetHost: String, targetPort: UInt16, payload: [UInt8], timeout: TimeInterval?) async throws
    func receive(timeout: TimeInterval?) async throws -> (fromHost: String, fromPort: UInt16, payload: [UInt8])
    func close()
}

extension ShadowsocksUDPRelay: UDPRelay {}

// MARK: - Dispatch

extension ProxyChain {
    /// Picks whichever UDP relay mechanism `hops` actually supports:
    /// an all-Shadowsocks chain (`ShadowsocksUDPRelay`, checked first since
    /// it's the more capable case -- every hop actually relays UDP, not just
    /// the last one), else a chain whose *last* hop is VMess/VLESS
    /// (`TunneledUDPRelay`, any protocol mix before it) or Trojan
    /// (`TrojanUDPRelay`, same "any protocol mix before it" rule), else
    /// refuses with `ProxyChainError.udpUnsupportedLastHop`.
    public static func openUDPRelay(hops: [ProxyHop], connectTimeout: TimeInterval? = 10, logID: String? = nil) async throws -> any UDPRelay {
        guard let last = hops.last else { throw ProxyChainError.emptyChain }

        let allShadowsocks = hops.allSatisfy {
            if case .shadowsocks = $0.protocolConfig { return true }
            return false
        }
        if allShadowsocks {
            return try await ShadowsocksUDPRelay.open(hops: hops, connectTimeout: connectTimeout, logID: logID)
        }

        switch last.protocolConfig {
        case .vmess, .vless:
            return try TunneledUDPRelay.open(hops: hops, connectTimeout: connectTimeout, logID: logID)
        case .trojan:
            return try await TrojanUDPRelay.open(hops: hops, connectTimeout: connectTimeout, logID: logID)
        default:
            let logPrefix = logID.map { "[\($0)] " } ?? ""
            proxyLog(.warn, "Chain", "\(logPrefix)UDP relay refused: last hop (\(last.protocolConfig.logName)) does not support UDP")
            throw ProxyChainError.udpUnsupportedLastHop(protocolName: last.protocolConfig.logName)
        }
    }
}

// MARK: - Length-prefixed datagram framing

/// `[UInt16 BE length][datagram]`, layered purely as bytes over any already
/// -open `ProxyTransport` -- see this file's own top comment for what this
/// is (and isn't yet) confirmed against.
enum LengthPrefixedDatagram {
    enum FramingError: Error, Equatable { case datagramTooLarge }

    static func send(_ payload: [UInt8], over transport: any ProxyTransport, timeout: TimeInterval?) async throws {
        guard let length = UInt16(exactly: payload.count) else { throw FramingError.datagramTooLarge }
        try await transport.send(length.bigEndianBytes + payload, timeout: timeout)
    }

    static func receiveOne(over transport: any ProxyTransport, timeout: TimeInterval?) async throws -> [UInt8] {
        let lengthBytes = try await transport.readExactly(2, timeout: timeout)
        let length = Int(lengthBytes[0]) << 8 | Int(lengthBytes[1])
        return try await transport.readExactly(length, timeout: timeout)
    }
}

// MARK: - TunneledUDPRelay

public final class TunneledUDPRelay: UDPRelay {
    private enum DatagramFraming { case vmessBodyChunk, lengthPrefixed }
    private struct TargetKey: Hashable { let host: String; let port: UInt16 }
    private struct Tunnel {
        let session: any ProxyTransport
        let task: Task<Void, Never>
    }

    private let hops: [ProxyHop]
    private let connectTimeout: TimeInterval?
    private let logID: String?
    private let framing: DatagramFraming
    /// Guards `tunnels` against `close()` racing `send()`/`pumpReplies` --
    /// `LocalProxyServer`'s task group calls `close()` from a different task
    /// than the one looping `send()`, the instant any one of its three
    /// concurrent tasks ends (see its own doc comment on `relayUDPAssociate`).
    private let tunnels = OSAllocatedUnfairLock<[TargetKey: Tunnel]>(initialState: [:])
    private let incoming: AsyncStream<(fromHost: String, fromPort: UInt16, payload: [UInt8])>
    private let incomingContinuation: AsyncStream<(fromHost: String, fromPort: UInt16, payload: [UInt8])>.Continuation

    private init(hops: [ProxyHop], connectTimeout: TimeInterval?, logID: String?, framing: DatagramFraming) {
        self.hops = hops
        self.connectTimeout = connectTimeout
        self.logID = logID
        self.framing = framing
        var continuation: AsyncStream<(fromHost: String, fromPort: UInt16, payload: [UInt8])>.Continuation!
        incoming = AsyncStream { continuation = $0 }
        incomingContinuation = continuation
    }

    /// Validates the last hop is VMess or VLESS -- doesn't dial anything
    /// yet, since dialing happens lazily, per target, on first `send`.
    public static func open(hops: [ProxyHop], connectTimeout: TimeInterval? = 10, logID: String? = nil) throws -> TunneledUDPRelay {
        guard let last = hops.last else { throw ProxyChainError.emptyChain }
        switch last.protocolConfig {
        case .vmess:
            return TunneledUDPRelay(hops: hops, connectTimeout: connectTimeout, logID: logID, framing: .vmessBodyChunk)
        case .vless:
            return TunneledUDPRelay(hops: hops, connectTimeout: connectTimeout, logID: logID, framing: .lengthPrefixed)
        default:
            throw ProxyChainError.udpUnsupportedLastHop(protocolName: last.protocolConfig.logName)
        }
    }

    /// Looks up (or dials, on first use) the tunnel for `targetHost:targetPort`,
    /// then writes `payload` as one length-prefixed chunk over it.
    ///
    /// For a freshly-dialed tunnel, the first `send` happens *before*
    /// `pumpReplies`'s background task is started, not after -- confirmed
    /// necessary against a real deadlock: when the last hop is VLESS with
    /// TLS (the only UDP-capable last hop that bridges through `TLSConn`'s
    /// single serial `ioQueue`, unlike a plain `NWConnection`, which reads
    /// and writes independently), spawning `pumpReplies` first lets its
    /// `receiveOne(timeout: nil)` -- an *unbounded* blocking read -- win the
    /// race for that one queue before this method's own send ever runs.
    /// Since nothing has been sent yet, the server has nothing to reply
    /// with, so that read blocks forever, permanently starving the queued-up
    /// send behind it; only the send's own outer timeout eventually fires,
    /// surfacing as `ProxyError.timedOut` with no data ever having moved.
    /// Sending first removes the race for the call that matters (the one
    /// this session's whole tunnel exists to make): the pump only ever
    /// starts *after* the server has something to reply to.
    public func send(targetHost: String, targetPort: UInt16, payload: [UInt8], timeout: TimeInterval? = nil) async throws {
        let key = TargetKey(host: targetHost, port: targetPort)
        let existing = tunnels.withLock { $0[key]?.session }
        if let existing {
            try await sendDatagram(payload, over: existing, timeout: timeout)
            return
        }

        // Dialing is async and can't happen while the lock is held --
        // `LocalProxyServer`'s actual usage never calls `send` for the
        // same not-yet-open target concurrently, so this doesn't need
        // to handle a duplicate-dial race for the same key.
        let session = try await dial(targetHost: targetHost, targetPort: targetPort)
        try await sendDatagram(payload, over: session, timeout: timeout)
        let task = Task { [weak self] in
            guard let self else { return }
            await self.pumpReplies(key: key, session: session)
        }
        tunnels.withLock { $0[key] = Tunnel(session: session, task: task) }
    }

    private func sendDatagram(_ payload: [UInt8], over session: any ProxyTransport, timeout: TimeInterval?) async throws {
        switch framing {
        case .vmessBodyChunk:
            try await session.send(payload, timeout: timeout)
        case .lengthPrefixed:
            try await LengthPrefixedDatagram.send(payload, over: session, timeout: timeout)
        }
    }

    /// Pulls the next datagram off whichever per-target tunnel produced one
    /// first -- every open tunnel's own background read loop
    /// (`pumpReplies`) feeds this same stream. Races that against `timeout`
    /// (when given) using a second child task rather than trusting
    /// `incoming`'s iteration to notice cancellation on its own -- every
    /// existing caller/test always got a reply before this needed proving,
    /// so a prior version of this method silently ignored `timeout`
    /// entirely and blocked forever on a target that never replies (a real
    /// VMess/VLESS server ignoring this client's own UDP body framing, or a
    /// blocked network path). See `ReceiveOutcome`'s cases for why a plain
    /// `Optional` return from each child task isn't enough to tell "the
    /// stream itself ended" apart from "the timeout task won the race".
    public func receive(timeout: TimeInterval? = nil) async throws -> (fromHost: String, fromPort: UInt16, payload: [UInt8]) {
        guard let timeout else {
            for await item in incoming { return item }
            throw ProxyError.connectionClosed
        }
        let outcome = try await withThrowingTaskGroup(of: ReceiveOutcome.self) { group -> ReceiveOutcome in
            group.addTask {
                for await item in self.incoming { return .item(item) }
                return .streamEnded
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                return .timedOut
            }
            let first = try await group.next() ?? .streamEnded
            group.cancelAll()
            return first
        }
        switch outcome {
        case .item(let item): return item
        case .streamEnded: throw ProxyError.connectionClosed
        case .timedOut: throw ProxyError.timedOut
        }
    }

    private enum ReceiveOutcome {
        case item((fromHost: String, fromPort: UInt16, payload: [UInt8]))
        case streamEnded
        case timedOut
    }

    public func close() {
        let closed = tunnels.withLock { dict -> [Tunnel] in
            let values = Array(dict.values)
            dict.removeAll()
            return values
        }
        for tunnel in closed {
            tunnel.session.close()
            tunnel.task.cancel()
        }
        incomingContinuation.finish()
    }

    /// Builds a fresh tunnel to `targetHost:targetPort`: a plain TCP chain
    /// through every hop but the last (reusing `ProxyChain.open` verbatim
    /// when there's more than one hop -- any protocol mix, exactly like the
    /// TCP relay path), then the last hop's own session opened in UDP mode
    /// with `targetHost:targetPort` as its one baked-in destination.
    private func dial(targetHost: String, targetPort: UInt16) async throws -> any ProxyTransport {
        let last = hops[hops.count - 1]
        let earlierHops = Array(hops.dropLast())
        let logPrefix = logID.map { "[\($0)] " } ?? ""

        do {
            let transport: any ProxyTransport
            if earlierHops.isEmpty {
                let conn = TCPConn(host: last.host, port: last.port)
                try await conn.connect(timeout: connectTimeout)
                transport = conn
            } else {
                transport = try await ProxyChain.open(
                    hops: earlierHops, finalTargetHost: last.host, finalTargetPort: last.port,
                    connectTimeout: connectTimeout, logID: logID
                )
            }

            do {
                switch last.protocolConfig {
                case .vmess(let uuid, let tls, let sni, let allowInsecure, let wsPath, let wsHost):
                    return try await VMessSession.open(
                        over: transport, uuid: uuid, target: VMessTarget(host: targetHost, port: targetPort),
                        command: VMessRequest.commandUDP,
                        tls: tls, sni: sni ?? last.host, allowInsecure: allowInsecure, wsPath: wsPath, wsHost: wsHost,
                        timeout: connectTimeout
                    )
                case .vless(let uuid, let tls, let sni, let allowInsecure, let wsPath, let wsHost):
                    return try await VLESSSession.open(
                        over: transport, uuid: uuid, target: VLESSTarget(host: targetHost, port: targetPort),
                        tls: tls, sni: sni ?? last.host, allowInsecure: allowInsecure, wsPath: wsPath, wsHost: wsHost,
                        command: VLESSCommand.udp, timeout: connectTimeout
                    )
                default:
                    // Unreachable: `open` above already validated the last hop.
                    throw ProxyChainError.udpUnsupportedLastHop(protocolName: last.protocolConfig.logName)
                }
            } catch {
                // `transport` (a freshly connected `TCPConn`, or a whole
                // already-open earlier-hop chain from `ProxyChain.open`
                // above) would otherwise leak here -- same fix as
                // `ProxyChain.open`'s own hop-composition catches.
                transport.close()
                throw error
            }
        } catch {
            proxyLog(.warn, "Chain", "\(logPrefix)UDP relay: failed to open a tunnel to \(targetHost):\(targetPort) via last hop \(last.host):\(last.port) (\(last.protocolConfig.logName)): \(error)")
            throw error
        }
    }

    /// **Known remaining limitation** (not fixed by the reordering in `send`
    /// above): this loop's `receiveOne(timeout: nil)` blocks indefinitely,
    /// which is fine for a plain `NWConnection` (VMess's case -- reads and
    /// writes are independent) but not for a session that serializes *all*
    /// I/O onto one queue, as `TLSConn` does for VLESS-with-TLS (`SSLContext`
    /// isn't safe to call into concurrently -- see that type's own doc
    /// comment): once this loop is running, a *second* (or later) `send` to
    /// the same already-open target can still starve behind this indefinite
    /// read forever, timing out well past its own caller-supplied deadline.
    /// `send` above only guarantees the *first* send for a newly-dialed
    /// target completes before this loop is ever started -- confirmed
    /// necessary (and sufficient for that one case) against a real xray-core
    /// VLESS server via `Tests/InteropTests`, which exercises exactly one
    /// round trip per chain and so doesn't hit this deeper issue.
    ///
    /// A bounded/polling timeout here looks like the fix, but isn't: every
    /// `ProxyTransport` in this codebase treats a read timeout as "the
    /// connection is now dead" (see `TCPConn.receiveChunk`'s `onTimeout:
    /// { self.connection.cancel() }`), not "try again later" -- so polling
    /// would tear down the very session it's trying to keep alive on the
    /// first idle poll. A real fix needs either a transport that supports
    /// genuinely concurrent read/write, or restructuring this relay to never
    /// let a send and this loop's read compete for the same queue at all --
    /// out of scope for the interop-test-suite work that found this; flagged
    /// here rather than silently left for someone to rediscover as a
    /// mystery hang.
    private func pumpReplies(key: TargetKey, session: any ProxyTransport) async {
        while true {
            do {
                let payload: [UInt8]
                switch framing {
                case .vmessBodyChunk:
                    payload = try await session.readAvailable(timeout: nil)
                    if payload.isEmpty { return }
                case .lengthPrefixed:
                    payload = try await LengthPrefixedDatagram.receiveOne(over: session, timeout: nil)
                }
                incomingContinuation.yield((fromHost: key.host, fromPort: key.port, payload: payload))
            } catch {
                return
            }
        }
    }
}

// MARK: - TrojanUDPRelay

/// UDP relay for a chain whose last hop is Trojan -- unlike VMess/VLESS
/// (`TunneledUDPRelay`, above), Trojan names its destination on *every*
/// frame rather than baking one target into the request header, so one
/// session can relay to arbitrarily many destinations: no per-target
/// session table, no fan-in stream, just one eagerly-opened session (same
/// eager-dial style as `ShadowsocksUDPRelay`) plus `TrojanCore`'s own
/// spec-accurate per-packet frame codec (`trojanUDPFrame`/`readTrojanUDPFrame`).
public final class TrojanUDPRelay: UDPRelay {
    private let session: any ProxyTransport

    private init(session: any ProxyTransport) { self.session = session }

    /// Validates the last hop is Trojan, builds a tunnel to reach it (any
    /// protocol mix before it, reusing `ProxyChain.open` exactly like
    /// `TunneledUDPRelay.dial` does), then opens that hop's session with
    /// `command: .udpAssociate` and a dummy target (real destinations are
    /// named per-frame afterward, not in this one-time request line).
    ///
    /// For a single-hop chain, dials with Network.framework's own native
    /// TLS (`TrojanSession.open(server:)`) rather than the generic
    /// `open(over:)` (`TLSConn`'s Secure Transport bridge) -- mirroring
    /// `ProxyChain.open`'s own first-hop special case for Trojan, confirmed
    /// live to get past an anti-probing filter that kills a Secure
    /// Transport ClientHello for the same node. Skipping this here would
    /// silently reintroduce that exact failure for a single-hop Trojan UDP chain.
    public static func open(hops: [ProxyHop], connectTimeout: TimeInterval? = 10, logID: String? = nil) async throws -> TrojanUDPRelay {
        guard let last = hops.last else { throw ProxyChainError.emptyChain }
        guard case .trojan(let password, let tls, let sni, let allowInsecure, let wsPath, let wsHost) = last.protocolConfig else {
            throw ProxyChainError.udpUnsupportedLastHop(protocolName: last.protocolConfig.logName)
        }
        let earlierHops = Array(hops.dropLast())
        let logPrefix = logID.map { "[\($0)] " } ?? ""

        do {
            let session: TrojanSession
            if earlierHops.isEmpty {
                session = try await TrojanSession.open(
                    server: TrojanServerConfig(host: last.host, port: last.port, password: password, tls: tls, sni: sni ?? last.host, allowInsecure: allowInsecure, wsPath: wsPath, wsHost: wsHost),
                    targetHost: .ipv4([0, 0, 0, 0]), targetPort: 0,
                    command: TrojanCommand.udpAssociate, connectTimeout: connectTimeout
                )
            } else {
                let transport = try await ProxyChain.open(
                    hops: earlierHops, finalTargetHost: last.host, finalTargetPort: last.port,
                    connectTimeout: connectTimeout, logID: logID
                )
                do {
                    session = try await TrojanSession.open(
                        over: transport, password: password, tls: tls, sni: sni ?? last.host, allowInsecure: allowInsecure,
                        wsPath: wsPath, wsHost: wsHost,
                        targetHost: .ipv4([0, 0, 0, 0]), targetPort: 0,
                        command: TrojanCommand.udpAssociate, timeout: connectTimeout
                    )
                } catch {
                    // `transport` (the already-open earlier-hop chain from
                    // `ProxyChain.open` above) would otherwise leak here --
                    // same fix as `ProxyChain.open`'s own hop-composition
                    // catches.
                    transport.close()
                    throw error
                }
            }
            return TrojanUDPRelay(session: session)
        } catch {
            proxyLog(.warn, "Chain", "\(logPrefix)UDP relay: failed to open a Trojan UDP session to \(last.host):\(last.port): \(error)")
            throw error
        }
    }

    public func send(targetHost: String, targetPort: UInt16, payload: [UInt8], timeout: TimeInterval? = nil) async throws {
        let frame = try trojanUDPFrame(target: ProxyAddress.parse(targetHost), targetPort: targetPort, payload: payload)
        try await session.send(frame, timeout: timeout)
    }

    public func receive(timeout: TimeInterval? = nil) async throws -> (fromHost: String, fromPort: UInt16, payload: [UInt8]) {
        let (target, port, payload) = try await readTrojanUDPFrame(from: session, timeout: timeout)
        return (target.displayHost, port, payload)
    }

    public func close() { session.close() }
}
