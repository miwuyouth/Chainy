// LocalProxyServer.swift
//
// The relay engine behind the Dashboard's Connect/Disconnect: binds a local
// mixed SOCKS5/HTTP listener, and for every accepted connection, sniffs
// which protocol that specific client is speaking (see `relay`'s first-byte
// check) and reads its CONNECT request in that protocol (an arbitrary
// per-connection destination -- a browser tab, curl, whatever's pointed at
// this port) and relays it through the currently-configured chain to
// wherever that one connection asked to go. Not an `ObservableObject`:
// `AppStore` is the only object views observe, and mirrors this type's state
// into its own `@Published` properties.

import Foundation
import os
import ProxyKit
import SOCKS5Core
import HTTPProxyCore
import ChainCore

/// Running upload/download byte totals for the live relay, incremented from
/// the `pump` hot path (see `pumpBothDirections`) which deliberately runs
/// off the MainActor -- see that function's own doc comment on why a
/// MainActor hop per chunk isn't safe here. `OSAllocatedUnfairLock` keeps
/// each increment to a single uncontended lock/unlock, cheap enough not to
/// reintroduce that same contention. `AppStore` polls `snapshot()` on a
/// timer (roughly once a second) rather than being pushed to per chunk, to
/// derive Overview's "Live Throughput" rate.
private final class RelayByteCounter: @unchecked Sendable {
    private struct Counts { var upload: UInt64 = 0; var download: UInt64 = 0 }
    private let state = OSAllocatedUnfairLock(initialState: Counts())

    func addUpload(_ n: Int) { state.withLock { $0.upload += UInt64(n) } }
    func addDownload(_ n: Int) { state.withLock { $0.download += UInt64(n) } }
    func snapshot() -> (upload: UInt64, download: UInt64) { state.withLock { ($0.upload, $0.download) } }
    func reset() { state.withLock { $0 = Counts() } }
}

/// Cumulative count of every relayed connection attempt (every accepted
/// local socket that reaches `relay`) versus how many of those failed
/// specifically with `ProxyError.timedOut`, as opposed to any other failure
/// (connection refused, TLS failure, protocol handshake error, etc.) --
/// feeds Overview's timeout-rate tile and chart. Same off-MainActor locking
/// pattern as `RelayByteCounter`, for the same reason: incremented from the
/// same `relay` hot path.
private final class ConnectionOutcomeCounter: @unchecked Sendable {
    private struct Counts { var total: UInt64 = 0; var timedOut: UInt64 = 0 }
    private let state = OSAllocatedUnfairLock(initialState: Counts())

    func recordAttempt() { state.withLock { $0.total += 1 } }
    func recordTimeout() { state.withLock { $0.timedOut += 1 } }
    func snapshot() -> (total: UInt64, timedOut: UInt64) { state.withLock { ($0.total, $0.timedOut) } }
    func reset() { state.withLock { $0 = Counts() } }
}

/// Which local-facing relay shape a connection is: a single fixed-destination
/// byte pipe (SOCKS5 CONNECT or HTTP CONNECT), or a SOCKS5 UDP ASSOCIATE
/// session (arbitrary destination per datagram). Feeds the Connections
/// panel's TYPE column.
public enum ConnectionKind: Equatable {
    case tcp
    case udp
}

/// A snapshot of one relayed connection -- live (`endedAt == nil`) or final,
/// once closed -- as listed by the Connections panel. `destination` for a
/// UDP association is whichever target the most recent datagram went to
/// (see `ConnectionStats.setDestination`), since one ASSOCIATE session can
/// carry datagrams to many different destinations over its life, unlike a
/// TCP CONNECT's single fixed target.
public struct ConnectionInfo: Identifiable, Equatable {
    public let id: UUID
    public let kind: ConnectionKind
    public let destination: String
    public let chainName: String
    public let startedAt: Date
    public let endedAt: Date?
    public let uploadBytes: UInt64
    public let downloadBytes: UInt64

    /// How long this connection has been (or was) open -- against `Date()`
    /// for a still-live row (`endedAt == nil`), against its actual `endedAt`
    /// otherwise. A real per-row value rather than sorting the Connections
    /// panel's DURATION column by `startedAt` directly: for a live row,
    /// duration is a *decreasing* function of `startedAt` (older start =
    /// longer duration), so a `startedAt`-keyed sort reads backwards; for a
    /// closed row, `endedAt` varies independently per row, so `startedAt`
    /// alone doesn't even track duration consistently at all.
    public var durationSeconds: TimeInterval {
        (endedAt ?? Date()).timeIntervalSince(startedAt)
    }
}

/// Per-connection counterpart to `RelayByteCounter` above -- same
/// off-MainActor, `OSAllocatedUnfairLock`-protected pattern, but one instance
/// per connection instead of shared globally, so unlike `RelayByteCounter`
/// these are never contended between connections (only ever touched by that
/// one connection's own relay/pump task, and polled by `AppStore` for the
/// Connections panel).
private final class ConnectionStats: @unchecked Sendable {
    private struct State {
        var kind: ConnectionKind = .tcp
        var destination: String = ""
        var upload: UInt64 = 0
        var download: UInt64 = 0
    }
    private let state = OSAllocatedUnfairLock(initialState: State())

    func setDestination(_ kind: ConnectionKind, _ destination: String) {
        state.withLock { $0.kind = kind; $0.destination = destination }
    }
    func addUpload(_ n: Int) { state.withLock { $0.upload += UInt64(n) } }
    func addDownload(_ n: Int) { state.withLock { $0.download += UInt64(n) } }
    func snapshot() -> (kind: ConnectionKind, destination: String, upload: UInt64, download: UInt64) {
        state.withLock { ($0.kind, $0.destination, $0.upload, $0.download) }
    }
}

@MainActor
final class LocalProxyServer {
    enum ServerError: Error, Equatable { case alreadyRunning }

    private(set) var isRunning = false
    private(set) var boundPort: UInt16?

    private var listener: TCPListener?
    private var hops: [ProxyHop] = []
    private var activeChainName = ""
    private var activeConnections: [UUID: ActiveConnection] = [:] {
        didSet { onConnectionCountChanged?(activeConnections.count) }
    }
    /// Bounded history of finished connections for the Connections panel's
    /// "Closed" toggle -- capped at `closedConnectionHistoryLimit`, oldest
    /// evicted first, reset on every fresh `start()` (same lifetime as
    /// `byteCounter`/`outcomeCounter`).
    private var closedConnections: [ConnectionInfo] = []
    private static let closedConnectionHistoryLimit = 200
    private var onUnexpectedStop: ((Error) -> Void)?
    private var onConnectionCountChanged: ((Int) -> Void)?
    private let byteCounter = RelayByteCounter()
    private let outcomeCounter = ConnectionOutcomeCounter()

    private final class ActiveConnection {
        let task: Task<Void, Never>
        let localConn: TCPConn
        var outbound: (any ProxyTransport)?
        let chainName: String
        let stats: ConnectionStats
        let startedAt = Date()
        init(task: Task<Void, Never>, localConn: TCPConn, chainName: String, stats: ConnectionStats) {
            self.task = task
            self.localConn = localConn
            self.chainName = chainName
            self.stats = stats
        }
    }

    /// Starts listening on `port`, relaying every accepted connection
    /// through `hops`. `allowLAN` binds every interface instead of just
    /// loopback, so another device on the same network can dial in (see
    /// `TCPListener.init`). Live relayed traffic is never rate-limited --
    /// the "Speed Test Size" setting only throttles the Test Bandwidth probe
    /// (see `AppStore.performBandwidthProbe`), not this listener.
    /// `onUnexpectedStop` fires if the listener fails after having already
    /// started successfully (e.g. the interface goes away) -- a deliberate
    /// `stop()` call never triggers it. `onConnectionCountChanged` fires
    /// with the live count of relaying connections every time one is
    /// accepted or finishes, so callers (the Overview screen's "Active
    /// Connections" stat) can mirror a real number instead of a
    /// placeholder.
    func start(port: UInt16, hops: [ProxyHop], chainName: String, allowLAN: Bool = false, onUnexpectedStop: @escaping (Error) -> Void, onConnectionCountChanged: ((Int) -> Void)? = nil) async throws -> UInt16 {
        guard !isRunning else { throw ServerError.alreadyRunning }
        self.hops = hops
        self.activeChainName = chainName
        self.onUnexpectedStop = onUnexpectedStop
        self.onConnectionCountChanged = onConnectionCountChanged
        byteCounter.reset()
        outcomeCounter.reset()
        closedConnections.removeAll()

        let listener: TCPListener
        do {
            listener = try TCPListener(port: port, allowLAN: allowLAN)
            try await listener.start(
                onAccept: { [weak self] conn in self?.handleAccepted(conn) },
                onFailure: { [weak self] error in self?.handleUnexpectedFailure(error) }
            )
        } catch {
            proxyLog(.error, "Proxy", "Failed to start local SOCKS5/HTTP listener on port \(port): \(error)")
            throw error
        }
        self.listener = listener
        isRunning = true
        boundPort = listener.port
        proxyLog(.info, "Proxy", "Local SOCKS5/HTTP listener started on \(allowLAN ? "0.0.0.0" : "127.0.0.1"):\(listener.port ?? port), relaying through \(hops.count) hop(s)")
        return listener.port!
    }

    /// Live hop swap: retargets *new* connections to `newHops` without
    /// touching the listener or any already-relaying connection -- each
    /// accepted connection snapshots `hops` once, at the moment it starts
    /// relaying (see `relay(localConn:id:)`), so mutating this property
    /// never disturbs anything already in flight. This is what lets the
    /// Chains/Dashboard screens switch the active chain without dropping
    /// whatever's mid-transfer, and what a future auto-optimize feature
    /// would call to switch chains seamlessly too.
    func updateHops(_ newHops: [ProxyHop], chainName: String) {
        hops = newHops
        activeChainName = chainName
        proxyLog(.info, "Proxy", "Active chain switched to \(newHops.count) hop(s); new connections will use it")
    }

    /// Cheap (single lock-protected read) snapshot of total bytes relayed
    /// through the live chain since `start()`/`byteCounter.reset()` --
    /// meant to be polled periodically (see `AppStore`'s throughput
    /// sampling loop) to derive a rate, not called per chunk.
    func snapshotByteCounts() -> (upload: UInt64, download: UInt64) {
        byteCounter.snapshot()
    }

    /// Cheap snapshot of total relayed-connection attempts vs how many of
    /// those timed out, since `start()`/`outcomeCounter.reset()` -- meant to
    /// be polled periodically (see `AppStore`'s throughput sampling loop) to
    /// derive a windowed timeout rate, not called per connection.
    func snapshotConnectionOutcomeCounts() -> (total: UInt64, timedOut: UInt64) {
        outcomeCounter.snapshot()
    }

    /// Live + closed connection lists for the Connections panel -- meant to
    /// be polled periodically (see `AppStore`'s throughput sampling loop),
    /// same cadence as the counters above. A plain synchronous read: this
    /// type is already `@MainActor`, and only each connection's own `stats`
    /// (touched off-MainActor by its relay/pump task) needs its own lock.
    func snapshotConnections() -> (active: [ConnectionInfo], closed: [ConnectionInfo]) {
        let activeInfos = activeConnections.map { id, active -> ConnectionInfo in
            let snap = active.stats.snapshot()
            return ConnectionInfo(
                id: id, kind: snap.kind, destination: snap.destination, chainName: active.chainName,
                startedAt: active.startedAt, endedAt: nil, uploadBytes: snap.upload, downloadBytes: snap.download
            )
        }
        return (activeInfos, closedConnections)
    }

    /// Tears down the listener AND force-closes every in-flight relayed
    /// connection. Cancelling each connection's wrapping `Task` alone isn't
    /// enough: none of `TCPConn`/`Session`'s blocking reads observe Swift
    /// Task cancellation (they block inside a continuation), so only
    /// closing the underlying transports actually unblocks a pending read.
    func stop() {
        guard isRunning else { return }
        listener?.cancel()
        listener = nil
        isRunning = false
        boundPort = nil

        for (_, active) in activeConnections {
            active.localConn.close()
            active.outbound?.close()
            active.task.cancel()
        }
        activeConnections.removeAll()
        proxyLog(.info, "Proxy", "Local SOCKS5/HTTP listener stopped")
    }

    private func handleUnexpectedFailure(_ error: Error) {
        proxyLog(.error, "Proxy", "Local SOCKS5/HTTP listener stopped unexpectedly: \(error)")
        onUnexpectedStop?(error)
        stop()
    }

    private func handleAccepted(_ localConn: TCPConn) {
        let id = UUID()
        let shortID = id.uuidString.prefix(8)
        proxyLog(.debug, "Proxy", "[\(shortID)] Accepted connection from \(localConn.remoteEndpointDescription)")
        let hopsForThisConnection = hops
        let chainNameForThisConnection = activeChainName
        // Captured directly rather than looked up through `activeConnections`
        // below, so `relay`'s writes never race the dictionary insert on the
        // next line -- both this closure and the `ActiveConnection` below
        // share the exact same instance.
        let stats = ConnectionStats()
        let task = Task { [weak self] in
            guard let self else { return }
            await Self.relay(
                localConn: localConn, id: id, hops: hopsForThisConnection,
                counter: self.byteCounter, outcomeCounter: self.outcomeCounter, stats: stats
            ) { outbound in
                self.activeConnections[id]?.outbound = outbound
            }
            self.recordClosedConnection(id: id)
        }
        activeConnections[id] = ActiveConnection(task: task, localConn: localConn, chainName: chainNameForThisConnection, stats: stats)
    }

    /// Moves a just-finished connection from `activeConnections` into the
    /// bounded `closedConnections` history, snapshotting its final byte
    /// counts/destination. Runs whether the connection ended normally or was
    /// force-closed by `stop()` (that just makes the pending read/send calls
    /// this task is awaiting on fail sooner), so abruptly-stopped connections
    /// still get recorded.
    private func recordClosedConnection(id: UUID) {
        guard let active = activeConnections.removeValue(forKey: id) else { return }
        let snap = active.stats.snapshot()
        let info = ConnectionInfo(
            id: id, kind: snap.kind, destination: snap.destination, chainName: active.chainName,
            startedAt: active.startedAt, endedAt: Date(), uploadBytes: snap.upload, downloadBytes: snap.download
        )
        closedConnections.append(info)
        if closedConnections.count > Self.closedConnectionHistoryLimit {
            closedConnections.removeFirst(closedConnections.count - Self.closedConnectionHistoryLimit)
        }
    }

    /// `nonisolated`, same rationale (and same `@MainActor`-static-member
    /// pitfall) as `pumpBothDirections` below -- but here it's the
    /// connection *setup* phase, not the data pump, that was pinned to
    /// MainActor: every `await` inside used to have to resume back on
    /// MainActor's serial executor before the next handshake step could run.
    /// With only a handful of connections that's unnoticeable; confirmed
    /// live past ~100 concurrent sessions, new connections' SOCKS5
    /// accept/DNS/TCP-dial/hop-handshake steps visibly queued up behind
    /// MainActor's other work (UI updates, `onConnectionCountChanged`, the
    /// throughput-sampling timer) rather than being limited by actual
    /// network latency. `hops`/`counter` are passed in as snapshots taken on
    /// MainActor in `handleAccepted` (same snapshot-at-accept-time behavior
    /// as before) since this function can't read `self`'s MainActor state
    /// directly; `onOutbound` is the one piece of bookkeeping that still has
    /// to land on MainActor (`stop()` reads `activeConnections` there), so
    /// it's typed `@MainActor` rather than handed a live reference to `self`.
    private nonisolated static func relay(
        localConn: TCPConn, id: UUID, hops: [ProxyHop], counter: RelayByteCounter, outcomeCounter: ConnectionOutcomeCounter,
        stats: ConnectionStats,
        onOutbound: @MainActor @Sendable (any ProxyTransport) -> Void
    ) async {
        let shortID = id.uuidString.prefix(8)
        outcomeCounter.recordAttempt()
        do {
            try await localConn.connect(timeout: 10)

            // Mixed-protocol sniff: a SOCKS5 greeting always starts with
            // version byte 0x05 (RFC 1928); an HTTP request line starts with
            // an ASCII method name instead. `peekByte` leaves the byte in
            // place so whichever parser runs below still sees it as the
            // first byte of its own read.
            let firstByte = try await localConn.peekByte(timeout: 10)
            let host: String
            let port: UInt16
            var replayToOutbound: [UInt8] = []
            if firstByte == 0x05 {
                switch try await SOCKS5Server.acceptRequest(over: localConn) {
                case .connect(let request):
                    host = request.host
                    port = request.port
                case .associate:
                    // A wholly different relay shape (datagrams, any
                    // destination per packet, no single `finalTargetHost`)
                    // from CONNECT's byte-pipe-to-one-destination model
                    // below -- handled start-to-finish here, then this
                    // connection is done (same shared `localConn.close()`
                    // every path falls through to).
                    await Self.relayUDPAssociate(localConn: localConn, shortID: shortID, hops: hops, counter: counter, stats: stats)
                    proxyLog(.debug, "Proxy", "[\(shortID)] UDP association closed")
                    localConn.close()
                    return
                }
            } else {
                let request = try await HTTPProxyServer.acceptConnect(over: localConn)
                host = request.host
                port = request.port
                replayToOutbound = request.replayToOutbound
            }

            stats.setDestination(.tcp, "\(host):\(port)")
            proxyLog(.debug, "Proxy", "[\(shortID)] Relaying to \(host):\(port) through \(hops.count) hop(s)")
            let outbound = try await ProxyChain.open(
                hops: hops,
                finalTargetHost: host,
                finalTargetPort: port,
                connectTimeout: 10,
                logID: String(shortID)
            )
            await onOutbound(outbound)
            // A plain (non-CONNECT) HTTP request already had its request
            // line/headers consumed off the client socket to find the
            // destination above -- replay them to the outbound hop before
            // the raw pump takes over relaying whatever's left (the request
            // body, if any, and every reply byte coming back).
            if !replayToOutbound.isEmpty {
                try await outbound.send(replayToOutbound, timeout: 10)
            }
            await pumpBothDirections(local: localConn, outbound: outbound, counter: counter, stats: stats)
            proxyLog(.debug, "Proxy", "[\(shortID)] Connection closed")
        } catch {
            // Local socket never completed a valid handshake, or the chain
            // failed to dial -- nothing more useful to do than close it.
            // `ProxyError.timedOut` specifically (a dial/handshake deadline
            // elapsing) is what feeds Overview's timeout-rate tile/chart --
            // every other failure (refused, TLS, protocol error) still
            // counts toward the attempt total above but not this.
            if (error as? ProxyError) == .timedOut {
                outcomeCounter.recordTimeout()
            }
            proxyLog(.warn, "Proxy", "[\(shortID)] Connection failed: \(error)")
        }
        localConn.close()
    }

    /// Serves one SOCKS5 UDP ASSOCIATE request end-to-end: opens whichever
    /// UDP relay mechanism `ChainCore.ProxyChain.openUDPRelay` picks for the
    /// current chain (an all-Shadowsocks chain, or one whose last hop is
    /// VMess/VLESS/Trojan -- refusing with a SOCKS5 command-not-supported
    /// reply otherwise; see that dispatcher's own doc comment), binds a local
    /// `UDPListener` for the one client that asked, replies telling it that
    /// address, then relays datagrams both ways until either the relay's own
    /// socket, the local peer's socket, or the original control TCP
    /// connection ends. Swallows its own errors (logging instead) since,
    /// unlike `relay`'s CONNECT/HTTP path, there's no single shared `catch`
    /// left to report through once this returns -- the caller just closes
    /// `localConn` unconditionally either way.
    private nonisolated static func relayUDPAssociate(localConn: TCPConn, shortID: Substring, hops: [ProxyHop], counter: RelayByteCounter, stats: ConnectionStats) async {
        let relay: any UDPRelay
        do {
            relay = try await ProxyChain.openUDPRelay(hops: hops, logID: String(shortID))
        } catch {
            proxyLog(.warn, "Proxy", "[\(shortID)] UDP ASSOCIATE refused: \(error)")
            try? await SOCKS5Server.replyCommandNotSupported(over: localConn)
            return
        }
        defer { relay.close() }

        do {
            let udpListener = try UDPListener()
            final class AcceptBox: @unchecked Sendable {
                var continuation: AsyncStream<UDPConn>.Continuation?
            }
            let box = AcceptBox()
            try await udpListener.start(
                onAccept: { conn in
                    // `UDPListener`'s own doc comment claims "at most once,"
                    // but nothing enforces that -- Network.framework spins
                    // up a distinct `NWConnection` (and fires this handler
                    // again) for every additional remote address that sends
                    // to this ephemeral port, e.g. an unrelated local
                    // process probing ports, for as long as this UDP
                    // association stays alive. Only the first one is ever
                    // read back out below (`peerIterator.next()`), so
                    // without this guard every later one would sit in the
                    // stream's unbounded buffer, retained but never
                    // `cancel()`-ed, for the rest of the association's
                    // lifetime -- the same kind of leaked-`NWConnection`
                    // bug fixed elsewhere in this file, just via a
                    // still-open door instead of a missing `close()`.
                    guard let continuation = box.continuation else {
                        conn.close()
                        return
                    }
                    continuation.yield(conn)
                    continuation.finish()
                    box.continuation = nil
                },
                onFailure: { error in
                    proxyLog(.warn, "Proxy", "[\(shortID)] UDP relay listener failed: \(error)")
                }
            )
            defer { udpListener.cancel() }
            guard let boundPort = udpListener.port else { throw ProxyError.connectionClosed }

            // Start waiting for the client's first datagram *before* telling
            // it where to send it (`replyAssociate`, right below), so there's
            // no window where an eager client's datagram could arrive and be
            // silently dropped before anything is listening for it.
            // `AsyncStream`'s build closure runs synchronously the instant
            // the stream is constructed, right here -- unlike an
            // `async let withCheckedContinuation { ... }` (this used to be
            // one), which defers that same closure to a concurrently
            // -scheduled child task with no guarantee it actually runs
            // before this function moves on to `replyAssociate` below.
            // Constructing the stream inline registers `box.continuation`
            // before anything else runs, closing that race for real instead
            // of just in the common case where the child task happens to be
            // scheduled first.
            let peerStream = AsyncStream<UDPConn> { continuation in
                box.continuation = continuation
            }
            try await SOCKS5Server.replyAssociate(over: localConn, boundPort: boundPort)
            var peerIterator = peerStream.makeAsyncIterator()
            guard let peer = await peerIterator.next() else { throw ProxyError.connectionClosed }
            // Same contract as `TCPConn.init(accepted:)`: a `UDPListener`
            // hands back a not-yet-started connection -- send/receiveDatagram
            // would hang forever without this.
            try await peer.connect(timeout: nil)
            stats.setDestination(.udp, "")

            proxyLog(.debug, "Proxy", "[\(shortID)] UDP association ready on 127.0.0.1:\(boundPort), relaying through \(hops.count) hop(s)")
            await withTaskGroup(of: Void.self) { group in
                // Peer -> relay: unwrap the client's own SOCKS5 UDP header
                // (any destination, per packet) and forward the raw payload.
                group.addTask {
                    while true {
                        do {
                            let packet = try await peer.receiveDatagram(timeout: nil)
                            if packet.isEmpty { return }
                            let (target, targetPort, payload) = try parseSOCKS5UDPDatagram(packet)
                            stats.setDestination(.udp, "\(target.displayHost):\(targetPort)")
                            counter.addUpload(payload.count)
                            stats.addUpload(payload.count)
                            try await relay.send(targetHost: target.displayHost, targetPort: targetPort, payload: payload, timeout: nil)
                        } catch {
                            return
                        }
                    }
                }
                // Relay -> peer: re-wrap whichever real remote address
                // replied in the same SOCKS5 UDP header shape before handing
                // it back to the client.
                group.addTask {
                    while true {
                        do {
                            let (fromHost, fromPort, payload) = try await relay.receive(timeout: nil)
                            let datagram = try socks5UDPDatagram(target: ProxyAddress.parse(fromHost), targetPort: fromPort, payload: payload)
                            counter.addDownload(payload.count)
                            stats.addDownload(payload.count)
                            try await peer.send(datagram, timeout: nil)
                        } catch {
                            return
                        }
                    }
                }
                // The control TCP connection: per RFC 1928 Section 6, this
                // association ends the moment it closes or errors -- this
                // task's only job is to notice that.
                group.addTask {
                    while true {
                        do {
                            let chunk = try await localConn.readAvailable(timeout: nil)
                            if chunk.isEmpty { return }
                        } catch {
                            return
                        }
                    }
                }
                _ = await group.next()
                peer.close()
                relay.close()
                localConn.close()
                await group.next()
                await group.next()
            }
        } catch {
            proxyLog(.warn, "Proxy", "[\(shortID)] UDP ASSOCIATE failed: \(error)")
        }
    }

    /// `nonisolated`: being static members of `@MainActor` `LocalProxyServer`
    /// would otherwise pull these onto the MainActor by default -- even
    /// inside `addTask`'s own child tasks, since it's this function's own
    /// declared isolation that decides where its body actually runs, not
    /// which task or task group invokes it. That mattered for real: with
    /// this isolated to MainActor, a live relayed connection could be
    /// starved for the several seconds a concurrent MainActor-heavy task
    /// (e.g. Auto-Optimize's bandwidth probe, see its own doc comment in
    /// `AppStore`) held the executor, long enough for the peer to reset the
    /// connection -- confirmed live, matching timestamps between an
    /// Auto-Optimize rotation cycle and a relayed connection dying mid
    /// nested-TLS-handshake. This function touches no `@MainActor` instance
    /// state (only its own parameters), so moving it off MainActor is safe.
    private nonisolated static func pumpBothDirections(local: TCPConn, outbound: any ProxyTransport, counter: RelayByteCounter, stats: ConnectionStats) async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await pump(from: local, to: outbound, record: { counter.addUpload($0); stats.addUpload($0) }) }
            group.addTask { await pump(from: outbound, to: local, record: { counter.addDownload($0); stats.addDownload($0) }) }
            _ = await group.next()
            // One direction ended (EOF/error). Proactively close both sides
            // so the other direction's in-flight/next `readAvailable` call
            // unblocks instead of leaking a task parked forever -- Task
            // cancellation alone wouldn't do this (see `stop()`'s comment).
            local.close()
            outbound.close()
            await group.next()
        }
    }

    private nonisolated static func pump(from source: any ByteStreamAvailableReader, to sink: any ByteStreamSink, record: @Sendable (Int) -> Void) async {
        while true {
            do {
                let chunk = try await source.readAvailable(timeout: nil)
                if chunk.isEmpty { return }
                record(chunk.count)
                try await sink.send(chunk, timeout: nil)
            } catch {
                return
            }
        }
    }
}
