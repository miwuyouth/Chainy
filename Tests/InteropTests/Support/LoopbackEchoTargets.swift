// LoopbackEchoTargets.swift
//
// The "real final destination" every chain in this test suite actually
// reaches: a plain TCP echo listener and a plain UDP echo listener, both
// bound to 127.0.0.1 on an ephemeral port. Every xray-core inbound in this
// suite's server (`XrayTestEnvironment`) has a `freedom` (direct-dial)
// outbound, so whatever a chain's last hop asks it to reach ends up here --
// no external server (Google or otherwise) is ever involved.
//
// Kept deliberately dumb (send back exactly what was received) since the
// point of this whole suite is proving the *proxy chain* relays correctly
// through real third-party protocol servers, not exercising the target
// itself.

import Foundation
import Network
import ProxyKit

/// Echoes back whatever it reads on each accepted TCP connection, one
/// request/response at a time, until the peer closes. Long-lived: started
/// once and shared across every test in this suite.
final class LoopbackTCPEchoServer {
    private let listener: TCPListener

    init() throws {
        listener = try TCPListener(port: 0)
    }

    var port: UInt16 { listener.port! }

    func start() async throws {
        try await listener.start(
            onAccept: { conn in
                Task {
                    do {
                        try await conn.connect(timeout: 10)
                        while true {
                            let data = try await conn.readAvailable(timeout: 30)
                            if data.isEmpty { break }
                            try await conn.send(data, timeout: 10)
                        }
                    } catch {
                        // Peer went away, or the read timed out -- either way
                        // there's nothing left to echo.
                    }
                    conn.close()
                }
            },
            onFailure: { _ in }
        )
    }

    func stop() { listener.cancel() }
}

/// The two loopback targets, started exactly once for the whole `InteropTests`
/// binary. A `static let` holding a `Task` is the standard "async singleton"
/// shape in Swift concurrency: every caller's `await .value` gets the same
/// already-running (or already-finished) task, whether it's the first or
/// the thousandth to ask.
enum EchoTargets {
    static let shared: Task<(tcp: LoopbackTCPEchoServer, udp: LoopbackUDPEchoServer), Error> = Task {
        let tcp = try LoopbackTCPEchoServer()
        try await tcp.start()
        let udp = try LoopbackUDPEchoServer()
        try await udp.start()
        return (tcp, udp)
    }
}

/// Echoes back whatever datagram it reads from each distinct remote peer --
/// `NWListener` demultiplexes UDP by remote endpoint, so a chain's `freedom`
/// outbound socket (a fresh one per UDP relay session) shows up as its own
/// `UDPConn` here, independent of any other concurrently-running chain's.
final class LoopbackUDPEchoServer {
    private let listener: UDPListener

    init() throws {
        listener = try UDPListener()
    }

    var port: UInt16 { listener.port! }

    func start() async throws {
        try await listener.start(
            onAccept: { conn in
                Task {
                    do {
                        // Same contract as `TCPConn.init(accepted:)`/`LocalProxyServer`'s
                        // own UDP ASSOCIATE relay: an accepted `UDPConn` still
                        // needs `connect()` called to actually `start()` its
                        // underlying `NWConnection` before it can send/receive.
                        try await conn.connect(timeout: 10)
                        while true {
                            let data = try await conn.receiveDatagram(timeout: 30)
                            try await conn.send(data, timeout: 10)
                        }
                    } catch {
                        // Peer went away, or the read timed out.
                    }
                    conn.close()
                }
            },
            onFailure: { _ in }
        )
    }

    func stop() { listener.cancel() }
}
