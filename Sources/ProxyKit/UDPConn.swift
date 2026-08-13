// UDPConn.swift
//
// The datagram-shaped counterpart to TCPConn: a thin async wrapper around
// Network.framework's UDP support. Where TCPConn's `readExactly` buffers
// across partial reads because a byte stream has no message boundaries, UDP
// already preserves them -- one `receiveMessage` call is always exactly one
// datagram, so there's no buffering, no chunk framing, nothing to reassemble
// here at all. That's also why this conforms to `DatagramTransport` instead
// of `ByteStreamSource`/`ByteStreamAvailableReader`: there's no `readExactly`
// to offer (a datagram is never "some more bytes are still coming").
//
// Built for Shadowsocks UDP relay (see ChainCore's `ShadowsocksUDPRelay`),
// which needs exactly one real UDP socket per chain -- to the first hop's
// server -- regardless of how many Shadowsocks hops are nested inside the
// packets sent over it (see that type's own doc comment for why chaining
// Shadowsocks UDP needs no transport-layering at all, unlike TCP's
// Session-over-Session stacking).

import Foundation
import Network

/// `UDPConn` reuses `TCPConn`'s `@unchecked Sendable` rationale verbatim:
/// every callback below runs serially on the same `.main` queue `start(queue:)`
/// binds to, so the compiler's inability to see that through the closures is
/// the only reason this needs the escape hatch.
public final class UDPConn: DatagramTransport, @unchecked Sendable {
    private var connection: NWConnection!
    private let dialHost: String?
    private let dialPort: UInt16?

    public init(host: String, port: UInt16) {
        dialHost = host
        dialPort = port
    }

    /// Wraps an already-accepted `NWConnection` from a `UDPListener`'s
    /// `newConnectionHandler` -- the server-side counterpart to the dial-side
    /// initializer above, mirroring `TCPConn.init(accepted:)`.
    public init(accepted connection: NWConnection) {
        self.connection = connection
        dialHost = nil
        dialPort = nil
    }

    public func connect(timeout: TimeInterval? = 10) async throws {
        if connection == nil, let dialHost, let dialPort {
            connection = NWConnection(host: NWEndpoint.Host(dialHost), port: NWEndpoint.Port(rawValue: dialPort)!, using: .udp)
        }
        try await raceAgainstDeadline(timeout: timeout, onTimeout: { self.connection.cancel() }) { (complete: @escaping (Result<Void, Error>) -> Void) in
            self.connection.stateUpdateHandler = { state in
                switch state {
                case .ready: complete(.success(()))
                case .failed(let err):
                    // Same leak `TCPConn.connect()` had -- see its own
                    // comment on this branch: `.failed` doesn't release the
                    // underlying resources by itself, `cancel()` still has
                    // to be called explicitly.
                    self.connection.cancel()
                    complete(.failure(err))
                case .cancelled: complete(.failure(ProxyError.timedOut))
                default: break
                }
            }
            self.connection.start(queue: .main)
        }
    }

    public func send(_ bytes: [UInt8], timeout: TimeInterval? = 10) async throws {
        try await raceAgainstDeadline(timeout: timeout, onTimeout: { self.connection.cancel() }) { (complete: @escaping (Result<Void, Error>) -> Void) in
            self.connection.send(content: Data(bytes), completion: .contentProcessed { error in
                if let error { complete(.failure(error)) } else { complete(.success(())) }
            })
        }
    }

    /// One `receiveMessage` call always yields exactly one whole datagram
    /// (or the end-of-connection/error signal) -- `receive(minimumIncompleteLength:maximumLength:)`
    /// is the stream-oriented API `TCPConn` uses and would risk truncating a
    /// packet larger than the buffer it's given; `receiveMessage` is
    /// Network.framework's documented datagram-safe equivalent.
    public func receiveDatagram(timeout: TimeInterval? = nil) async throws -> [UInt8] {
        try await raceAgainstDeadline(timeout: timeout, onTimeout: { self.connection.cancel() }) { (complete: @escaping (Result<[UInt8], Error>) -> Void) in
            self.connection.receiveMessage { data, _, isComplete, error in
                if let error {
                    complete(.failure(error))
                } else if let data, !data.isEmpty {
                    complete(.success(Array(data)))
                } else if isComplete {
                    complete(.success([]))
                } else {
                    complete(.failure(ProxyError.connectionClosed))
                }
            }
        }
    }

    public func close() { connection?.cancel() }
}
