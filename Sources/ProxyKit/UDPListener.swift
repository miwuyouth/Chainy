// UDPListener.swift
//
// The datagram-shaped counterpart to TCPListener: binds and accepts an
// inbound UDP peer. Built for Chainy's local SOCKS5 UDP ASSOCIATE relay --
// one `UDPListener` is bound per association, and (unlike the TCP listener,
// which stays up for the app's whole session and accepts many connections)
// only the *first* peer it hears from is ever accepted, since one SOCKS5
// ASSOCIATE is meant to serve exactly the one client that requested it.
// `NWListener` surfaces UDP the same way it surfaces TCP here: each distinct
// remote endpoint that sends it a first datagram shows up as a new
// `NWConnection` via `newConnectionHandler`, even though UDP itself is
// connectionless -- Network.framework does the demuxing.

import Foundation
import Network

public final class UDPListener: @unchecked Sendable {
    private let listener: NWListener
    // Same rationale as `TCPListener.didResumeStart`: tracked on the class
    // itself so mutating it from `NWListener`'s `@Sendable` handlers doesn't
    // trip the compiler's Sendable-closure-capture check.
    private var didResumeStart = false

    /// Binds to 127.0.0.1 on an ephemeral port by default (via
    /// `requiredLocalEndpoint`, port 0) -- same loopback-only rationale as
    /// `TCPListener`: this relays UDP for another local app's SOCKS5
    /// ASSOCIATE request, not a listener meant to be reachable from the
    /// network. `allowLAN` mirrors `TCPListener`'s own flag for the same
    /// "expose to other devices on this network" opt-in.
    public init(allowLAN: Bool = false) throws {
        let params = NWParameters.udp
        if allowLAN {
            listener = try NWListener(using: params)
        } else {
            params.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: 0)
            listener = try NWListener(using: params)
        }
    }

    public var port: UInt16? { listener.port?.rawValue }

    /// Starts listening, resuming once `.ready` or throwing if the listener
    /// fails outright. `onAccept` fires at most once, for the first peer
    /// heard from -- exactly the one client that dialed the port this
    /// listener handed back in its SOCKS5 ASSOCIATE reply.
    public func start(onAccept: @escaping (UDPConn) -> Void, onFailure: @escaping (Error) -> Void) async throws {
        didResumeStart = false
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            listener.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    guard !self.didResumeStart else { return }
                    self.didResumeStart = true
                    cont.resume()
                case .failed(let err):
                    if !self.didResumeStart {
                        self.didResumeStart = true
                        cont.resume(throwing: err)
                    } else {
                        onFailure(err)
                    }
                case .cancelled:
                    if !self.didResumeStart {
                        self.didResumeStart = true
                        cont.resume(throwing: ProxyError.timedOut)
                    }
                default:
                    break
                }
            }
            listener.newConnectionHandler = { conn in onAccept(UDPConn(accepted: conn)) }
            listener.start(queue: .main)
        }
    }

    public func cancel() { listener.cancel() }
}
