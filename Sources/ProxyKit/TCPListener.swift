// TCPListener.swift
//
// The server-side counterpart to TCPConn's dial-side wrapper: binds and
// accepts inbound TCP connections. Kept in ProxyKit (not Chainy) because
// it's protocol-agnostic plumbing, same rationale as TCPConn itself, and
// kept in its own file rather than appended to Networking.swift so that
// file's own "dial-side" header comment stays accurate.

import Foundation
import Network

public enum TCPListenerError: Error, Equatable {
    case portInUse
    case invalidPort
}

public final class TCPListener: @unchecked Sendable {
    private let listener: NWListener
    // Tracked on the class itself (not a local var captured by the handler
    // closures below) so mutating it doesn't trip the compiler's
    // Sendable-closure-capture check -- `NWListener`'s handlers are
    // `@Sendable`, unlike `NWConnection`'s (see `TCPConn.raceAgainstDeadline`,
    // which captures a local `didResume` the same way with no such warning).
    private var didResumeStart = false

    /// Binds to 127.0.0.1 explicitly (via `requiredLocalEndpoint`) by
    /// default, not a wildcard bind -- this is meant to relay traffic for
    /// other apps on this same Mac, not to be reachable from other devices
    /// on the LAN. Passing `allowLAN: true` binds the given port on every
    /// interface instead (via `NWListener(using:on:)`, which leaves
    /// `requiredLocalEndpoint` unset), so another device on the same network
    /// can dial this Mac's LAN IP -- opt-in, since it's also then reachable
    /// by anything else on that network, not just its own owner.
    public init(port: UInt16, allowLAN: Bool = false) throws {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { throw TCPListenerError.invalidPort }
        let params = NWParameters.tcp
        if allowLAN {
            listener = try NWListener(using: params, on: nwPort)
        } else {
            params.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: nwPort)
            listener = try NWListener(using: params)
        }
    }

    public var port: UInt16? { listener.port?.rawValue }

    /// Starts listening, resuming once `.ready` (mapping the common
    /// "address already in use" failure to `.portInUse` for a readable UI
    /// message) or throwing if the listener fails outright. `onAccept` fires
    /// once per accepted connection with a not-yet-started `TCPConn` --
    /// callers must still call `connect(timeout:)` on it themselves.
    /// `onFailure` fires only for a failure *after* startup already
    /// succeeded (e.g. the interface goes away), since the listener keeps
    /// running independently of this call once it returns.
    ///
    /// `newConnectionHandler`/`stateUpdateHandler` are set before
    /// `listener.start()` -- set later and an accepted connection is
    /// silently dropped (proven necessary already by
    /// `ChainCoreLiveSocketTests.ChainTestServer`, which this mirrors).
    public func start(onAccept: @escaping (TCPConn) -> Void, onFailure: @escaping (Error) -> Void) async throws {
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
                        if case .posix(.EADDRINUSE) = err {
                            cont.resume(throwing: TCPListenerError.portInUse)
                        } else {
                            cont.resume(throwing: err)
                        }
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
            listener.newConnectionHandler = { conn in onAccept(TCPConn(accepted: conn)) }
            listener.start(queue: .main)
        }
    }

    public func cancel() { listener.cancel() }
}
