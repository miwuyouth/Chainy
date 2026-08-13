// Networking.swift
//
// A thin async TCP wrapper around Network.framework, shared by every proxy
// protocol client: dial, send, and timeout-guarded reads. None of this
// depends on VMess (or any other protocol) -- it's just "talk to a TCP
// socket with a deadline", which SOCKS5/Shadowsocks/HTTP CONNECT clients
// need exactly as much as VMess does.

import Foundation
import Network

public enum ProxyError: Error, Equatable {
    /// The connection closed (or a read otherwise came up short) before as
    /// many bytes as expected arrived.
    case connectionClosed
    /// A deadline (connect/send/read) elapsed before the operation completed.
    /// A malicious or misconfigured server can give bad credentials no
    /// distinguishing response at all (to resist active probing) -- it just
    /// stops talking -- so this is what turns that into a prompt, reported
    /// error instead of an indefinite hang. (Found by testing VMess against
    /// a real local xray-core server with a deliberately wrong UUID -- see
    /// Scripts/integration_test.sh.)
    case timedOut
}

/// Anything that can hand back exactly `n` bytes (or throw), with an
/// optional deadline. `TCPConn` conforms to this for real traffic; tests use
/// in-memory fakes so protocol decode logic can be exercised without a socket.
public protocol ByteStreamSource {
    func readExactly(_ n: Int, timeout: TimeInterval?) async throws -> [UInt8]
}

/// Anything that can accept bytes to send onward, with an optional deadline.
/// Split out from `ByteStreamSource` (rather than folded into one combined
/// protocol) so tests that only exercise a decode/parse path -- like
/// ShadowsocksCore's chunk-crypto tests -- can fake just the read half
/// without also faking a writer.
public protocol ByteStreamSink {
    func send(_ bytes: [UInt8], timeout: TimeInterval?) async throws
}

/// Anything that can hand back "whatever's next" without a caller-specified
/// length -- the shape every protocol's own `receive()` needs for streaming
/// a response of unknown length back to a *terminal* caller, as opposed to
/// `readExactly`, which a handshake needs for precise framing.
public protocol ByteStreamAvailableReader {
    func readAvailable(timeout: TimeInterval?) async throws -> [UInt8]
}

/// Tears down whatever's underneath: a real socket for `TCPConn`, or (for a
/// protocol `Session` layered on top of another hop) simply the next
/// `close()` down the chain -- so closing the outermost session of an N-hop
/// proxy chain closes the one real TCP connection at its root.
public protocol ByteStreamCloser {
    func close()
}

/// The full interface a proxy hop exposes, whether it's a raw socket or
/// another protocol's session stacked on top of one: exact-length reads (for
/// a nested handshake to frame its own request/response against),
/// best-effort reads (for a terminal caller streaming an unknown-length
/// response), sends, and teardown. `TCPConn` conforms directly -- it's the
/// root of every chain -- and so does each protocol's `Session` type, which
/// is what makes chaining possible: passing one protocol's `Session` as the
/// `over:` transport for the next one's `open` needs nothing more than this.
public typealias ProxyTransport = ByteStreamSource & ByteStreamSink & ByteStreamAvailableReader & ByteStreamCloser

/// The datagram-shaped counterpart to `ProxyTransport`: no `readExactly`/
/// `readAvailable` split, since a UDP receive is never partial -- one
/// `receiveDatagram` call always hands back exactly one whole packet (or
/// throws), the same way one `send` call always writes exactly one packet.
/// `UDPConn` conforms directly (a real datagram socket); a `ChainCore`
/// relay type layering per-packet encryption on top of one still exposes
/// this same shape so its own tests can fake it, mirroring how
/// `ProxyTransport` fakes already work for the TCP path.
public protocol DatagramTransport {
    func send(_ bytes: [UInt8], timeout: TimeInterval?) async throws
    func receiveDatagram(timeout: TimeInterval?) async throws -> [UInt8]
    func close()
}

/// Races an async callback (an `NWConnection` completion handler, in every
/// caller here) against an optional deadline timer, both firing serially on
/// the same queue the connection's own callbacks run on -- so a plain
/// captured flag, no lock, is enough to make "resume exactly once" safe:
/// whichever callback runs first on that queue wins. `onTimeout` tears down
/// whatever's underneath so the loser's callback (if it ever fires) finds a
/// dead connection rather than leaking it. Shared by `TCPConn` and `UDPConn`
/// (each passing their own `connection.cancel()`) rather than duplicated,
/// since the race/continuation logic itself has nothing to do with TCP vs UDP.
func raceAgainstDeadline<T>(
    timeout: TimeInterval?,
    onTimeout: @escaping () -> Void,
    register: @escaping (@escaping (Result<T, Error>) -> Void) -> Void
) async throws -> T {
    try await withCheckedThrowingContinuation { (cont: CheckedContinuation<T, Error>) in
        var didResume = false
        func resumeOnce(_ result: Result<T, Error>) {
            guard !didResume else { return }
            didResume = true
            cont.resume(with: result)
        }
        register { result in resumeOnce(result) }
        if let timeout {
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout) {
                guard !didResume else { return }
                onTimeout()
                resumeOnce(.failure(ProxyError.timedOut))
            }
        }
    }
}

// All mutable state (`buffered`) and every callback below only ever run
// serially on the `.main` queue that `connection.start(queue:)` binds to
// (NWConnection callbacks and the `DispatchQueue.main.asyncAfter` deadline
// timer alike), so concurrent access never actually happens even though the
// compiler can't see that through the closures -- hence `@unchecked Sendable`.
public final class TCPConn: ByteStreamSource, ByteStreamSink, ByteStreamAvailableReader, ByteStreamCloser, @unchecked Sendable {
    // `NWConnection!` rather than `let`: for the dial-side initializer, it's
    // no longer created until `connect()` runs, since the host/port aren't
    // available until then. Always non-nil by the time any other method
    // runs, since every caller in this codebase already awaits `connect()`
    // before touching a `TCPConn`.
    private var connection: NWConnection!
    private let dialHost: String?
    private let dialPort: UInt16?
    private var buffered: [UInt8] = []

    public init(host: String, port: UInt16) {
        dialHost = host
        dialPort = port
    }

    /// Wraps an already-accepted `NWConnection` from a listener's
    /// `newConnectionHandler` -- the server-side counterpart to the dial-side
    /// initializer above. Not yet started: callers still call `connect(timeout:)`
    /// exactly as they would after dialing, since `connect()` only ever does
    /// `start(queue:)` + await `.ready`, already protocol-agnostic.
    public init(accepted connection: NWConnection) {
        self.connection = connection
        dialHost = nil
        dialPort = nil
    }

    /// `connect(timeout:tls:)`'s optional native-TLS parameter: negotiates
    /// TLS as part of establishing the connection itself, via
    /// Network.framework's own TLS support, rather than a bare TCP socket a
    /// caller layers `TLSConn`'s Secure Transport bridge over afterward.
    /// Only usable for a fresh dial (exactly what `TCPConn` already only
    /// supports here -- there's no equivalent for the `accepted:` init or
    /// for wrapping an already-open transport; that's what `TLSConn` is
    /// still for). Chosen deliberately over `TLSConn` for Trojan's specific
    /// "first hop, fresh connection" case: confirmed live against a real
    /// relay that its anti-probing filter passed a native
    /// Network.framework-shaped TLS ClientHello while consistently killing
    /// (RST after a fake alert record) Secure Transport's, for the same
    /// node, same moment, same machine.
    public struct NativeTLSOptions {
        public let serverName: String
        public let allowInsecure: Bool
        public init(serverName: String, allowInsecure: Bool = false) {
            self.serverName = serverName
            self.allowInsecure = allowInsecure
        }
    }

    public func connect(timeout: TimeInterval? = 10, tls: NativeTLSOptions? = nil) async throws {
        if connection == nil, let dialHost, let dialPort {
            let params: NWParameters
            if let tls {
                let tlsOptions = NWProtocolTLS.Options()
                // Explicit SNI rather than relying on it being inferred from
                // the dial host, so a caller can front one hostname while
                // presenting another in the TLS handshake.
                sec_protocol_options_set_tls_server_name(tlsOptions.securityProtocolOptions, tls.serverName)
                if tls.allowInsecure {
                    sec_protocol_options_set_verify_block(tlsOptions.securityProtocolOptions, { _, _, complete in
                        complete(true)
                    }, DispatchQueue.global())
                }
                params = NWParameters(tls: tlsOptions, tcp: .init())
            } else {
                params = .tcp
            }
            connection = NWConnection(host: NWEndpoint.Host(dialHost), port: NWEndpoint.Port(rawValue: dialPort)!, using: params)
        }
        try await raceAgainstDeadline(timeout: timeout, onTimeout: { self.connection.cancel() }) { (complete: @escaping (Result<Void, Error>) -> Void) in
            self.connection.stateUpdateHandler = { state in
                switch state {
                case .ready: complete(.success(()))
                case .failed(let err):
                    // NWConnection docs: reaching `.failed` doesn't release
                    // its underlying resources by itself -- `cancel()` must
                    // still be called, same as the `onTimeout` branch below
                    // already does, or the socket leaks even though nothing
                    // still references this `TCPConn`. Confirmed as the
                    // cause of a real "proxy stops working after a few
                    // hours, restart fixes it" report: every ordinary failed
                    // dial (refused/unreachable destination) leaked one fd
                    // until the process ran out of them.
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

    /// POSIX codes NWConnection has been observed to surface through the
    /// receive completion handler's `error` parameter for what is, from the
    /// caller's point of view, just "the peer tore down the connection" --
    /// not a real transport problem. Treated the same as a clean EOF (empty
    /// data) so callers only ever need to handle `ProxyError.connectionClosed`
    /// for "no more data", not enumerate OS-specific close error codes.
    private static let benignCloseCodes: Set<POSIXErrorCode> = [.ECONNRESET, .ENOTCONN, .EPIPE]

    /// ENODATA ("no message available") turned up mid-transfer during a real
    /// large-response test against shadowsocks-rust -- not at the end of the
    /// stream. Its own strerror text ("No message available on STREAM") is
    /// easily misread as a hard close (it was first mistaken for ENOMSG,
    /// which *is* fatal), but empirically it's transient there: more data
    /// really is still coming, so mid-stream this retries the read instead
    /// of truncating early (confirmed: the same 2MB transfer only came back
    /// byte-exact after switching from "treat as EOF" to retry).
    ///
    /// But at the genuine end of the stream, ENODATA was observed to repeat
    /// *forever* rather than ever resolving to a clean `isComplete`/empty
    /// signal -- so retrying unconditionally turned "truncates early" into
    /// "hangs forever" instead of fixing it. `maxTransientRetries` bounds
    /// the retry: real in-flight data arrives within microseconds on
    /// loopback, so a few dozen 1ms retries comfortably covers it, while
    /// still resolving a truly-ended stream in well under a second rather
    /// than hanging indefinitely.
    private static let transientRetryCodes: Set<POSIXErrorCode> = [.ENODATA]
    private static let maxTransientRetries = 200

    private func receiveChunk(timeout: TimeInterval?) async throws -> [UInt8] {
        try await raceAgainstDeadline(timeout: timeout, onTimeout: { self.connection.cancel() }) { complete in
            func attempt(retriesLeft: Int) {
                self.connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
                    if let error {
                        if case .posix(let code) = error, Self.transientRetryCodes.contains(code), retriesLeft > 0 {
                            DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(1)) {
                                attempt(retriesLeft: retriesLeft - 1)
                            }
                            return
                        }
                        if case .posix(let code) = error, Self.benignCloseCodes.contains(code) || Self.transientRetryCodes.contains(code) {
                            complete(.success([]))
                        } else {
                            complete(.failure(error))
                        }
                        return
                    }
                    if let data, !data.isEmpty { complete(.success(Array(data))); return }
                    if isComplete { complete(.success([])); return }
                    // No data, no error, and not complete: Network.framework's
                    // documented receive contract allows the completion to
                    // fire this way when there's nothing to report yet even
                    // though the connection is still open. Only `isComplete`
                    // means the stream actually ended; this is a spurious
                    // wakeup, so keep waiting on the same receive rather than
                    // resolving as EOF (which would tear down an entire
                    // healthy relay -- confirmed live, this exact case was
                    // silently ending a connection mid nested-TLS-handshake
                    // with no error anywhere in the log).
                    attempt(retriesLeft: retriesLeft)
                }
            }
            attempt(retriesLeft: Self.maxTransientRetries)
        }
    }

    public func readExactly(_ n: Int, timeout: TimeInterval? = 10) async throws -> [UInt8] {
        while buffered.count < n {
            let chunk = try await receiveChunk(timeout: timeout)
            if chunk.isEmpty { throw ProxyError.connectionClosed }
            buffered += chunk
        }
        let result = Array(buffered.prefix(n))
        buffered.removeFirst(n)
        return result
    }

    /// Looks at the next byte without consuming it -- for a local listener
    /// that accepts more than one inbound protocol on the same port (Chainy's
    /// mixed SOCKS5/HTTP proxy listener) and needs to sniff which one a
    /// client is speaking before picking a parser. Reuses the same
    /// `buffered` array `readExactly` reads from, just without the
    /// `removeFirst` -- so whichever parser runs next still sees this byte
    /// as the start of its own read.
    public func peekByte(timeout: TimeInterval? = 10) async throws -> UInt8 {
        while buffered.isEmpty {
            let chunk = try await receiveChunk(timeout: timeout)
            if chunk.isEmpty { throw ProxyError.connectionClosed }
            buffered += chunk
        }
        return buffered[0]
    }

    /// Reads whatever is currently available (or waits for the next chunk), for streaming the tail of a response.
    public func readAvailable(timeout: TimeInterval? = nil) async throws -> [UInt8] {
        if !buffered.isEmpty {
            let result = buffered
            buffered = []
            return result
        }
        return try await receiveChunk(timeout: timeout)
    }

    // `connection` is only nil for a dial-side `TCPConn` before `connect()`
    // has run (see its doc comment on the stored property) -- guarded rather
    // than force-unwrapped here since, unlike the methods above, closing (or
    // describing) a never-connected instance is a real, if unusual, path
    // (e.g. an error before `connect()` was reached) that previously worked
    // because `connection` used to be created eagerly in `init`.
    public func close() { connection?.cancel() }

    /// The peer's address:port for an accepted (server-side) connection --
    /// `NWConnection.endpoint` reflects the remote side for connections
    /// handed out by `NWListener`'s `newConnectionHandler`, as opposed to the
    /// dial-side initializer above where it's the host this instance is
    /// connecting *to*. Used purely for logging which client dialed in.
    public var remoteEndpointDescription: String { connection.map { "\($0.endpoint)" } ?? (dialHost.map { "\($0):\(dialPort ?? 0)" } ?? "unknown") }
}
