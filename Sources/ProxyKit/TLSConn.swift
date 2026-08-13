// TLSConn.swift
//
// A TLS client that runs over *any* `ProxyTransport` -- a fresh `TCPConn`
// exactly as easily as a previous hop's already-open `Session` -- which is
// what Trojan needs (its whole wire protocol is "TLS, then a plaintext
// header, then a raw byte stream") to fit ChainCore's "any protocol, any
// position" chaining model the same way every other protocol here does.
//
// Network.framework's own TLS support (`NWParameters(tls:...)`) can't do
// this: it only wraps TLS around a connection *it* dials itself against a
// host/port, not around a byte stream that's already open and whose bytes
// might currently be flowing through a previous hop's encryption. Secure
// Transport (`SSLContext` + `SSLSetIOFuncs`) is the one API on this platform
// that lets TLS's read/write calls be redirected to arbitrary functions --
// exactly what's needed to splice it onto `ProxyTransport`'s
// send/readAvailable instead of a real socket. It's the deprecated
// predecessor to Network.framework, but this specific capability (TLS over a
// caller-supplied transport) was never carried over to its replacement, so
// it's still the right tool for this one job.
//
// `SSLContext` isn't safe to call into concurrently, so every operation that
// touches it runs serially on `ioQueue`, a dedicated background thread --
// not one of Swift concurrency's cooperative pool threads. That matters
// because Secure Transport's I/O callbacks are synchronous C function
// pointers with no async equivalent: bridging them to this module's async
// `ProxyTransport` means blocking *some* thread on a continuation, and doing
// that on `ioQueue` (parked on a `DispatchSemaphore`) rather than a
// cooperative-pool thread is what keeps that block from starving other
// unrelated `Task`s.

import Foundation
import Security

public struct TLSOptions {
    /// Sent as the TLS ClientHello's SNI, and (unless `allowInsecure`) the
    /// hostname the peer's certificate is validated against -- separate from
    /// the `host` a caller dials, since a Trojan node's `sni` is sometimes
    /// deliberately different (e.g. domain fronting, or a front domain that
    /// isn't the same as the actual server address).
    public let serverName: String
    /// Skips certificate validation entirely (still negotiates real
    /// encryption -- this only disables the "is this the peer I think it
    /// is" check), matching real Trojan clients' `allow_insecure`/
    /// `allowInsecure` option for self-signed deployments.
    public let allowInsecure: Bool

    public init(serverName: String, allowInsecure: Bool = false) {
        self.serverName = serverName
        self.allowInsecure = allowInsecure
    }
}

public enum TLSError: Error, Equatable {
    /// A Secure Transport call (handshake, read, or write) failed; carries
    /// the raw `OSStatus` since `SecCopyErrorMessageString` isn't
    /// `Equatable`-friendly and the raw code is enough to diagnose from logs.
    case failed(OSStatus)
}

/// One TLS client session layered over `underlying`. Conforms to
/// `ProxyTransport` itself (same shape as every other `Session` in this
/// codebase), so a protocol's plaintext framing -- Trojan's header, or
/// anything else -- can be sent/received through it exactly like a raw
/// socket, and so it can equally serve as the `over:` transport for a
/// *further* hop stacked on top of it.
public final class TLSConn: ByteStreamSource, ByteStreamSink, ByteStreamAvailableReader, ByteStreamCloser, @unchecked Sendable {
    private let underlying: any ProxyTransport
    private let allowInsecure: Bool
    private var context: SSLContext!
    private let ioQueue = DispatchQueue(label: "TLSConn.io")

    /// Raw (still-encrypted) bytes already read from `underlying` but not
    /// yet consumed by Secure Transport -- fed to `sslReadFunc` without ever
    /// blocking there (see that function's doc comment for why).
    private var rawFeed: [UInt8] = []
    /// Decrypted application bytes handed back by `SSLRead` but not yet
    /// claimed by a caller -- the same "leftover" buffering pattern every
    /// other `Session` in this codebase uses for `readAvailable`/`readExactly`.
    private var plainBuffered: [UInt8] = []
    /// The deadline for whichever blocking Secure Transport call is
    /// currently running on `ioQueue` -- stashed here (rather than threaded
    /// as a parameter) because `sslReadFunc`/`sslWriteFunc` are plain C
    /// function pointers with no room for extra arguments. Safe to share
    /// one field for this: `ioQueue` is serial, so exactly one operation
    /// (and therefore one deadline) is ever in flight at a time.
    private var currentOperationTimeout: TimeInterval?

    private init(underlying: any ProxyTransport, allowInsecure: Bool) {
        self.underlying = underlying
        self.allowInsecure = allowInsecure
    }

    /// Runs the TLS client handshake over `underlying`, returning a session
    /// ready to carry a protocol's own framing (e.g. Trojan's header) once
    /// it returns. `transport` is a fresh `TCPConn` when TLS wraps the very
    /// first hop of a chain, or a previous hop's already-open `Session` when
    /// it's stacked on top of one.
    public static func handshake(over underlying: any ProxyTransport, options: TLSOptions, timeout: TimeInterval? = 10) async throws -> TLSConn {
        let conn = TLSConn(underlying: underlying, allowInsecure: options.allowInsecure)
        try await conn.performHandshake(serverName: options.serverName, timeout: timeout)
        return conn
    }

    // MARK: - Handshake

    private func performHandshake(serverName: String, timeout: TimeInterval?) async throws {
        guard let ctx = SSLCreateContext(nil, .clientSide, .streamType) else {
            throw TLSError.failed(errSecParam)
        }
        context = ctx

        let selfPtr = Unmanaged.passUnretained(self).toOpaque()
        SSLSetConnection(ctx, selfPtr)
        SSLSetIOFuncs(ctx, TLSConn.sslReadFunc, TLSConn.sslWriteFunc)
        SSLSetPeerDomainName(ctx, serverName, serverName.utf8.count)
        if allowInsecure {
            SSLSetSessionOption(ctx, .breakOnServerAuth, true)
        }

        try await runOnIOQueue(timeout: timeout) {
            while true {
                switch SSLHandshake(ctx) {
                case errSecSuccess:
                    return
                case errSSLPeerAuthCompleted:
                    // Only reached when `allowInsecure` set `.breakOnServerAuth`
                    // above -- accept whatever certificate the peer presented
                    // without evaluating trust, and loop back into
                    // `SSLHandshake` to resume it. Without that option, Secure
                    // Transport performs its own default system-trust
                    // validation inline and never pauses here at all, so this
                    // case is unreachable in that case.
                    continue
                case errSSLWouldBlock:
                    // `sslReadFunc` never blocks (see its doc comment) -- it
                    // only ever reports what's already in `rawFeed`, so a
                    // would-block here means Secure Transport needs more
                    // ciphertext than that currently holds. Fetch one chunk
                    // (blocking is fine: we're on `ioQueue`) and loop back
                    // into `SSLHandshake` to retry with it queued up.
                    let raw = try self.blockingReadAvailable()
                    if raw.isEmpty { throw ProxyError.connectionClosed }
                    self.rawFeed += raw
                case let status:
                    throw TLSError.failed(status)
                }
            }
        }
    }

    // MARK: - Sending (plaintext in, ciphertext out over `underlying`)

    /// Encrypts and sends `bytes`. Runs on `ioQueue`: `SSLWrite` calls
    /// `sslWriteFunc` synchronously, which itself blocks (via
    /// `blockingSend`) until `underlying.send` completes -- safe here
    /// precisely because `ioQueue` is a dedicated thread, not a cooperative
    /// Swift concurrency one.
    public func send(_ bytes: [UInt8], timeout: TimeInterval? = nil) async throws {
        guard !bytes.isEmpty else { return }
        try await runOnIOQueue(timeout: timeout) {
            var processed = 0
            let status = bytes.withUnsafeBytes { buf -> OSStatus in
                SSLWrite(self.context, buf.baseAddress, buf.count, &processed)
            }
            guard status == errSecSuccess, processed == bytes.count else { throw TLSError.failed(status) }
        }
    }

    // MARK: - Receiving (ciphertext in over `underlying`, plaintext out)

    public func readAvailable(timeout: TimeInterval? = nil) async throws -> [UInt8] {
        if !plainBuffered.isEmpty {
            let result = plainBuffered
            plainBuffered = []
            return result
        }
        return try await pumpRead(timeout: timeout)
    }

    /// Exact-length read for a protocol stacked *on top of* this TLS hop
    /// (or for this session's own opener to read the fixed-shape parts of a
    /// server's plaintext reply): buffers across as many `pumpRead` calls as
    /// needed, the same pattern every other `Session.readExactly` uses.
    public func readExactly(_ n: Int, timeout: TimeInterval? = nil) async throws -> [UInt8] {
        while plainBuffered.count < n {
            let chunk = try await pumpRead(timeout: timeout)
            if chunk.isEmpty { throw ProxyError.connectionClosed }
            plainBuffered += chunk
        }
        let result = Array(plainBuffered.prefix(n))
        plainBuffered.removeFirst(n)
        return result
    }

    /// One `SSLRead` pump: returns as soon as *any* decrypted plaintext is
    /// available, fetching more raw ciphertext from `underlying` only as
    /// needed -- not "block until a full 64KB buffer fills", which is what
    /// naively calling `SSLRead` with a large length and fully-blocking I/O
    /// functions would do (Secure Transport's documented behavior: blocking
    /// I/O functions make `SSLRead` block until the *entire* requested
    /// length is read). Runs on `ioQueue` for the same reason `send` does.
    private func pumpRead(timeout: TimeInterval?) async throws -> [UInt8] {
        try await runOnIOQueue(timeout: timeout) {
            while true {
                var buffer = [UInt8](repeating: 0, count: 65536)
                var processed = 0
                let status = buffer.withUnsafeMutableBytes { buf -> OSStatus in
                    SSLRead(self.context, buf.baseAddress!, buf.count, &processed)
                }
                switch status {
                case errSecSuccess:
                    return Array(buffer.prefix(processed))
                case errSSLWouldBlock where processed > 0:
                    return Array(buffer.prefix(processed))
                case errSSLWouldBlock:
                    // Secure Transport drained everything it could decrypt
                    // from `rawFeed` and needs more ciphertext -- fetch one
                    // chunk (blocking is fine: we're on `ioQueue`) and retry.
                    let raw = try self.blockingReadAvailable()
                    if raw.isEmpty { return [] } // clean EOF on the underlying transport
                    self.rawFeed += raw
                case errSSLClosedGraceful, errSSLClosedAbort, errSSLClosedNoNotify:
                    return []
                default:
                    throw TLSError.failed(status)
                }
            }
        }
    }

    public func close() { underlying.close() }

    // MARK: - Secure Transport I/O callbacks
    //
    // Both are plain C function pointers (no captured context), so they
    // recover `self` from the opaque pointer `SSLSetConnection` stored.
    // They always run synchronously on `ioQueue` (every call into
    // `SSLHandshake`/`SSLRead`/`SSLWrite` above is itself wrapped in
    // `runOnIOQueue`), so touching this instance's plain (non-atomic) state
    // from them is safe.

    /// Never blocks: hands back whatever's already in `rawFeed` (possibly
    /// less than requested -- returning `errSSLWouldBlock` for a short read
    /// is Secure Transport's documented non-blocking contract) rather than
    /// reaching back into `underlying` itself. That's what lets `pumpRead`
    /// above return as soon as one chunk's worth of plaintext is ready
    /// instead of Secure Transport blocking this function until a caller's
    /// entire (possibly 64KB) request is satisfied.
    private static let sslReadFunc: SSLReadFunc = { connectionRef, data, dataLength in
        let conn = Unmanaged<TLSConn>.fromOpaque(connectionRef).takeUnretainedValue()
        let requested = dataLength.pointee
        let n = min(requested, conn.rawFeed.count)
        if n > 0 {
            conn.rawFeed.withUnsafeBufferPointer { src in
                data.copyMemory(from: src.baseAddress!, byteCount: n)
            }
            conn.rawFeed.removeFirst(n)
        }
        dataLength.pointee = n
        return n == requested ? errSecSuccess : errSSLWouldBlock
    }

    /// Blocks (via `blockingSend`) until `underlying.send` completes --
    /// unlike the read side, there's no "partial write" concern to preserve
    /// responsiveness for, so this stays simple and just waits.
    private static let sslWriteFunc: SSLWriteFunc = { connectionRef, data, dataLength in
        let conn = Unmanaged<TLSConn>.fromOpaque(connectionRef).takeUnretainedValue()
        let toWrite = dataLength.pointee
        let bytes = Array(UnsafeRawBufferPointer(start: data, count: toWrite))
        do {
            try conn.blockingSend(bytes)
            dataLength.pointee = toWrite
            return errSecSuccess
        } catch {
            dataLength.pointee = 0
            return errSSLClosedAbort
        }
    }

    // MARK: - Bridging ioQueue's synchronous world to `underlying`'s async one
    //
    // `Task { ... }` below runs on Swift concurrency's cooperative pool, not
    // `ioQueue` -- only the `sem.wait()` blocks `ioQueue`'s dedicated
    // thread, so the pool itself is never starved by these calls.

    private func blockingReadAvailable() throws -> [UInt8] {
        let sem = DispatchSemaphore(value: 0)
        var result: Result<[UInt8], Error> = .success([])
        let timeout = currentOperationTimeout
        Task {
            do { result = .success(try await underlying.readAvailable(timeout: timeout)) }
            catch { result = .failure(error) }
            sem.signal()
        }
        sem.wait()
        return try result.get()
    }

    private func blockingSend(_ bytes: [UInt8]) throws {
        let sem = DispatchSemaphore(value: 0)
        var thrown: Error?
        let timeout = currentOperationTimeout
        Task {
            do { try await underlying.send(bytes, timeout: timeout) }
            catch { thrown = error }
            sem.signal()
        }
        sem.wait()
        if let thrown { throw thrown }
    }

    /// Runs `body` (a blocking Secure Transport call) on `ioQueue`, bridged
    /// back to this `async` call via a continuation -- the same
    /// register-a-completion shape `TCPConn.raceAgainstDeadline` uses, and
    /// for the same reason: `SSLHandshake` doing *default* (non-`allowInsecure`)
    /// certificate trust evaluation can itself perform network I/O (e.g. an
    /// OCSP/CRL revocation check) that happens entirely inside Secure
    /// Transport/the Security framework, never touching `underlying` at all
    /// -- so `currentOperationTimeout` (which only bounds
    /// `blockingReadAvailable`/`blockingSend`, i.e. waits that *do* go
    /// through `underlying`) can't put a ceiling on it. This second, outer
    /// deadline is what actually bounds that case: confirmed necessary
    /// against a real hang in exactly this scenario (a self-signed peer,
    /// `allowInsecure: false`, on a network where the resulting revocation
    /// check stalls rather than failing fast).
    ///
    /// Unlike `TCPConn.raceAgainstDeadline`, there's no way to cancel `body`
    /// itself once it's blocked inside Secure Transport -- so timing out
    /// only makes the *caller* stop waiting; `ioQueue`'s thread stays
    /// occupied until the underlying call eventually returns on its own.
    /// That's still strictly better than an indefinite hang for every other
    /// caller of this `TLSConn`, since `ioQueue` only serializes calls on
    /// *this* instance, not globally.
    private func runOnIOQueue<T>(timeout: TimeInterval?, _ body: @escaping () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<T, Error>) in
            let lock = NSLock()
            var didResume = false
            func resumeOnce(_ result: Result<T, Error>) {
                lock.lock()
                let shouldResume = !didResume
                didResume = true
                lock.unlock()
                guard shouldResume else { return }
                cont.resume(with: result)
            }

            ioQueue.async {
                self.currentOperationTimeout = timeout
                do { resumeOnce(.success(try body())) }
                catch { resumeOnce(.failure(error)) }
            }

            if let timeout {
                DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                    resumeOnce(.failure(ProxyError.timedOut))
                }
            }
        }
    }
}
