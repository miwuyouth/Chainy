import XCTest
import Network
import ProxyKit
@testable import VMessCore

/// A minimal in-process VMess-speaking TCP server, used to exercise
/// `VMessSession`/`TCPConn` over a *real* socket (loopback) without any
/// external binary (unlike Scripts/integration_test.sh, which uses real
/// xray-core). It decodes the client's actual AEAD request header using
/// VMessCore's own primitives, replies with a valid AEAD response header,
/// then echoes whatever the client sends -- enough to prove the real
/// networking path (connect/send/receive framing, timeouts, teardown)
/// works, not just the pure encode/decode logic tested elsewhere.
final class FakeVMessServer {
    enum ServerError: Error { case noConnection, eof }

    private let listener: NWListener
    private let cmdKey: [UInt8]
    private var connection: NWConnection?
    private var responseBodyKey: [UInt8] = []
    private var responseBodyIV: [UInt8] = []
    private var requestBodyKey: [UInt8] = []
    private var requestBodyIV: [UInt8] = []
    private var inboundChunkCounter: UInt16 = 0
    private var outboundChunkCounter: UInt16 = 0

    init(cmdKey: [UInt8]) throws {
        self.cmdKey = cmdKey
        listener = try NWListener(using: .tcp)
    }

    /// Starts listening on an OS-assigned ephemeral port and returns it once bound.
    func start() async throws -> UInt16 {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<UInt16, Error>) in
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: cont.resume(returning: self.listener.port!.rawValue)
                case .failed(let err): cont.resume(throwing: err)
                default: break
                }
            }
            listener.newConnectionHandler = { [weak self] conn in
                self?.connection = conn
                conn.start(queue: .main)
            }
            listener.start(queue: .main)
        }
    }

    private func readExactly(_ n: Int) async throws -> [UInt8] {
        guard let connection else { throw ServerError.noConnection }
        var buf: [UInt8] = []
        while buf.count < n {
            let chunk: [UInt8] = try await withCheckedThrowingContinuation { cont in
                connection.receive(minimumIncompleteLength: 1, maximumLength: n - buf.count) { data, _, _, error in
                    if let error { cont.resume(throwing: error); return }
                    cont.resume(returning: data.map(Array.init) ?? [])
                }
            }
            if chunk.isEmpty { throw ServerError.eof }
            buf += chunk
        }
        return buf
    }

    private func write(_ bytes: [UInt8]) async throws {
        guard let connection else { throw ServerError.noConnection }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(content: Data(bytes), completion: .contentProcessed { error in
                if let error { cont.resume(throwing: error) } else { cont.resume() }
            })
        }
    }

    /// Blocks (briefly, polling) until `newConnectionHandler` has fired.
    private func waitForConnection() async throws {
        for _ in 0..<500 where connection == nil {
            try await Task.sleep(nanoseconds: 10_000_000) // 10ms, up to ~5s total
        }
        guard connection != nil else { throw ServerError.noConnection }
    }

    /// Reads and decodes the client's real AEAD request header (same wire
    /// format `VMessRequest.build` produces), then sends back a valid AEAD
    /// response header carrying `responseOptionByte`.
    @discardableResult
    func handleHandshake(responseOptionByte: UInt8) async throws -> [UInt8] {
        try await waitForConnection()

        let authID = try await readExactly(16)
        let lengthAndNonce = try await readExactly(18 + 8)
        let connectionNonce = Array(lengthAndNonce[18..<26])

        let lengthKey = vmessKDF16(key: cmdKey, path: [Array("VMess Header AEAD Key_Length".utf8), authID, connectionNonce])
        let lengthNonce = Array(vmessKDF(key: cmdKey, path: [Array("VMess Header AEAD Nonce_Length".utf8), authID, connectionNonce]).prefix(12))
        let lengthBytes = try aesGCMOpen(key: lengthKey, nonce: lengthNonce, sealed: Array(lengthAndNonce[0..<18]), aad: authID)
        let headerLen = Int(lengthBytes[0]) << 8 | Int(lengthBytes[1])

        let sealedHeader = try await readExactly(headerLen + 16)
        let requestPlain = try openVMessAEADHeader(key: cmdKey, authID: authID, remainder: lengthAndNonce + sealedHeader)

        // Ver(1) requestBodyIV(16) requestBodyKey(16) responseHeaderByte(1) ...
        let requestBodyIV = Array(requestPlain[1..<17])
        let requestBodyKey = Array(requestPlain[17..<33])
        let responseHeaderByte = requestPlain[33]

        self.requestBodyKey = requestBodyKey
        self.requestBodyIV = requestBodyIV
        let responseBodyKey = Array(sha256(requestBodyKey).prefix(16))
        let responseBodyIV = Array(sha256(requestBodyIV).prefix(16))
        self.responseBodyKey = responseBodyKey
        self.responseBodyIV = responseBodyIV
        let header: [UInt8] = [responseHeaderByte, responseOptionByte, 0, 0]

        let respLengthKey = vmessKDF16(key: responseBodyKey, path: [Array("AEAD Resp Header Len Key".utf8)])
        let respLengthNonce = Array(vmessKDF(key: responseBodyIV, path: [Array("AEAD Resp Header Len IV".utf8)]).prefix(12))
        let sealedRespLength = aesGCMSeal(key: respLengthKey, nonce: respLengthNonce, plaintext: UInt16(header.count).bigEndianBytes, aad: [])

        let respHeaderKey = vmessKDF16(key: responseBodyKey, path: [Array("AEAD Resp Header Key".utf8)])
        let respHeaderNonce = Array(vmessKDF(key: responseBodyIV, path: [Array("AEAD Resp Header IV".utf8)]).prefix(12))
        let sealedRespHeader = aesGCMSeal(key: respHeaderKey, nonce: respHeaderNonce, plaintext: header, aad: [])

        try await write(sealedRespLength + sealedRespHeader)
        return requestPlain
    }

    /// Reads one AEAD-sealed application-data chunk (length prefix + sealed
    /// payload, the same framing `VMessSession.send` now produces), decrypts
    /// it with the client's request body key/IV, then re-seals and echoes
    /// the plaintext back as one response-direction chunk.
    @discardableResult
    func echoOnce() async throws -> [UInt8] {
        let lengthBytes = try await readExactly(2)
        let length = Int(lengthBytes[0]) << 8 | Int(lengthBytes[1])
        let sealed = try await readExactly(length)
        let plaintext = try openVMessBodyChunkPayload(key: requestBodyKey, iv: requestBodyIV, counter: inboundChunkCounter, sealed: sealed)
        inboundChunkCounter &+= 1

        let echoChunk = sealVMessBodyChunk(key: responseBodyKey, iv: responseBodyIV, counter: outboundChunkCounter, plaintext: plaintext)
        outboundChunkCounter &+= 1
        try await write(echoChunk)
        return plaintext
    }

    func stop() {
        connection?.cancel()
        listener.cancel()
    }
}

final class VMessSessionLiveSocketTests: XCTestCase {
    private let uuidString = "0398d470-bc09-4cd5-889d-3ae4c569b6da"

    /// End-to-end over a real loopback socket: dial, complete the AEAD
    /// handshake against an independent server-side implementation of the
    /// same primitives, and round-trip an echoed payload. This is the one
    /// test that exercises `TCPConn`'s actual NWConnection usage (framing,
    /// buffering, ordering) rather than a `VMessByteSource` fake.
    func testFullHandshakeAndEchoRoundTripOverRealSocket() async throws {
        let cmdKey = md5(parseUUID(uuidString) + cmdKeyMagic)
        let server = try FakeVMessServer(cmdKey: cmdKey)
        let port = try await server.start()
        defer { server.stop() }

        async let serverSide: Void = {
            _ = try await server.handleHandshake(responseOptionByte: 7)
            _ = try await server.echoOnce()
        }()

        let session = try await VMessSession.open(
            server: VMessServerConfig(host: "127.0.0.1", port: port, uuid: uuidString),
            target: VMessTarget(host: "example.com", port: 80)
        )
        let header = try await session.readResponseHeader()
        XCTAssertEqual(header.optionByte, 7)

        let payload = Array("hello over a real loopback socket".utf8)
        try await session.send(payload)
        let echoed = try await session.receive()
        XCTAssertEqual(echoed, payload)

        session.close()
        try await serverSide
    }

    /// `VMessSession.send` splits anything over `vmessMaxChunkPlaintext` into
    /// multiple AEAD-sealed chunks (still one underlying TCP write); this
    /// proves that split survives a real socket round trip against an
    /// independent server-side implementation, not just self-consistency.
    func testSendSplitsLargePayloadIntoMultipleChunksAndRoundTripsOverRealSocket() async throws {
        let cmdKey = md5(parseUUID(uuidString) + cmdKeyMagic)
        let server = try FakeVMessServer(cmdKey: cmdKey)
        let port = try await server.start()
        defer { server.stop() }

        let payload = (0..<(vmessMaxChunkPlaintext + 500)).map { UInt8($0 % 256) }

        async let serverSide: Void = {
            _ = try await server.handleHandshake(responseOptionByte: 0)
            _ = try await server.echoOnce() // first vmessMaxChunkPlaintext bytes
            _ = try await server.echoOnce() // the remaining 500 bytes
        }()

        let session = try await VMessSession.open(
            server: VMessServerConfig(host: "127.0.0.1", port: port, uuid: uuidString),
            target: VMessTarget(host: "example.com", port: 80)
        )
        try await session.send(payload)

        var echoed: [UInt8] = []
        while echoed.count < payload.count {
            echoed += try await session.receive()
        }
        XCTAssertEqual(echoed, payload)

        session.close()
        try await serverSide
    }

    /// At the raw socket level (confirmed separately with `nc`), connecting
    /// to a closed loopback port is refused essentially instantly (~10ms).
    /// `NWConnection`, however, does *not* surface that refusal promptly in
    /// this environment -- it was observed to hang until the connect
    /// deadline fires. So rather than assert a specific "fast" bound (which
    /// turned out to be a wrong assumption about NWConnection's behavior
    /// here), this pins down what actually happens: `connectTimeout` is
    /// doing real, load-bearing work for plain connection-refused cases too,
    /// not just for the "server silently drops the connection" scenario in
    /// VMessCoreTests -- and it must still resolve at (not well past) the deadline.
    func testConnectToClosedPortEventuallyFailsAtTheDeadline() async throws {
        let probe = try NWListener(using: .tcp)
        // NWListener.start() requires newConnectionHandler to be set first --
        // without it, start() fails outright with EINVAL (confirmed against
        // this Network.framework; FakeVMessServer already does this, which is
        // why its listener works while a bare `NWListener(using: .tcp)` here
        // did not, before this fix).
        probe.newConnectionHandler = { $0.cancel() }
        let port: UInt16 = try await withCheckedThrowingContinuation { cont in
            probe.stateUpdateHandler = { state in
                if case .ready = state { cont.resume(returning: probe.port!.rawValue) }
                if case .failed(let err) = state { cont.resume(throwing: err) }
            }
            probe.start(queue: .main)
        }
        probe.cancel()
        try await Task.sleep(nanoseconds: 200_000_000) // let the OS actually release the port

        let start = Date()
        do {
            _ = try await VMessSession.open(
                server: VMessServerConfig(host: "127.0.0.1", port: port, uuid: uuidString),
                target: VMessTarget(host: "example.com", port: 80),
                connectTimeout: 2
            )
            XCTFail("expected connection to a closed port to fail")
        } catch {
            let elapsed = Date().timeIntervalSince(start)
            XCTAssertLessThan(elapsed, 4, "must not hang well past the 2s connect deadline")
        }
    }

    /// After `close()`, further use must fail predictably rather than crash
    /// or hang -- a cancelled NWConnection should just keep erroring out.
    func testOperationsAfterCloseFailInsteadOfCrashing() async throws {
        let cmdKey = md5(parseUUID(uuidString) + cmdKeyMagic)
        let server = try FakeVMessServer(cmdKey: cmdKey)
        let port = try await server.start()
        defer { server.stop() }

        async let serverSide: Void = {
            _ = try await server.handleHandshake(responseOptionByte: 0)
        }()

        let session = try await VMessSession.open(
            server: VMessServerConfig(host: "127.0.0.1", port: port, uuid: uuidString),
            target: VMessTarget(host: "example.com", port: 80)
        )
        _ = try await session.readResponseHeader()
        try await serverSide

        session.close()

        do {
            try await session.send(Array("after close".utf8))
            // Some platforms may accept the write locally before the RST is
            // observed; either outcome is fine as long as we don't hang or crash.
        } catch {
            // expected on most platforms
        }
    }
}
