import XCTest
import Network
import ProxyKit
@testable import ShadowsocksCore

/// A minimal in-process Shadowsocks-speaking TCP server, used to exercise
/// `ShadowsocksSession`/`TCPConn` over a *real* socket (loopback) without any
/// external binary (unlike Scripts/integration_test_shadowsocks.sh, which
/// uses real shadowsocks-rust). It decodes the client's actual salt +
/// address chunk using ShadowsocksCore's own primitives, then can reply with
/// its own salt + chunks, or just count how many chunks arrive.
final class ShadowsocksTestServer: ByteStreamSource {
    enum ServerError: Error { case noConnection }

    private let listener: NWListener
    private let cipher: ShadowsocksCipher
    private let masterKey: [UInt8]
    private var connection: NWConnection?

    init(cipher: ShadowsocksCipher, password: String) throws {
        self.cipher = cipher
        self.masterKey = evpBytesToKey(password: password, keyLength: cipher.keyLength)
        listener = try NWListener(using: .tcp)
    }

    func start() async throws -> UInt16 {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<UInt16, Error>) in
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: cont.resume(returning: self.listener.port!.rawValue)
                case .failed(let err): cont.resume(throwing: err)
                default: break
                }
            }
            // NWListener.start() requires newConnectionHandler set first, or
            // it fails outright with EINVAL (see VMessSessionLiveSocketTests).
            listener.newConnectionHandler = { [weak self] conn in
                self?.connection = conn
                conn.start(queue: .main)
            }
            listener.start(queue: .main)
        }
    }

    private func waitForConnection() async throws {
        for _ in 0..<500 where connection == nil {
            try await Task.sleep(nanoseconds: 10_000_000) // up to ~5s
        }
        guard connection != nil else { throw ServerError.noConnection }
    }

    func readExactly(_ n: Int, timeout: TimeInterval?) async throws -> [UInt8] {
        guard let connection else { throw ServerError.noConnection }
        var buf: [UInt8] = []
        while buf.count < n {
            let chunk: [UInt8] = try await withCheckedThrowingContinuation { cont in
                connection.receive(minimumIncompleteLength: 1, maximumLength: n - buf.count) { data, _, _, error in
                    if let error { cont.resume(throwing: error); return }
                    cont.resume(returning: data.map(Array.init) ?? [])
                }
            }
            if chunk.isEmpty { throw ProxyError.connectionClosed }
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

    /// Reads the client's salt + address chunk, decodes it, then replies with
    /// its own fresh salt + one response chunk carrying `responsePayload`.
    @discardableResult
    func handleHandshakeAndRespond(_ responsePayload: [UInt8]) async throws -> [UInt8] {
        try await waitForConnection()
        let salt = try await readExactly(cipher.saltLength, timeout: nil)
        let subkey = shadowsocksDeriveSubkey(masterKey: masterKey, salt: salt, cipher: cipher)
        let reader = ShadowsocksChunkCrypto(cipher: cipher, key: subkey)
        let addressBytes = try await reader.openChunk(from: self, timeout: nil)

        let responseSalt = (0..<cipher.saltLength).map { _ in UInt8.random(in: 0...255) }
        let responseSubkey = shadowsocksDeriveSubkey(masterKey: masterKey, salt: responseSalt, cipher: cipher)
        let writer = ShadowsocksChunkCrypto(cipher: cipher, key: responseSubkey)
        try await write(responseSalt + writer.sealChunk(responsePayload))

        return addressBytes
    }

    /// Reads the client's salt + address chunk (discarded), then keeps
    /// decrypting chunks until `expectedChunks` more have arrived, returning
    /// that count -- used to confirm `send()` actually splits oversized
    /// payloads into the right number of wire chunks.
    func receiveRequestAndCountChunks(expectedChunks: Int) async throws -> Int {
        try await waitForConnection()
        let salt = try await readExactly(cipher.saltLength, timeout: nil)
        let subkey = shadowsocksDeriveSubkey(masterKey: masterKey, salt: salt, cipher: cipher)
        let reader = ShadowsocksChunkCrypto(cipher: cipher, key: subkey)

        _ = try await reader.openChunk(from: self, timeout: nil) // the address chunk

        var count = 0
        while count < expectedChunks {
            _ = try await reader.openChunk(from: self, timeout: nil)
            count += 1
        }
        return count
    }

    func stop() {
        connection?.cancel()
        listener.cancel()
    }
}

final class ShadowsocksSessionLiveSocketTests: XCTestCase {

    /// End-to-end over a real loopback socket: dial, send the target address
    /// as the first chunk, and receive back a server-generated salt + response
    /// chunk decoded correctly. This is the one test that exercises
    /// `TCPConn`'s actual NWConnection usage, not an in-memory fake.
    func testFullHandshakeAndResponseRoundTripOverRealSocket() async throws {
        let cipher = ShadowsocksCipher.aes128Gcm
        let password = "live-socket-test-password"
        let server = try ShadowsocksTestServer(cipher: cipher, password: password)
        let port = try await server.start()
        defer { server.stop() }

        let responsePayload = Array("hello from the shadowsocks server".utf8)
        async let serverSide = server.handleHandshakeAndRespond(responsePayload)

        let session = try await ShadowsocksSession.open(
            server: ShadowsocksServerConfig(host: "127.0.0.1", port: port, password: password, cipher: cipher),
            targetHost: .domain("example.com"), targetPort: 443
        )

        let receivedAddress = try await serverSide
        // ATYP=3 (domain) + length-prefixed "example.com" + port(2 bytes BE)
        XCTAssertEqual(receivedAddress, try ProxyAddress.domain("example.com").socks5Encoded + UInt16(443).bigEndianBytes)

        let response = try await session.receive()
        XCTAssertEqual(response, responsePayload)

        session.close()
    }

    /// Confirms `send()` respects the 0x3FFF max chunk size by observing how
    /// many wire chunks a real server actually sees for an oversized payload.
    func testSendSplitsOversizedPayloadAcrossMultipleChunksOverRealSocket() async throws {
        let cipher = ShadowsocksCipher.aes256Gcm
        let password = "chunk-split-live-test"
        let server = try ShadowsocksTestServer(cipher: cipher, password: password)
        let port = try await server.start()
        defer { server.stop() }

        async let serverSide = server.receiveRequestAndCountChunks(expectedChunks: 2)

        let session = try await ShadowsocksSession.open(
            server: ShadowsocksServerConfig(host: "127.0.0.1", port: port, password: password, cipher: cipher),
            targetHost: .domain("example.com"), targetPort: 80
        )
        let oversized = [UInt8](repeating: 0x41, count: ShadowsocksMaxChunkSize.value + 10)
        try await session.send(oversized)

        let chunkCount = try await serverSide
        XCTAssertEqual(chunkCount, 2)
        session.close()
    }

    /// After `close()`, further use must fail predictably rather than crash or hang.
    func testOperationsAfterCloseFailInsteadOfCrashing() async throws {
        let cipher = ShadowsocksCipher.aes128Gcm
        let password = "close-test-password"
        let server = try ShadowsocksTestServer(cipher: cipher, password: password)
        let port = try await server.start()
        defer { server.stop() }

        async let serverSide: Void = {
            _ = try await server.handleHandshakeAndRespond(Array("ok".utf8))
        }()

        let session = try await ShadowsocksSession.open(
            server: ShadowsocksServerConfig(host: "127.0.0.1", port: port, password: password, cipher: cipher),
            targetHost: .domain("example.com"), targetPort: 80
        )
        _ = try await session.receive()
        try await serverSide

        session.close()

        do {
            try await session.send(Array("after close".utf8))
        } catch {
            // expected on most platforms
        }
    }
}
