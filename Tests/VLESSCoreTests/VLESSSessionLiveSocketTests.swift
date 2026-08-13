import XCTest
import Network
import Security
import ProxyKit
@testable import VLESSCore

/// A minimal in-process VLESS-speaking TCP server, used to exercise
/// `VLESSSession`/`TCPConn` over a *real* socket (loopback) without any
/// external binary. It decodes the client's actual plaintext request header
/// (Version + UUID + Addons + Command + Port + Address -- VLESS has no
/// crypto of its own to reproduce, unlike VMess's AEAD header), replies with
/// a valid response header, then echoes whatever the client sends -- enough
/// to prove the real networking path (connect/send/receive framing,
/// timeouts, teardown) works, not just the pure header-building logic
/// tested in VLESSCoreTests.
final class FakeVLESSServer {
    enum ServerError: Error { case noConnection, eof, malformedHeader }

    private let listener: NWListener
    private var connection: NWConnection?

    init() throws {
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

    /// Reads and decodes the client's real VLESS request header, then sends
    /// back a valid (empty-addons) response header immediately followed by
    /// `responsePayload`.
    @discardableResult
    func handleHandshakeAndRespond(_ responsePayload: [UInt8]) async throws -> (uuid: [UInt8], targetHost: String, targetPort: UInt16) {
        try await waitForConnection()

        guard try await readExactly(1) == [0x00] else { throw ServerError.malformedHeader }
        let uuid = try await readExactly(16)
        let addonsLen = try await readExactly(1)[0]
        if addonsLen > 0 { _ = try await readExactly(Int(addonsLen)) }
        guard try await readExactly(1) == [0x01] else { throw ServerError.malformedHeader } // Command = TCP

        let portBytes = try await readExactly(2)
        let port = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])

        let atyp = try await readExactly(1)[0]
        let host: String
        switch atyp {
        case 0x01:
            let bytes = try await readExactly(4)
            host = bytes.map(String.init).joined(separator: ".")
        case 0x03:
            _ = try await readExactly(16)
            host = "::1" // not exercised by these tests; only IPv4/domain targets are used
        case 0x02:
            let length = try await readExactly(1)[0]
            let domainBytes = try await readExactly(Int(length))
            guard let domain = String(bytes: domainBytes, encoding: .utf8) else { throw ServerError.malformedHeader }
            host = domain
        default:
            throw ServerError.malformedHeader
        }

        try await write([0x00, 0x00] + responsePayload) // Version echo + empty addons, then real data
        return (uuid, host, port)
    }

    /// Reads one chunk of raw application bytes and echoes it back verbatim.
    @discardableResult
    func echoOnce() async throws -> [UInt8] {
        guard let connection else { throw ServerError.noConnection }
        let data: [UInt8] = try await withCheckedThrowingContinuation { cont in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, _, error in
                if let error { cont.resume(throwing: error); return }
                cont.resume(returning: data.map(Array.init) ?? [])
            }
        }
        try await write(data)
        return data
    }

    func stop() {
        connection?.cancel()
        listener.cancel()
    }
}

final class VLESSSessionLiveSocketTests: XCTestCase {
    private let uuidString = "0398d470-bc09-4cd5-889d-3ae4c569b6da"

    /// End-to-end over a real loopback socket, `tls: false`: dial, send the
    /// real request header, and round-trip an echoed payload. This is the
    /// one test that exercises `TCPConn`'s actual NWConnection usage
    /// (framing, buffering, ordering) rather than a fake.
    func testFullHandshakeAndEchoRoundTripOverRealSocket() async throws {
        let server = try FakeVLESSServer()
        let port = try await server.start()
        defer { server.stop() }

        async let serverSide: (uuid: [UInt8], targetHost: String, targetPort: UInt16, echoedPayload: [UInt8]) = {
            let handshake = try await server.handleHandshakeAndRespond([])
            let echoed = try await server.echoOnce()
            return (handshake.uuid, handshake.targetHost, handshake.targetPort, echoed)
        }()

        let session = try await VLESSSession.open(
            server: VLESSServerConfig(host: "127.0.0.1", port: port, uuid: uuidString),
            target: VLESSTarget(host: "example.com", port: 80)
        )

        let payload = Array("hello over a real loopback socket".utf8)
        try await session.send(payload)
        let response = try await session.receive()
        XCTAssertEqual(response, payload)

        let result = try await serverSide
        XCTAssertEqual(result.uuid, parseVLESSUUID(uuidString))
        XCTAssertEqual(result.targetHost, "example.com")
        XCTAssertEqual(result.targetPort, 80)
        XCTAssertEqual(result.echoedPayload, payload)

        session.close()
    }

    /// At the raw socket level, connecting to a closed loopback port is
    /// refused, but `NWConnection` doesn't always surface that promptly (see
    /// the identical test in VMessSessionLiveSocketTests) -- `connectTimeout`
    /// must still bound the wait.
    func testConnectToClosedPortEventuallyFailsAtTheDeadline() async throws {
        let probe = try NWListener(using: .tcp)
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
            _ = try await VLESSSession.open(
                server: VLESSServerConfig(host: "127.0.0.1", port: port, uuid: uuidString),
                target: VLESSTarget(host: "example.com", port: 80),
                connectTimeout: 2
            )
            XCTFail("expected connection to a closed port to fail")
        } catch {
            let elapsed = Date().timeIntervalSince(start)
            XCTAssertLessThan(elapsed, 4, "must not hang well past the 2s connect deadline")
        }
    }
}

// MARK: - TLS path

/// A throwaway self-signed TLS server identity, generated via `openssl` --
/// the same approach TrojanCoreTests' `SelfSignedIdentity` uses (see its own
/// doc comment for why: Security framework has no API to *issue* a
/// certificate, only import one, and RSA rather than EC avoids a
/// `SecPKCS12Import` crash observed on this platform for EC bundles).
/// Duplicated here rather than shared across test targets since XCTest
/// targets in this package don't expose test-only helpers to each other.
final class VLESSSelfSignedIdentity {
    let secIdentity: SecIdentity
    private let tempDir: URL
    private static let passphrase = "vless-live-test-passphrase"

    enum SetupError: Error { case opensslFailed(String), pkcs12ImportFailed(OSStatus) }

    init() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("vless-tls-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        tempDir = dir

        let keyPath = dir.appendingPathComponent("key.pem").path
        let certPath = dir.appendingPathComponent("cert.pem").path
        let p12Path = dir.appendingPathComponent("bundle.p12").path

        try Self.run(["req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath,
                       "-days", "1", "-nodes", "-subj", "/CN=localhost"])
        try Self.run(["pkcs12", "-export", "-inkey", keyPath, "-in", certPath, "-out", p12Path,
                       "-passout", "pass:\(Self.passphrase)"])

        let p12Data = try Data(contentsOf: URL(fileURLWithPath: p12Path))
        let options: [String: Any] = [kSecImportExportPassphrase as String: Self.passphrase]
        var rawItems: CFArray?
        let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &rawItems)
        guard status == errSecSuccess, let items = rawItems as? [[String: Any]],
              let identity = items.first?[kSecImportItemIdentity as String] else {
            throw SetupError.pkcs12ImportFailed(status)
        }
        secIdentity = (identity as! SecIdentity)
    }

    private static func run(_ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw SetupError.opensslFailed(arguments.joined(separator: " ")) }
    }

    deinit { try? FileManager.default.removeItem(at: tempDir) }
}

/// A minimal in-process TLS + VLESS-speaking TCP server, exercising
/// `VLESSSession`'s `tls: true` path over a *real* TLS socket (loopback).
/// TLS termination is Network.framework's own (server-side can just use
/// `NWParameters(tls:...)` directly -- it's only the client side, wrapping
/// TLS around an arbitrary already-open transport, that needs `TLSConn`'s
/// Secure Transport bridge), so this decodes the VLESS-layer plaintext
/// header by hand once the handshake completes, same shape `FakeVLESSServer`
/// decodes over a bare socket above.
final class VLESSTLSTestServer {
    enum ServerError: Error { case noConnection, malformedHeader }

    private let listener: NWListener
    private var connection: NWConnection?

    init(identity: SecIdentity) throws {
        let tlsOptions = NWProtocolTLS.Options()
        guard let secIdentity = sec_identity_create(identity) else { throw ServerError.noConnection }
        sec_protocol_options_set_local_identity(tlsOptions.securityProtocolOptions, secIdentity)
        listener = try NWListener(using: NWParameters(tls: tlsOptions, tcp: .init()))
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
            listener.newConnectionHandler = { [weak self] conn in
                self?.connection = conn
                conn.start(queue: .main)
            }
            listener.start(queue: .main)
        }
    }

    private func waitForConnection() async throws {
        for _ in 0..<500 where connection == nil {
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        guard connection != nil else { throw ServerError.noConnection }
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

    @discardableResult
    func handleHandshakeAndRespond(_ responsePayload: [UInt8]) async throws -> (uuid: [UInt8], targetHost: String, targetPort: UInt16) {
        try await waitForConnection()

        guard try await readExactly(1) == [0x00] else { throw ServerError.malformedHeader }
        let uuid = try await readExactly(16)
        let addonsLen = try await readExactly(1)[0]
        if addonsLen > 0 { _ = try await readExactly(Int(addonsLen)) }
        guard try await readExactly(1) == [0x01] else { throw ServerError.malformedHeader }

        let portBytes = try await readExactly(2)
        let port = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])

        let atyp = try await readExactly(1)[0]
        let host: String
        switch atyp {
        case 0x01:
            let bytes = try await readExactly(4)
            host = bytes.map(String.init).joined(separator: ".")
        case 0x02:
            let length = try await readExactly(1)[0]
            let domainBytes = try await readExactly(Int(length))
            guard let domain = String(bytes: domainBytes, encoding: .utf8) else { throw ServerError.malformedHeader }
            host = domain
        default:
            throw ServerError.malformedHeader
        }

        try await write([0x00, 0x00] + responsePayload)
        return (uuid, host, port)
    }

    func stop() {
        connection?.cancel()
        listener.cancel()
    }
}

final class VLESSTLSSessionLiveSocketTests: XCTestCase {
    private let uuidString = "0398d470-bc09-4cd5-889d-3ae4c569b6da"

    /// End-to-end over a real loopback TLS socket, `tls: true`: dial with
    /// native TLS (`allowInsecure: true` against a self-signed identity),
    /// send the request header, and receive the response.
    func testFullHandshakeAndResponseRoundTripOverRealTLSSocket() async throws {
        let identity = try VLESSSelfSignedIdentity()
        let server = try VLESSTLSTestServer(identity: identity.secIdentity)
        let port = try await server.start()
        defer { server.stop() }

        let responsePayload = Array("hello from the vless+tls server".utf8)
        async let serverSide = server.handleHandshakeAndRespond(responsePayload)

        let session = try await VLESSSession.open(
            server: VLESSServerConfig(host: "127.0.0.1", port: port, uuid: uuidString, tls: true, sni: "localhost", allowInsecure: true),
            target: VLESSTarget(host: "example.com", port: 443)
        )

        let (uuidBytes, targetHost, targetPort) = try await serverSide
        XCTAssertEqual(uuidBytes, parseVLESSUUID(uuidString))
        XCTAssertEqual(targetHost, "example.com")
        XCTAssertEqual(targetPort, 443)

        let response = try await session.receive()
        XCTAssertEqual(response, responsePayload)

        session.close()
    }

    /// Without `allowInsecure`, a self-signed certificate must be rejected
    /// rather than silently accepted -- the one thing standing between
    /// `tls: true` being a real TLS client and one that only *looks* like one.
    func testDefaultCertificateValidationRejectsSelfSignedServer() async throws {
        let identity = try VLESSSelfSignedIdentity()
        let server = try VLESSTLSTestServer(identity: identity.secIdentity)
        let port = try await server.start()

        async let serverSide: () = {
            _ = try? await server.handleHandshakeAndRespond([])
        }()

        do {
            _ = try await VLESSSession.open(
                server: VLESSServerConfig(host: "127.0.0.1", port: port, uuid: uuidString, tls: true, sni: "localhost", allowInsecure: false),
                target: VLESSTarget(host: "example.com", port: 443), connectTimeout: 5
            )
            XCTFail("expected certificate validation to reject the self-signed identity")
        } catch {
            // expected: TLS handshake failure
        }
        server.stop()
        await serverSide
    }
}
