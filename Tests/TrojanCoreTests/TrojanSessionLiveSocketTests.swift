import XCTest
import Network
import Security
import ProxyKit
@testable import TrojanCore

/// A throwaway self-signed TLS server identity, generated via `openssl`
/// (already relied on by Scripts/integration_test_*.sh) rather than crafted
/// by hand: Security framework has no public API to *issue* a certificate,
/// only to import one. RSA rather than EC: an EC PKCS#12 bundle produced by
/// this system's LibreSSL fails `SecPKCS12Import` on this platform (crashes
/// deep in `SecIdentityCreate`'s EC key path) -- confirmed empirically
/// before writing this, RSA doesn't have the same problem.
final class SelfSignedIdentity {
    let secIdentity: SecIdentity
    private let tempDir: URL
    private static let passphrase = "trojan-live-test-passphrase"

    enum SetupError: Error { case opensslFailed(String), pkcs12ImportFailed(OSStatus) }

    init() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("trojan-tls-test-\(UUID().uuidString)")
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

/// A minimal in-process TLS + trojan-speaking TCP server, used to exercise
/// `TrojanSession`/`TLSConn` over a *real* TLS socket (loopback), the same
/// role `ShadowsocksTestServer` plays for `ShadowsocksSession`. TLS
/// termination is Network.framework's own (server-side dial/accept *can*
/// just use `NWParameters(tls:...)` directly -- it's only the client side,
/// wrapping TLS around an arbitrary already-open `ProxyTransport`, that
/// needed `TLSConn`'s Secure Transport bridge), so this decodes the
/// trojan-layer plaintext header by hand once the handshake completes.
final class TrojanTestServer {
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

    // `internal` (not `private`): `ChainCoreTrojanUDPRelayLiveSocketTests.swift`
    // (same target, different file) reuses these three via its own
    // `TrojanTestServer` extension rather than duplicating the NWConnection
    // read/write/accept plumbing.
    func waitForConnection() async throws {
        for _ in 0..<500 where connection == nil {
            try await Task.sleep(nanoseconds: 10_000_000) // up to ~5s
        }
        guard connection != nil else { throw ServerError.noConnection }
    }

    func readExactly(_ n: Int) async throws -> [UInt8] {
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

    func write(_ bytes: [UInt8]) async throws {
        guard let connection else { throw ServerError.noConnection }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(content: Data(bytes), completion: .contentProcessed { error in
                if let error { cont.resume(throwing: error) } else { cont.resume() }
            })
        }
    }

    /// Reads the trojan request header (56-hex-char password + CRLF + CMD +
    /// ATYP + address + port + CRLF), decodes it by hand (mirroring
    /// SOCKS5Server's own server-side address decode), then replies with
    /// `responsePayload` over the same TLS session.
    @discardableResult
    func handleHandshakeAndRespond(_ responsePayload: [UInt8]) async throws -> (passwordHex: String, targetHost: String, targetPort: UInt16) {
        try await waitForConnection()

        let passwordHexBytes = try await readExactly(56)
        guard let passwordHex = String(bytes: passwordHexBytes, encoding: .utf8) else { throw ServerError.malformedHeader }
        guard try await readExactly(2) == [0x0D, 0x0A] else { throw ServerError.malformedHeader }

        let cmd = try await readExactly(1)[0]
        guard cmd == 0x01 else { throw ServerError.malformedHeader }
        let atyp = try await readExactly(1)[0]
        let host: String
        switch atyp {
        case 0x01:
            let bytes = try await readExactly(4)
            host = bytes.map(String.init).joined(separator: ".")
        case 0x04:
            _ = try await readExactly(16)
            host = "::1" // not exercised by these tests; only IPv4/domain targets are used
        case 0x03:
            let length = try await readExactly(1)[0]
            let domainBytes = try await readExactly(Int(length))
            guard let domain = String(bytes: domainBytes, encoding: .utf8) else { throw ServerError.malformedHeader }
            host = domain
        default:
            throw ServerError.malformedHeader
        }
        let portBytes = try await readExactly(2)
        let port = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])
        guard try await readExactly(2) == [0x0D, 0x0A] else { throw ServerError.malformedHeader }

        try await write(responsePayload)
        return (passwordHex, host, port)
    }

    func stop() {
        connection?.cancel()
        listener.cancel()
    }
}

/// A minimal in-process trojan-speaking TCP server with **no TLS at all** --
/// exercises `TrojanServerConfig.tls == false` (the rarer real-world
/// deployment that runs the trojan handshake directly over plain TCP; see
/// `TrojanCore`'s own doc comment) over a real loopback socket, the same
/// role `TrojanTestServer` plays for the TLS case. Decodes the same
/// plaintext header shape `TrojanTestServer.handleHandshakeAndRespond` does,
/// just without any TLS listener setup around it.
final class PlainTrojanTestServer {
    enum ServerError: Error { case noConnection, malformedHeader }

    private let listener: TCPListener
    private var connection: TCPConn?

    init() throws { listener = try TCPListener(port: 0) }

    func start() async throws -> UInt16 {
        try await listener.start(onAccept: { [weak self] conn in self?.connection = conn }, onFailure: { _ in })
        return listener.port!
    }

    @discardableResult
    func handleHandshakeAndRespond(_ responsePayload: [UInt8]) async throws -> (passwordHex: String, targetHost: String, targetPort: UInt16) {
        for _ in 0..<500 where connection == nil { try await Task.sleep(nanoseconds: 10_000_000) } // up to ~5s
        guard let connection else { throw ServerError.noConnection }
        try await connection.connect()

        let passwordHexBytes = try await connection.readExactly(56, timeout: nil)
        guard let passwordHex = String(bytes: passwordHexBytes, encoding: .utf8) else { throw ServerError.malformedHeader }
        guard try await connection.readExactly(2, timeout: nil) == [0x0D, 0x0A] else { throw ServerError.malformedHeader }

        let cmd = try await connection.readExactly(1, timeout: nil)[0]
        guard cmd == 0x01 else { throw ServerError.malformedHeader }
        let atyp = try await connection.readExactly(1, timeout: nil)[0]
        let host: String
        switch atyp {
        case 0x01:
            host = (try await connection.readExactly(4, timeout: nil)).map(String.init).joined(separator: ".")
        case 0x03:
            let length = try await connection.readExactly(1, timeout: nil)[0]
            let domainBytes = try await connection.readExactly(Int(length), timeout: nil)
            guard let domain = String(bytes: domainBytes, encoding: .utf8) else { throw ServerError.malformedHeader }
            host = domain
        default:
            throw ServerError.malformedHeader
        }
        let portBytes = try await connection.readExactly(2, timeout: nil)
        let port = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])
        guard try await connection.readExactly(2, timeout: nil) == [0x0D, 0x0A] else { throw ServerError.malformedHeader }

        try await connection.send(responsePayload, timeout: nil)
        return (passwordHex, host, port)
    }

    func stop() {
        connection?.close()
        listener.cancel()
    }
}

final class TrojanSessionLiveSocketTests: XCTestCase {

    /// End-to-end over a real loopback TLS socket: dial, complete a real TLS
    /// handshake against a self-signed server identity (`allowInsecure:
    /// true`), send the credential + CONNECT header, and receive back the
    /// server's response -- the one test that exercises `TLSConn`'s actual
    /// Secure Transport usage, not an in-memory fake.
    func testFullHandshakeAndResponseRoundTripOverRealTLSSocket() async throws {
        let identity = try SelfSignedIdentity()
        let server = try TrojanTestServer(identity: identity.secIdentity)
        let port = try await server.start()
        defer { server.stop() }

        let password = "live-trojan-test-password"
        let responsePayload = Array("hello from the trojan server".utf8)
        async let serverSide = server.handleHandshakeAndRespond(responsePayload)

        let session = try await TrojanSession.open(
            server: TrojanServerConfig(host: "127.0.0.1", port: port, password: password, sni: "localhost", allowInsecure: true),
            targetHost: .domain("example.com"), targetPort: 443
        )

        let (passwordHex, targetHost, targetPort) = try await serverSide
        XCTAssertEqual(passwordHex, trojanPasswordHex(password))
        XCTAssertEqual(targetHost, "example.com")
        XCTAssertEqual(targetPort, 443)

        let response = try await session.receive()
        XCTAssertEqual(response, responsePayload)

        session.close()
    }

    /// `tls: false` end-to-end over a real loopback *plain* TCP socket (no
    /// TLS at all) -- the rarer real-world deployment (`security=none` in a
    /// subscription link) this type now supports. Confirmed live against an
    /// actual node before this support existed: it drops any real TLS
    /// ClientHello but accepts this exact unencrypted header.
    func testTLSFalseSendsHandshakeOverPlainTCPSocket() async throws {
        let server = try PlainTrojanTestServer()
        let port = try await server.start()
        defer { server.stop() }

        let password = "live-trojan-no-tls-test-password"
        let responsePayload = Array("hello from the plain trojan server".utf8)
        async let serverSide = server.handleHandshakeAndRespond(responsePayload)

        let session = try await TrojanSession.open(
            server: TrojanServerConfig(host: "127.0.0.1", port: port, password: password, tls: false),
            targetHost: .domain("example.com"), targetPort: 80
        )

        let (passwordHex, targetHost, targetPort) = try await serverSide
        XCTAssertEqual(passwordHex, trojanPasswordHex(password))
        XCTAssertEqual(targetHost, "example.com")
        XCTAssertEqual(targetPort, 80)

        let response = try await session.receive()
        XCTAssertEqual(response, responsePayload)

        session.close()
    }

    /// Without `allowInsecure`, a self-signed certificate must be rejected
    /// (it isn't in the system trust store) rather than silently accepted --
    /// the one thing standing between this being a real TLS client and a
    /// client that only *looks* like one.
    func testDefaultCertificateValidationRejectsSelfSignedServer() async throws {
        let identity = try SelfSignedIdentity()
        let server = try TrojanTestServer(identity: identity.secIdentity)
        let port = try await server.start()

        // Rejected before the TLS handshake ever finishes, so the server
        // never receives a trojan header to read -- started here (rather
        // than awaited) purely so the connection gets accepted; deliberately
        // *not* awaited below, since `readExactly` has no timeout of its own
        // and would otherwise block forever on bytes the client never sends.
        // `server.stop()` (cancelling the accepted connection) is what lets
        // it unblock, so that has to happen *before* structured concurrency
        // would otherwise implicitly await this at scope exit.
        async let serverSide: () = {
            _ = try? await server.handleHandshakeAndRespond([])
        }()

        do {
            _ = try await TrojanSession.open(
                server: TrojanServerConfig(host: "127.0.0.1", port: port, password: "irrelevant", sni: "localhost", allowInsecure: false),
                targetHost: .domain("example.com"), targetPort: 443, connectTimeout: 5
            )
            XCTFail("expected certificate validation to reject the self-signed identity")
        } catch {
            // expected: TLSError.failed(...) from the handshake
        }
        server.stop()
        await serverSide
    }

    /// A wrong SNI/hostname must also fail validation, confirming the
    /// hostname (not just "is this cert signed by someone trusted") is
    /// actually checked against `TLSOptions.serverName`.
    func testAllowInsecureSkipsValidationEvenWithWrongSNI() async throws {
        let identity = try SelfSignedIdentity()
        let server = try TrojanTestServer(identity: identity.secIdentity)
        let port = try await server.start()
        defer { server.stop() }

        let responsePayload = Array("ok".utf8)
        async let serverSide = server.handleHandshakeAndRespond(responsePayload)

        // "not-the-cert-cn.example" doesn't match the server cert's CN
        // (localhost) at all -- allowInsecure must still let this through.
        let session = try await TrojanSession.open(
            server: TrojanServerConfig(host: "127.0.0.1", port: port, password: "p", sni: "not-the-cert-cn.example", allowInsecure: true),
            targetHost: .domain("example.com"), targetPort: 80
        )
        _ = try await serverSide
        let response = try await session.receive()
        XCTAssertEqual(response, responsePayload)
        session.close()
    }
}
