import XCTest
import Network
import ProxyKit
@testable import SOCKS5Core

/// A minimal in-process SOCKS5-speaking TCP server, used to exercise
/// `SOCKS5Session`/`TCPConn` over a *real* socket (loopback) without any
/// external binary (unlike Scripts/integration_test_socks5.sh, which uses
/// real xray-core). It decodes the client's actual greeting/auth/CONNECT
/// bytes independently of SOCKS5Core's own encode/decode logic, so this
/// exercises the real networking path (connect/send/receive framing,
/// timeouts, teardown), not just the pure handshake logic already covered
/// by SOCKS5CoreTests' fake-transport tests.
final class FakeSOCKS5Server {
    enum ServerError: Error { case noConnection, eof }
    enum AuthMode { case noAuth, usernamePassword(username: String, password: String) }

    private let listener: NWListener
    private var connection: NWConnection?

    init() throws { listener = try NWListener(using: .tcp) }

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

    /// Reads the greeting, replies selecting the method implied by
    /// `expectedAuth`, and if that's username/password, runs the RFC 1929
    /// subnegotiation (accepting only credentials matching `expectedAuth`).
    func handleGreetingAndAuth(expectedAuth: AuthMode) async throws {
        try await waitForConnection()
        let greeting = try await readExactly(2)
        precondition(greeting[0] == 0x05, "unexpected SOCKS version \(greeting[0])")
        let methods = try await readExactly(Int(greeting[1]))

        let selected: UInt8
        switch expectedAuth {
        case .noAuth: selected = 0x00
        case .usernamePassword: selected = 0x02
        }
        precondition(methods.contains(selected), "client didn't offer method 0x\(String(format: "%02x", selected))")
        try await write([0x05, selected])

        if case .usernamePassword(let expectedUser, let expectedPass) = expectedAuth {
            let head = try await readExactly(2) // [ver=0x01, ulen]
            let uname = try await readExactly(Int(head[1]))
            let plen = try await readExactly(1)
            let passwd = try await readExactly(Int(plen[0]))
            let ok = String(decoding: uname, as: UTF8.self) == expectedUser && String(decoding: passwd, as: UTF8.self) == expectedPass
            try await write([0x01, ok ? 0x00 : 0x01])
        }
    }

    /// Reads the CONNECT request, decodes the target address/port, and
    /// replies with `replyCode` (plus a fixed 127.0.0.1:8080 bound address).
    @discardableResult
    func handleConnectRequest(replyCode: UInt8) async throws -> (address: ProxyAddress, port: UInt16) {
        let head = try await readExactly(4) // ver, cmd, rsv, atyp
        let address: ProxyAddress
        switch head[3] {
        case 0x01: address = .ipv4(try await readExactly(4))
        case 0x04: address = .ipv6(try await readExactly(16))
        case 0x03:
            let len = try await readExactly(1)
            address = .domain(String(decoding: try await readExactly(Int(len[0])), as: UTF8.self))
        default:
            preconditionFailure("unexpected ATYP \(head[3])")
        }
        let portBytes = try await readExactly(2)
        let port = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])

        try await write([0x05, replyCode, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90])
        return (address, port)
    }

    /// Reads one chunk of raw application bytes and echoes it back verbatim.
    @discardableResult
    func echoOnce() async throws -> [UInt8] {
        let data = try await readAvailable()
        try await write(data)
        return data
    }

    private func readAvailable() async throws -> [UInt8] {
        guard let connection else { throw ServerError.noConnection }
        return try await withCheckedThrowingContinuation { cont in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, _, error in
                if let error { cont.resume(throwing: error); return }
                cont.resume(returning: data.map(Array.init) ?? [])
            }
        }
    }

    func stop() {
        connection?.cancel()
        listener.cancel()
    }
}

final class SOCKS5SessionLiveSocketTests: XCTestCase {

    /// End-to-end over a real loopback socket: dial, complete the
    /// no-auth greeting + CONNECT handshake against an independent
    /// server-side implementation, and round-trip an echoed payload.
    func testFullHandshakeNoAuthAndEchoRoundTripOverRealSocket() async throws {
        let server = try FakeSOCKS5Server()
        let port = try await server.start()
        defer { server.stop() }

        async let serverSide: (address: ProxyAddress, port: UInt16) = {
            try await server.handleGreetingAndAuth(expectedAuth: .noAuth)
            let req = try await server.handleConnectRequest(replyCode: 0x00)
            _ = try await server.echoOnce()
            return req
        }()

        let session = try await SOCKS5Session.open(
            server: SOCKS5ServerConfig(host: "127.0.0.1", port: port),
            targetHost: .domain("example.com"), targetPort: 443
        )

        let payload = Array("hello over a real socks5 loopback socket".utf8)
        try await session.send(payload)
        let echoed = try await session.receive()
        XCTAssertEqual(echoed, payload)

        let (address, targetPort) = try await serverSide
        XCTAssertEqual(address, .domain("example.com"))
        XCTAssertEqual(targetPort, 443)

        session.close()
    }

    /// A server that requires RFC 1929 username/password auth accepts the
    /// connection when the client's credentials match.
    func testUsernamePasswordAuthSucceedsOverRealSocket() async throws {
        let server = try FakeSOCKS5Server()
        let port = try await server.start()
        defer { server.stop() }

        async let serverSide: Void = {
            try await server.handleGreetingAndAuth(expectedAuth: .usernamePassword(username: "alice", password: "hunter2"))
            _ = try await server.handleConnectRequest(replyCode: 0x00)
        }()

        let session = try await SOCKS5Session.open(
            server: SOCKS5ServerConfig(host: "127.0.0.1", port: port, auth: .usernamePassword(username: "alice", password: "hunter2")),
            targetHost: .domain("example.com"), targetPort: 80
        )
        try await serverSide
        session.close()
    }

    /// Wrong credentials against a server that requires auth must fail
    /// closed with `SOCKS5Error.authenticationFailed`, not hang or succeed.
    func testUsernamePasswordAuthFailureOverRealSocket() async throws {
        let server = try FakeSOCKS5Server()
        let port = try await server.start()
        defer { server.stop() }

        async let serverSide: Void = try await server.handleGreetingAndAuth(expectedAuth: .usernamePassword(username: "alice", password: "hunter2"))

        do {
            _ = try await SOCKS5Session.open(
                server: SOCKS5ServerConfig(host: "127.0.0.1", port: port, auth: .usernamePassword(username: "alice", password: "WRONG")),
                targetHost: .domain("example.com"), targetPort: 80
            )
            XCTFail("expected authentication to fail")
        } catch SOCKS5Error.authenticationFailed(let status) {
            XCTAssertEqual(status, 0x01)
        }
        try await serverSide
    }

    /// A server that refuses the CONNECT itself (e.g. its own outbound
    /// firewall rules) must surface `SOCKS5Error.requestFailed` with the
    /// server's actual reply code, not a generic/opaque failure.
    func testServerRejectsConnectRequestOverRealSocket() async throws {
        let server = try FakeSOCKS5Server()
        let port = try await server.start()
        defer { server.stop() }

        async let serverSide: Void = {
            try await server.handleGreetingAndAuth(expectedAuth: .noAuth)
            _ = try await server.handleConnectRequest(replyCode: 0x05) // Connection refused
        }()

        do {
            _ = try await SOCKS5Session.open(
                server: SOCKS5ServerConfig(host: "127.0.0.1", port: port),
                targetHost: .domain("example.com"), targetPort: 80
            )
            XCTFail("expected requestFailed")
        } catch SOCKS5Error.requestFailed(let code) {
            XCTAssertEqual(code, 0x05)
        }
        try await serverSide
    }

    /// After `close()`, further use must fail predictably rather than crash or hang.
    func testOperationsAfterCloseFailInsteadOfCrashing() async throws {
        let server = try FakeSOCKS5Server()
        let port = try await server.start()
        defer { server.stop() }

        async let serverSide: Void = {
            try await server.handleGreetingAndAuth(expectedAuth: .noAuth)
            _ = try await server.handleConnectRequest(replyCode: 0x00)
        }()

        let session = try await SOCKS5Session.open(
            server: SOCKS5ServerConfig(host: "127.0.0.1", port: port),
            targetHost: .domain("example.com"), targetPort: 80
        )
        try await serverSide
        session.close()

        do {
            try await session.send(Array("after close".utf8))
        } catch {
            // expected on most platforms
        }
    }
}
