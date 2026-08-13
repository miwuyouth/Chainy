import XCTest
import ProxyKit
@testable import HTTPProxyCore

/// Proves `HTTPProxySession` (the outbound/client side) actually
/// interoperates with `HTTPProxyServer.acceptConnect` (the accept side)
/// over a *real* loopback socket -- both halves of the same protocol,
/// implemented independently in this module, exercised end-to-end exactly
/// like `SOCKS5SessionLiveSocketTests`/`TrojanSessionLiveSocketTests` do
/// for their own protocols.
final class HTTPProxySessionLiveSocketTests: XCTestCase {
    private final class AcceptedBox {
        var conn: TCPConn?
    }

    private func waitForAccepted(_ box: AcceptedBox) async throws {
        for _ in 0..<500 where box.conn == nil {
            try await Task.sleep(nanoseconds: 10_000_000) // up to ~5s
        }
        XCTAssertNotNil(box.conn)
    }

    func testFullCONNECTHandshakeAndEchoRoundTripOverRealSocket() async throws {
        let listener = try TCPListener(port: 0)
        let box = AcceptedBox()
        try await listener.start(onAccept: { box.conn = $0 }, onFailure: { _ in })
        defer { listener.cancel() }
        let port = try XCTUnwrap(listener.port)

        async let serverSide: HTTPProxyIncomingRequest = {
            try await waitForAccepted(box)
            let serverConn = try XCTUnwrap(box.conn)
            try await serverConn.connect()
            let request = try await HTTPProxyServer.acceptConnect(over: serverConn)
            let payload = try await serverConn.readExactly(5)
            try await serverConn.send(payload)
            serverConn.close()
            return request
        }()

        let session = try await HTTPProxySession.open(
            server: HTTPProxyServerConfig(host: "127.0.0.1", port: port),
            targetHost: "example.com", targetPort: 443
        )

        let payload = Array("hello".utf8)
        try await session.send(payload)
        let echoed = try await session.receive()
        session.close()

        XCTAssertEqual(echoed, payload)
        let request = try await serverSide
        XCTAssertEqual(request, HTTPProxyIncomingRequest(host: "example.com", port: 443))
    }

    /// A server that never sees a client it recognizes as authenticated
    /// would reply 407 in the real world (this accept side has no auth
    /// support -- see `HTTPProxyServer.swift`'s own doc comment -- so this
    /// synthesizes that reply directly instead of exercising the real
    /// server code) -- the client must surface it as a typed error, not
    /// hang or silently treat it as success.
    func testClientSurfacesNon2xxReplyFromRealSocket() async throws {
        let listener = try TCPListener(port: 0)
        let box = AcceptedBox()
        try await listener.start(onAccept: { box.conn = $0 }, onFailure: { _ in })
        defer { listener.cancel() }
        let port = try XCTUnwrap(listener.port)

        async let serverSide: Void = {
            try await waitForAccepted(box)
            let serverConn = try XCTUnwrap(box.conn)
            try await serverConn.connect()
            _ = try await serverConn.readExactly(1) // wait for the client's CONNECT to start arriving
            try await serverConn.send(Array("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".utf8))
            serverConn.close()
        }()

        do {
            _ = try await HTTPProxySession.open(
                server: HTTPProxyServerConfig(host: "127.0.0.1", port: port),
                targetHost: "example.com", targetPort: 443
            )
            XCTFail("expected requestFailed")
        } catch HTTPProxyClientError.requestFailed(let statusCode, _) {
            XCTAssertEqual(statusCode, 407)
        }
        try await serverSide
    }
}
