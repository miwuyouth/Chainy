import XCTest
import ProxyKit
@testable import HTTPProxyCore

/// Proves `HTTPProxyServer.acceptConnect` actually works over one real
/// loopback socket, both for a CONNECT tunnel and for a plain (non-CONNECT)
/// request's replay -- `HTTPProxyServerTests` already covers the wire-format
/// logic against a fake transport; this is the integration check via
/// `TCPListener`/`TCPConn`, mirroring `SOCKS5ServerLiveSocketTests`.
final class HTTPProxyServerLiveSocketTests: XCTestCase {
    private final class AcceptedBox {
        var conn: TCPConn?
    }

    private func waitForAccepted(_ box: AcceptedBox) async throws {
        for _ in 0..<500 where box.conn == nil {
            try await Task.sleep(nanoseconds: 10_000_000) // up to ~5s
        }
        XCTAssertNotNil(box.conn)
    }

    func testRealCONNECTTunnelRoundTripsPayloadAfter200Reply() async throws {
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

        let client = TCPConn(host: "127.0.0.1", port: port)
        try await client.connect()
        try await client.send(Array("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".utf8))
        let expectedReply = Array("HTTP/1.1 200 Connection Established\r\n\r\n".utf8)
        let reply = try await client.readExactly(expectedReply.count)
        XCTAssertEqual(reply, expectedReply)

        try await client.send(Array("hello".utf8))
        let echoed = try await client.readExactly(5)
        client.close()

        XCTAssertEqual(String(decoding: echoed, as: UTF8.self), "hello")
        let request = try await serverSide
        XCTAssertEqual(request, HTTPProxyIncomingRequest(host: "example.com", port: 443))
    }

    func testRealPlainRequestReplaysOriginFormRequestToServerSide() async throws {
        let listener = try TCPListener(port: 0)
        let box = AcceptedBox()
        try await listener.start(onAccept: { box.conn = $0 }, onFailure: { _ in })
        defer { listener.cancel() }
        let port = try XCTUnwrap(listener.port)

        async let serverSide: (request: HTTPProxyIncomingRequest, replayedHead: [UInt8]) = {
            try await waitForAccepted(box)
            let serverConn = try XCTUnwrap(box.conn)
            try await serverConn.connect()
            let request = try await HTTPProxyServer.acceptConnect(over: serverConn)
            serverConn.close()
            return (request, request.replayToOutbound)
        }()

        let client = TCPConn(host: "127.0.0.1", port: port)
        try await client.connect()
        try await client.send(Array("GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8))
        client.close()

        let result = try await serverSide
        XCTAssertEqual(result.request.host, "example.com")
        XCTAssertEqual(result.request.port, 80)
        XCTAssertEqual(String(decoding: result.replayedHead, as: UTF8.self), "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n")
    }
}
