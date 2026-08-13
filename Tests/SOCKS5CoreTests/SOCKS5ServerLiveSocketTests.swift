import XCTest
import ProxyKit
@testable import SOCKS5Core

/// Proves the real client (`SOCKS5Session.open`) and the real server
/// (`SOCKS5Server.acceptConnect`) actually agree over one real loopback
/// socket -- `SOCKS5CoreTests`/`SOCKS5ServerTests` already cover each side's
/// wire-format logic against a fake transport; this is the integration
/// check that they interoperate for real, via `TCPListener`/`TCPConn`.
final class SOCKS5ServerLiveSocketTests: XCTestCase {
    private final class AcceptedBox {
        var conn: TCPConn?
    }

    private func waitForAccepted(_ box: AcceptedBox) async throws {
        for _ in 0..<500 where box.conn == nil {
            try await Task.sleep(nanoseconds: 10_000_000) // up to ~5s
        }
        XCTAssertNotNil(box.conn)
    }

    private func acceptAndEcho(_ box: AcceptedBox, payloadLength: Int) async throws -> (request: SOCKS5IncomingRequest, echoed: [UInt8]) {
        try await waitForAccepted(box)
        let serverConn = try XCTUnwrap(box.conn)
        try await serverConn.connect()
        let request = try await SOCKS5Server.acceptConnect(over: serverConn)
        let payload = try await serverConn.readExactly(payloadLength)
        try await serverConn.send(payload)
        serverConn.close()
        return (request, payload)
    }

    func testRealClientAgainstRealServerRoundTripsCorrectTargetAndPayload() async throws {
        let listener = try TCPListener(port: 0)
        let box = AcceptedBox()
        try await listener.start(onAccept: { box.conn = $0 }, onFailure: { _ in })
        defer { listener.cancel() }
        let port = try XCTUnwrap(listener.port)

        let payload = Array("hello through a real local SOCKS5 server".utf8)
        async let serverSide = acceptAndEcho(box, payloadLength: payload.count)

        let client = try await SOCKS5Session.open(
            server: SOCKS5ServerConfig(host: "127.0.0.1", port: port, auth: .none),
            targetHost: .domain("example.com"),
            targetPort: 443
        )
        try await client.send(payload)
        let echoed = try await client.receive()
        client.close()

        let result = try await serverSide
        XCTAssertEqual(result.request, SOCKS5IncomingRequest(host: "example.com", port: 443))
        XCTAssertEqual(result.echoed, payload)
        XCTAssertEqual(echoed, payload)
    }
}
