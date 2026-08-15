import XCTest
@testable import ProxyKit

/// Real-socket coverage for `TCPListener`/`TCPConn(accepted:)` -- the accept
/// side Chainy's local SOCKS5 server is built on. Uses an ephemeral port (0)
/// unless a test specifically needs a fixed, already-bound
/// one, and a polling wait (rather than an indefinite one) for the accepted
/// connection to show up.
final class TCPListenerLiveSocketTests: XCTestCase {
    private final class AcceptedBox {
        var conn: TCPConn?
    }

    private func waitForAccepted(_ box: AcceptedBox) async throws {
        for _ in 0..<500 where box.conn == nil {
            try await Task.sleep(nanoseconds: 10_000_000) // up to ~5s
        }
        XCTAssertNotNil(box.conn, "expected a connection to have been accepted")
    }

    func testAcceptedConnectionRoundTripsBytes() async throws {
        let listener = try TCPListener(port: 0)
        let box = AcceptedBox()
        try await listener.start(onAccept: { box.conn = $0 }, onFailure: { _ in })
        defer { listener.cancel() }

        let port = try XCTUnwrap(listener.port)
        let client = TCPConn(host: "127.0.0.1", port: port)
        try await client.connect()

        try await waitForAccepted(box)
        let server = try XCTUnwrap(box.conn)
        try await server.connect() // accepted-but-not-started -- same ready-wait as the dial side

        let payload = Array("hello over an accepted TCPConn".utf8)
        try await client.send(payload)
        let received = try await server.readExactly(payload.count)
        XCTAssertEqual(received, payload)

        try await server.send(received)
        let echoed = try await client.readExactly(payload.count)
        XCTAssertEqual(echoed, payload)

        client.close()
        server.close()
    }

    func testStartThrowsPortInUseWhenPortAlreadyBound() async throws {
        let first = try TCPListener(port: 0)
        try await first.start(onAccept: { _ in }, onFailure: { _ in })
        defer { first.cancel() }
        let port = try XCTUnwrap(first.port)

        let second = try TCPListener(port: port)
        do {
            try await second.start(onAccept: { _ in }, onFailure: { _ in })
            XCTFail("expected .portInUse")
        } catch TCPListenerError.portInUse {
            // expected
        }
    }

    /// `allowLAN: true` binds every interface instead of just loopback (see
    /// `TCPListener.init`) -- confirmed here via the one address every Mac
    /// always has either way, 127.0.0.1, since a real test can't assume
    /// there's an actual LAN interface up in CI.
    func testAllowLANStillAcceptsLoopbackConnections() async throws {
        let listener = try TCPListener(port: 0, allowLAN: true)
        let box = AcceptedBox()
        try await listener.start(onAccept: { box.conn = $0 }, onFailure: { _ in })
        defer { listener.cancel() }

        let port = try XCTUnwrap(listener.port)
        let client = TCPConn(host: "127.0.0.1", port: port)
        try await client.connect()

        try await waitForAccepted(box)
        let server = try XCTUnwrap(box.conn)
        try await server.connect()

        let payload = Array("hello over a LAN-bound listener".utf8)
        try await client.send(payload)
        let received = try await server.readExactly(payload.count)
        XCTAssertEqual(received, payload)

        client.close()
        server.close()
    }

    /// `peekByte` backs Chainy's mixed SOCKS5/HTTP local listener, which
    /// sniffs the first byte of an accepted connection to pick a parser --
    /// this proves the byte it hands back is still there for a real
    /// `readExactly` right after, not consumed.
    func testPeekByteLeavesTheByteForTheNextRead() async throws {
        let listener = try TCPListener(port: 0)
        let box = AcceptedBox()
        try await listener.start(onAccept: { box.conn = $0 }, onFailure: { _ in })
        defer { listener.cancel() }

        let port = try XCTUnwrap(listener.port)
        let client = TCPConn(host: "127.0.0.1", port: port)
        try await client.connect()

        try await waitForAccepted(box)
        let server = try XCTUnwrap(box.conn)
        try await server.connect()

        let payload = Array("Ghello".utf8) // "G" as in a real HTTP method's first byte
        try await client.send(payload)

        let peeked = try await server.peekByte()
        XCTAssertEqual(peeked, UInt8(ascii: "G"))

        // The peeked byte is still there for a real read afterward.
        let received = try await server.readExactly(payload.count)
        XCTAssertEqual(received, payload)

        client.close()
        server.close()
    }

    func testCancelStopsAcceptingNewConnections() async throws {
        let listener = try TCPListener(port: 0)
        try await listener.start(onAccept: { _ in }, onFailure: { _ in })
        let port = try XCTUnwrap(listener.port)
        listener.cancel()

        // NWListener cancellation is asynchronous. A connection attempted in
        // the same run-loop turn can still reach the old listening socket, so
        // wait for cancellation to take effect instead of asserting an
        // immediate kernel-level close.
        let deadline = Date().addingTimeInterval(3)
        while Date() < deadline {
            let client = TCPConn(host: "127.0.0.1", port: port)
            do {
                try await client.connect(timeout: 0.2)
                client.close()
                try await Task.sleep(nanoseconds: 10_000_000)
            } catch {
                return
            }
        }
        XCTFail("cancelled listener kept accepting connections for 3 seconds")
    }
}
