import XCTest
@testable import ProxyKit

// MARK: - Minimal server-side test double for RFC 6455

/// Speaks just enough of the WebSocket server role to prove `WSConn`'s
/// client-side handshake and frame codec are correct: reads the HTTP
/// upgrade request, replies with a real (not hardcoded) `Sec-WebSocket-Accept`
/// derived the same way a real server's would be, then reads/writes frames
/// directly (server-to-client frames are unmasked, per spec -- unlike
/// `WSConn`'s own client-to-server sends).
private final class FakeWSServer {
    private let listener: TCPListener
    private var accepted: TCPConn?

    init() throws { listener = try TCPListener(port: 0) }

    var port: UInt16 { listener.port! }

    func start() async throws {
        try await listener.start(onAccept: { [weak self] conn in self?.accepted = conn }, onFailure: { _ in })
    }

    func stop() { listener.cancel() }

    private func waitForConnection() async throws -> TCPConn {
        for _ in 0..<500 where accepted == nil {
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        guard let accepted else { throw ProxyError.connectionClosed }
        try await accepted.connect()
        return accepted
    }

    /// Completes the handshake, replying with a valid `101` unless
    /// `respondWithGarbage` -- for the negative test.
    @discardableResult
    func acceptHandshake(respondWithGarbage: Bool = false) async throws -> TCPConn {
        let conn = try await waitForConnection()
        var head: [UInt8] = []
        while !String(decoding: head, as: UTF8.self).contains("\r\n\r\n") {
            head += try await conn.readAvailable()
        }
        let text = String(decoding: head, as: UTF8.self)
        guard let keyLine = text.components(separatedBy: "\r\n").first(where: { $0.lowercased().hasPrefix("sec-websocket-key:") }) else {
            throw ProxyError.connectionClosed
        }
        let key = keyLine.split(separator: ":", maxSplits: 1)[1].trimmingCharacters(in: .whitespaces)

        if respondWithGarbage {
            try await conn.send(Array("HTTP/1.1 400 Bad Request\r\n\r\n".utf8))
            return conn
        }

        let accept = Data(sha1(Array((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").utf8))).base64EncodedString()
        let response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: \(accept)\r\n\r\n"
        try await conn.send(Array(response.utf8))
        return conn
    }

    /// Reads one client frame (masked) and returns its decoded opcode/payload.
    func readClientFrame(over conn: TCPConn) async throws -> (opcode: UInt8, payload: [UInt8]) {
        let firstTwo = try await conn.readExactly(2)
        let opcode = firstTwo[0] & 0x0F
        let masked = firstTwo[1] & 0x80 != 0
        var length = Int(firstTwo[1] & 0x7F)
        if length == 126 {
            let ext = try await conn.readExactly(2)
            length = Int(ext[0]) << 8 | Int(ext[1])
        } else if length == 127 {
            let ext = try await conn.readExactly(8)
            length = ext.reduce(0) { ($0 << 8) | Int($1) }
        }
        let maskKey = masked ? try await conn.readExactly(4) : []
        let raw = length > 0 ? try await conn.readExactly(length) : []
        let payload = masked ? raw.enumerated().map { $0.element ^ maskKey[$0.offset % 4] } : raw
        return (opcode, payload)
    }

    /// Sends one *unmasked* server-to-client frame (per spec).
    func sendServerFrame(opcode: UInt8, payload: [UInt8], over conn: TCPConn) async throws {
        var frame: [UInt8] = [0x80 | opcode]
        if payload.count <= 125 {
            frame.append(UInt8(payload.count))
        } else if payload.count <= 0xFFFF {
            frame.append(126)
            frame += UInt16(payload.count).bigEndianBytes
        } else {
            frame.append(127)
            frame += (0..<8).reversed().map { UInt8((UInt64(payload.count) >> ($0 * 8)) & 0xFF) }
        }
        frame += payload
        try await conn.send(frame)
    }

    func echoOnce(over conn: TCPConn) async throws {
        let (opcode, payload) = try await readClientFrame(over: conn)
        try await sendServerFrame(opcode: opcode, payload: payload, over: conn)
    }
}

// MARK: - Tests

final class WSConnTests: XCTestCase {
    func testHandshakeAndEchoRoundTrip() async throws {
        let server = try FakeWSServer()
        try await server.start()
        defer { server.stop() }

        async let serverConn = server.acceptHandshake()

        let client = TCPConn(host: "127.0.0.1", port: server.port)
        try await client.connect()
        let ws = try await WSConn.handshake(over: client, host: "127.0.0.1", path: "/test-path")
        let accepted = try await serverConn

        let payload = Array("hello over a fake ws server".utf8)
        async let echo: Void = server.echoOnce(over: accepted)
        try await ws.send(payload)
        _ = try await echo

        let received = try await ws.readExactly(payload.count)
        XCTAssertEqual(received, payload)
        ws.close()
    }

    func testMultipleRoundTripsOnSameConnection() async throws {
        let server = try FakeWSServer()
        try await server.start()
        defer { server.stop() }

        async let serverConn = server.acceptHandshake()
        let client = TCPConn(host: "127.0.0.1", port: server.port)
        try await client.connect()
        let ws = try await WSConn.handshake(over: client, host: "127.0.0.1", path: "/")
        let accepted = try await serverConn

        for i in 0..<3 {
            let payload = Array("message-\(i)".utf8)
            async let echo: Void = server.echoOnce(over: accepted)
            try await ws.send(payload)
            _ = try await echo
            let received = try await ws.readExactly(payload.count)
            XCTAssertEqual(received, payload, "round trip \(i) mismatch")
        }
        ws.close()
    }

    /// A payload over 125 bytes forces the 16-bit extended-length header
    /// field this codebase's own frame codec has to handle correctly, not
    /// just the common short-payload case.
    func testPayloadOver125BytesUsesExtendedLength() async throws {
        let server = try FakeWSServer()
        try await server.start()
        defer { server.stop() }

        async let serverConn = server.acceptHandshake()
        let client = TCPConn(host: "127.0.0.1", port: server.port)
        try await client.connect()
        let ws = try await WSConn.handshake(over: client, host: "127.0.0.1", path: "/")
        let accepted = try await serverConn

        let payload = Array(repeating: UInt8(0x41), count: 5000)
        async let echo: Void = server.echoOnce(over: accepted)
        try await ws.send(payload)
        _ = try await echo
        let received = try await ws.readExactly(payload.count)
        XCTAssertEqual(received, payload)
        ws.close()
    }

    func testPingIsAnsweredWithPongAndNotSurfacedAsData() async throws {
        let server = try FakeWSServer()
        try await server.start()
        defer { server.stop() }

        async let serverConn = server.acceptHandshake()
        let client = TCPConn(host: "127.0.0.1", port: server.port)
        try await client.connect()
        let ws = try await WSConn.handshake(over: client, host: "127.0.0.1", path: "/")
        let accepted = try await serverConn

        // Server sends a ping, then (after reading the client's pong reply)
        // a real data frame -- `readExactly` should skip the ping/pong
        // dance transparently and hand back only the real payload.
        async let serverSide: Void = {
            try await server.sendServerFrame(opcode: 0x9, payload: Array("ping-payload".utf8), over: accepted)
            let (opcode, payload) = try await server.readClientFrame(over: accepted)
            XCTAssertEqual(opcode, 0xA, "expected a Pong reply")
            XCTAssertEqual(payload, Array("ping-payload".utf8), "Pong should echo the Ping's payload")
            try await server.sendServerFrame(opcode: 0x2, payload: Array("real-data".utf8), over: accepted)
        }()

        let received = try await ws.readExactly(Array("real-data".utf8).count)
        XCTAssertEqual(received, Array("real-data".utf8))
        try await serverSide
        ws.close()
    }

    func testCloseFrameActsAsCleanEOF() async throws {
        let server = try FakeWSServer()
        try await server.start()
        defer { server.stop() }

        async let serverConn = server.acceptHandshake()
        let client = TCPConn(host: "127.0.0.1", port: server.port)
        try await client.connect()
        let ws = try await WSConn.handshake(over: client, host: "127.0.0.1", path: "/")
        let accepted = try await serverConn

        try await server.sendServerFrame(opcode: 0x8, payload: [], over: accepted)
        do {
            _ = try await ws.readExactly(1)
            XCTFail("expected connectionClosed")
        } catch ProxyError.connectionClosed {
            // expected
        }
        ws.close()
    }

    func testNonSwitchingProtocolsResponseThrowsHandshakeFailed() async throws {
        let server = try FakeWSServer()
        try await server.start()
        defer { server.stop() }

        async let serverSide: Void = { _ = try await server.acceptHandshake(respondWithGarbage: true) }()
        let client = TCPConn(host: "127.0.0.1", port: server.port)
        try await client.connect()
        do {
            _ = try await WSConn.handshake(over: client, host: "127.0.0.1", path: "/")
            XCTFail("expected handshakeFailed")
        } catch WSError.handshakeFailed {
            // expected
        }
        _ = try await serverSide
    }
}
