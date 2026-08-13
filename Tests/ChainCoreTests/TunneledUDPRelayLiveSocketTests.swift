import XCTest
import ProxyKit
import SOCKS5Core
@testable import VMessCore
@testable import VLESSCore
@testable import ChainCore

// MARK: - Minimal in-process fake VMess/VLESS servers, UDP mode
//
// Real VMess/VLESS servers, in UDP mode, decode the same handshake as TCP
// mode (the command byte is the only thing that differs, and this client's
// own handshake decode doesn't even look at it -- see `VMessCore`/`VLESSCore`),
// then this client's own `TunneledUDPRelay` frames the body into
// `[UInt16 BE length][datagram]` chunks -- these fakes speak exactly that:
// decode the real handshake with the same crypto/framing production code
// uses, then loop echoing back whatever length-prefixed chunk arrives.
//
// Reuses `TCPListener`/`TCPConn` directly (both public ProxyKit types)
// rather than `ChainCoreLiveSocketTests`' own `private` fixtures, since
// those aren't visible from this file and this scenario (UDP-mode handshake
// + chunk echo) is different enough from that file's TCP-echo-only servers
// to warrant its own small, self-contained version anyway.

private func waitForAccepted(_ box: AcceptedConnBox) async throws -> TCPConn {
    for _ in 0..<500 where box.conn == nil {
        try await Task.sleep(nanoseconds: 10_000_000) // up to ~5s
    }
    guard let conn = box.conn else { throw ProxyError.connectionClosed }
    try await conn.connect()
    return conn
}

private final class AcceptedConnBox: @unchecked Sendable {
    var conn: TCPConn?
}

/// Loops reading one `[UInt16 BE length][payload]` chunk and echoing it back
/// the same way, until the connection closes -- the UDP-mode body framing
/// both `FakeVMessUDPServer` and `FakeVLESSUDPServer` share after their own
/// (different) handshake decode. Takes the existential `ByteStreamSource &
/// ByteStreamSink` shape rather than `TCPConn` directly so `FakeVMessUDPServer`
/// can hand back a `VMessUDPServerAdapter` (real AEAD body chunks now sit
/// between this framing and the raw socket) while VLESS's fake server -- no
/// such body encryption -- just passes its own `TCPConn` straight through.
private func echoLengthPrefixedChunks(over conn: any (ByteStreamSource & ByteStreamSink), count: Int) async throws -> [[UInt8]] {
    var received: [[UInt8]] = []
    for _ in 0..<count {
        let lengthBytes = try await conn.readExactly(2, timeout: nil)
        let length = Int(lengthBytes[0]) << 8 | Int(lengthBytes[1])
        let payload = try await conn.readExactly(length, timeout: nil)
        received.append(payload)
        try await conn.send(UInt16(payload.count).bigEndianBytes + payload, timeout: nil)
    }
    return received
}

/// Wraps the post-handshake `TCPConn` in the same AEAD body chunk
/// decrypt/re-encrypt `VMessSession`'s client side now speaks (see
/// VMessCore's `sealVMessBodyChunk`/`openVMessBodyChunkPayload`), so
/// `echoLengthPrefixedChunks` above can keep operating on a plain,
/// already-decrypted byte pipe exactly as it did before real body
/// encryption shipped -- mirrors `ChainCoreLiveSocketTests`' own
/// `VMessServerAdapter` (that file's fake servers aren't visible here, see
/// this file's own header comment on why it has its own fixtures).
private final class VMessUDPServerAdapter: ByteStreamSource, ByteStreamSink {
    private let conn: TCPConn
    private let requestBodyKey: [UInt8]
    private let requestBodyIV: [UInt8]
    private let responseBodyKey: [UInt8]
    private let responseBodyIV: [UInt8]
    private var buffered: [UInt8] = []
    private var inboundChunkCounter: UInt16 = 0
    private var outboundChunkCounter: UInt16 = 0

    init(conn: TCPConn, requestBodyKey: [UInt8], requestBodyIV: [UInt8]) {
        self.conn = conn
        self.requestBodyKey = requestBodyKey
        self.requestBodyIV = requestBodyIV
        self.responseBodyKey = Array(sha256(requestBodyKey).prefix(16))
        self.responseBodyIV = Array(sha256(requestBodyIV).prefix(16))
    }

    func send(_ bytes: [UInt8], timeout: TimeInterval?) async throws {
        var offset = 0
        while offset < bytes.count {
            let end = min(offset + vmessMaxChunkPlaintext, bytes.count)
            let framed = sealVMessBodyChunk(key: responseBodyKey, iv: responseBodyIV, counter: outboundChunkCounter, plaintext: Array(bytes[offset..<end]))
            outboundChunkCounter &+= 1
            try await conn.send(framed, timeout: timeout)
            offset = end
        }
    }

    func readExactly(_ n: Int, timeout: TimeInterval?) async throws -> [UInt8] {
        while buffered.count < n {
            let lengthBytes = try await conn.readExactly(2, timeout: timeout)
            let length = Int(lengthBytes[0]) << 8 | Int(lengthBytes[1])
            let sealed = try await conn.readExactly(length, timeout: timeout)
            let plaintext = try openVMessBodyChunkPayload(key: requestBodyKey, iv: requestBodyIV, counter: inboundChunkCounter, sealed: sealed)
            inboundChunkCounter &+= 1
            buffered += plaintext
        }
        let result = Array(buffered.prefix(n))
        buffered.removeFirst(n)
        return result
    }
}

private final class FakeVMessUDPServer {
    private let listener: TCPListener
    private let box = AcceptedConnBox()

    init() throws { listener = try TCPListener(port: 0) }
    func start() async throws -> UInt16 {
        try await listener.start(onAccept: { [box] conn in box.conn = conn }, onFailure: { _ in })
        return listener.port!
    }
    func stop() { listener.cancel() }

    /// Accepts one connection (optionally preceded by a real SOCKS5 CONNECT
    /// handshake, when this server is dialed *through* an earlier SOCKS5
    /// hop), decodes the VMess AEAD request header, replies, and returns the
    /// decoded command byte + target for the caller to assert on, plus a
    /// closure the test can call afterward to run the chunk-echo loop.
    func acceptHandshake(uuid: String, throughSOCKS5: Bool) async throws -> (command: UInt8, host: String, port: UInt16, conn: any (ByteStreamSource & ByteStreamSink)) {
        let conn = try await waitForAccepted(box)
        if throughSOCKS5 {
            _ = try await SOCKS5Server.acceptConnect(over: conn)
        }

        let cmdKey = md5(parseUUID(uuid) + cmdKeyMagic)
        let authID = try await conn.readExactly(16, timeout: nil)
        let lengthAndNonce = try await conn.readExactly(18 + 8, timeout: nil)
        let connectionNonce = Array(lengthAndNonce[18..<26])

        let lengthKey = vmessKDF16(key: cmdKey, path: [Array("VMess Header AEAD Key_Length".utf8), authID, connectionNonce])
        let lengthNonce = Array(vmessKDF(key: cmdKey, path: [Array("VMess Header AEAD Nonce_Length".utf8), authID, connectionNonce]).prefix(12))
        let lengthBytes = try aesGCMOpen(key: lengthKey, nonce: lengthNonce, sealed: Array(lengthAndNonce[0..<18]), aad: authID)
        let headerLen = Int(lengthBytes[0]) << 8 | Int(lengthBytes[1])

        let sealedHeader = try await conn.readExactly(headerLen + 16, timeout: nil)
        let requestPlain = try openVMessAEADHeader(key: cmdKey, authID: authID, remainder: lengthAndNonce + sealedHeader)

        let requestBodyIV = Array(requestPlain[1..<17])
        let requestBodyKey = Array(requestPlain[17..<33])
        let responseHeaderByte = requestPlain[33]
        let command = requestPlain[37]
        let port = UInt16(requestPlain[38]) << 8 | UInt16(requestPlain[39])
        let atyp = requestPlain[40]
        let host: String
        switch atyp {
        case 0x01: host = requestPlain[41..<45].map { String($0) }.joined(separator: ".")
        case 0x02:
            let len = Int(requestPlain[41])
            host = String(decoding: requestPlain[42..<(42 + len)], as: UTF8.self)
        default: preconditionFailure("unsupported ATYP \(atyp) in test")
        }

        let responseBodyKey = Array(sha256(requestBodyKey).prefix(16))
        let responseBodyIV = Array(sha256(requestBodyIV).prefix(16))
        let header: [UInt8] = [responseHeaderByte, 0, 0, 0]

        let respLengthKey = vmessKDF16(key: responseBodyKey, path: [Array("AEAD Resp Header Len Key".utf8)])
        let respLengthNonce = Array(vmessKDF(key: responseBodyIV, path: [Array("AEAD Resp Header Len IV".utf8)]).prefix(12))
        let sealedRespLength = aesGCMSeal(key: respLengthKey, nonce: respLengthNonce, plaintext: UInt16(header.count).bigEndianBytes, aad: [])

        let respHeaderKey = vmessKDF16(key: responseBodyKey, path: [Array("AEAD Resp Header Key".utf8)])
        let respHeaderNonce = Array(vmessKDF(key: responseBodyIV, path: [Array("AEAD Resp Header IV".utf8)]).prefix(12))
        let sealedRespHeader = aesGCMSeal(key: respHeaderKey, nonce: respHeaderNonce, plaintext: header, aad: [])

        try await conn.send(sealedRespLength + sealedRespHeader, timeout: nil)
        let adapter = VMessUDPServerAdapter(conn: conn, requestBodyKey: requestBodyKey, requestBodyIV: requestBodyIV)
        return (command, host, port, adapter)
    }
}

private final class FakeVLESSUDPServer {
    private let listener: TCPListener
    private let box = AcceptedConnBox()

    init() throws { listener = try TCPListener(port: 0) }
    func start() async throws -> UInt16 {
        try await listener.start(onAccept: { [box] conn in box.conn = conn }, onFailure: { _ in })
        return listener.port!
    }
    func stop() { listener.cancel() }

    func acceptHandshake(throughSOCKS5: Bool) async throws -> (command: UInt8, host: String, port: UInt16, conn: TCPConn) {
        let conn = try await waitForAccepted(box)
        if throughSOCKS5 {
            _ = try await SOCKS5Server.acceptConnect(over: conn)
        }

        let head = try await conn.readExactly(1 + 16 + 1 + 1, timeout: nil) // Ver, UUID, AddonsLen, Cmd
        let ver = head[0]
        let addonsLen = Int(head[17])
        let command = head[18]
        if addonsLen > 0 { _ = try await conn.readExactly(addonsLen, timeout: nil) }

        let portBytes = try await conn.readExactly(2, timeout: nil)
        let port = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])
        let atyp = try await conn.readExactly(1, timeout: nil)
        let host: String
        switch atyp[0] {
        case 0x01: host = (try await conn.readExactly(4, timeout: nil)).map { String($0) }.joined(separator: ".")
        case 0x02:
            let lenByte = try await conn.readExactly(1, timeout: nil)
            host = String(decoding: try await conn.readExactly(Int(lenByte[0]), timeout: nil), as: UTF8.self)
        default: preconditionFailure("unsupported ATYP \(atyp[0]) in test")
        }

        try await conn.send([ver, 0x00], timeout: nil) // response: Ver + AddonsLen(0)
        return (command, host, port, conn)
    }
}

// MARK: - Tests

final class TunneledUDPRelayLiveSocketTests: XCTestCase {
    private let uuidA = "0398d470-bc09-4cd5-889d-3ae4c569b6da"

    func testVMessUDPSingleHopRoundTripOverRealSocket() async throws {
        let server = try FakeVMessUDPServer()
        let port = try await server.start()
        defer { server.stop() }

        async let serverSide = server.acceptHandshake(uuid: uuidA, throughSOCKS5: false)

        let hops = [ProxyHop(host: "127.0.0.1", port: port, protocolConfig: .vmess(uuid: uuidA))]
        let relay = try await ProxyChain.openUDPRelay(hops: hops)
        defer { relay.close() }

        try await relay.send(targetHost: "dns.example", targetPort: 53, payload: Array("query".utf8), timeout: nil)

        let (command, host, targetPort, conn) = try await serverSide
        XCTAssertEqual(command, VMessRequest.commandUDP)
        XCTAssertEqual(host, "dns.example")
        XCTAssertEqual(targetPort, 53)

        async let echoed = echoLengthPrefixedChunks(over: conn, count: 1)
        let result = try await relay.receive(timeout: 5)
        XCTAssertEqual(result.fromHost, "dns.example")
        XCTAssertEqual(result.fromPort, 53)
        XCTAssertEqual(result.payload, Array("query".utf8))
        _ = try await echoed
    }

    func testVLESSUDPSingleHopRoundTripOverRealSocket() async throws {
        let server = try FakeVLESSUDPServer()
        let port = try await server.start()
        defer { server.stop() }

        async let serverSide = server.acceptHandshake(throughSOCKS5: false)

        let hops = [ProxyHop(host: "127.0.0.1", port: port, protocolConfig: .vless(uuid: uuidA))]
        let relay = try await ProxyChain.openUDPRelay(hops: hops)
        defer { relay.close() }

        try await relay.send(targetHost: "8.8.8.8", targetPort: 443, payload: Array("hello".utf8), timeout: nil)

        let (command, host, targetPort, conn) = try await serverSide
        XCTAssertEqual(command, VLESSCommand.udp)
        XCTAssertEqual(host, "8.8.8.8")
        XCTAssertEqual(targetPort, 443)

        async let echoed = echoLengthPrefixedChunks(over: conn, count: 1)
        let result = try await relay.receive(timeout: 5)
        XCTAssertEqual(result.fromHost, "8.8.8.8")
        XCTAssertEqual(result.fromPort, 443)
        XCTAssertEqual(result.payload, Array("hello".utf8))
        _ = try await echoed
    }

    /// Earlier hop is SOCKS5, last hop is VMess -- proves `TunneledUDPRelay`
    /// really does accept *any* protocol mix before the terminal UDP hop,
    /// not just a single-hop chain.
    func testTwoHopChainSOCKS5ThenVMessUDPOverRealSocket() async throws {
        let server = try FakeVMessUDPServer()
        let port = try await server.start()
        defer { server.stop() }

        async let serverSide = server.acceptHandshake(uuid: uuidA, throughSOCKS5: true)

        let hops = [
            ProxyHop(host: "127.0.0.1", port: port, protocolConfig: .socks5(auth: .none)),
            ProxyHop(host: "vmess-hop.example", port: 8443, protocolConfig: .vmess(uuid: uuidA)),
        ]
        let relay = try await ProxyChain.openUDPRelay(hops: hops)
        defer { relay.close() }

        try await relay.send(targetHost: "real-target.example", targetPort: 9999, payload: Array("via socks5 then vmess".utf8), timeout: nil)

        let (command, host, targetPort, conn) = try await serverSide
        XCTAssertEqual(command, VMessRequest.commandUDP)
        // The SOCKS5 hop was asked to CONNECT to the VMess hop's own
        // declared address (same "hop i -> hop i+1's address" chaining the
        // TCP path already does) -- confirmed by simply reaching this point
        // at all, since `acceptHandshake`'s SOCKS5 branch already consumed
        // that CONNECT request. The VMess request itself names the *real*
        // final target, not the SOCKS5 hop's address.
        XCTAssertEqual(host, "real-target.example")
        XCTAssertEqual(targetPort, 9999)

        async let echoed = echoLengthPrefixedChunks(over: conn, count: 1)
        let result = try await relay.receive(timeout: 5)
        XCTAssertEqual(result.payload, Array("via socks5 then vmess".utf8))
        _ = try await echoed
    }

    /// Regression test: `receive(timeout:)` used to ignore its `timeout`
    /// parameter entirely (`for await item in incoming { return item }`,
    /// with no deadline at all) and block forever whenever the target never
    /// answers -- invisible in the three tests above since their fake
    /// servers always echo back a reply, so `timeout` never needed to
    /// actually fire. Here the server completes the handshake (so the
    /// tunnel is genuinely open) but deliberately never echoes anything
    /// back, then asserts `receive(timeout: 1)` throws `.timedOut` and
    /// returns promptly rather than hanging -- this is exactly what a real
    /// VMess/VLESS server doing something other than expected with this
    /// client's UDP body framing (or a blocked network path) looks like, and
    /// is what "Test Connection" surfaces as an indefinitely-stuck spinner
    /// once its own UDP probe reuses this same call.
    func testReceiveTimesOutRatherThanHangingForeverWhenTargetNeverReplies() async throws {
        let server = try FakeVMessUDPServer()
        let port = try await server.start()
        defer { server.stop() }

        async let serverSide = server.acceptHandshake(uuid: uuidA, throughSOCKS5: false)

        let hops = [ProxyHop(host: "127.0.0.1", port: port, protocolConfig: .vmess(uuid: uuidA))]
        let relay = try await ProxyChain.openUDPRelay(hops: hops)
        defer { relay.close() }

        try await relay.send(targetHost: "dns.example", targetPort: 53, payload: Array("query".utf8), timeout: nil)
        _ = try await serverSide // handshake completes; server sends no reply afterward

        let start = Date()
        await XCTAssertThrowsErrorAsync(try await relay.receive(timeout: 1)) { error in
            XCTAssertEqual(error as? ProxyError, .timedOut)
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 3, "receive(timeout: 1) should time out promptly, not hang")
    }
}

/// `XCTAssertThrowsError` has no `async` overload -- this bridges an
/// awaited throwing expression into the same assert-and-inspect shape.
private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ errorHandler: (Error) -> Void = { _ in },
    file: StaticString = #filePath, line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected an error to be thrown", file: file, line: line)
    } catch {
        errorHandler(error)
    }
}
