import XCTest
import Network
import ProxyKit
import SOCKS5Core
@testable import ShadowsocksCore
@testable import VMessCore
import ChainCore

// MARK: - Minimal server-side test double for a proxy chain
//
// Speaks an arbitrary ordered sequence of SOCKS5 (CONNECT) / Shadowsocks /
// VMess server roles over one real loopback socket -- exactly what
// `ProxyChain.open` produces on the client side. SOCKS5's CONNECT relay
// adds zero extra framing (a hop just decodes the handshake and hands back
// the same underlying transport), while Shadowsocks and VMess each wrap the
// stream in their own per-chunk AEAD framing -- so layering here grows a new
// *adapter* for each of those two, mirroring `ShadowsocksSession`/
// `VMessSession`'s own client-side body framing.
//
// This exists to prove real cross-protocol correctness -- genuine crypto,
// genuine wire framing, arbitrary hop order/length -- through the real
// `ProxyChain.open` public API, not just that method calls happen in the
// right order.

private struct DecodedTarget: Equatable {
    let host: String
    let port: UInt16
}

private func proxyAddressToHost(_ address: ProxyAddress) -> String {
    switch address {
    case .ipv4(let b): return b.map(String.init).joined(separator: ".")
    case .ipv6(let b): return b.map { String(format: "%02x", $0) }.joined()
    case .domain(let d): return d
    }
}

private final class StaticByteSource: ByteStreamSource {
    private var buffer: [UInt8]
    init(_ buffer: [UInt8]) { self.buffer = buffer }
    func readExactly(_ n: Int, timeout: TimeInterval?) async throws -> [UInt8] {
        let result = Array(buffer.prefix(n))
        buffer.removeFirst(n)
        return result
    }
}

/// Decodes the RFC 1928 ATYP + address + port shape shared verbatim by
/// SOCKS5's CONNECT target and Shadowsocks' address chunk (see ProxyKit's
/// `ProxyAddress.socks5Encoded`).
private func decodeAddressPort(atyp: UInt8, transport: any ByteStreamSource) async throws -> DecodedTarget {
    let address: ProxyAddress
    switch atyp {
    case 0x01: address = .ipv4(try await transport.readExactly(4, timeout: nil))
    case 0x04: address = .ipv6(try await transport.readExactly(16, timeout: nil))
    case 0x03:
        let len = try await transport.readExactly(1, timeout: nil)
        address = .domain(String(decoding: try await transport.readExactly(Int(len[0]), timeout: nil), as: UTF8.self))
    default:
        preconditionFailure("unexpected ATYP \(atyp)")
    }
    let portBytes = try await transport.readExactly(2, timeout: nil)
    let port = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])
    return DecodedTarget(host: proxyAddressToHost(address), port: port)
}

/// Wraps a real `NWConnection` as a `ByteStreamSource & ByteStreamSink`,
/// buffering partial reads the same way `TCPConn`/each `Session` does --
/// the root of the server-side layer stack, mirroring the client-side root (`TCPConn`).
private final class RawAdapter: ByteStreamSource, ByteStreamSink {
    private let connection: NWConnection
    private var buffered: [UInt8] = []

    init(connection: NWConnection) { self.connection = connection }

    func send(_ bytes: [UInt8], timeout: TimeInterval?) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(content: Data(bytes), completion: .contentProcessed { error in
                if let error { cont.resume(throwing: error) } else { cont.resume() }
            })
        }
    }

    private func receiveChunk() async throws -> [UInt8] {
        try await withCheckedThrowingContinuation { cont in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, _, error in
                if let error { cont.resume(throwing: error); return }
                cont.resume(returning: data.map(Array.init) ?? [])
            }
        }
    }

    func readExactly(_ n: Int, timeout: TimeInterval?) async throws -> [UInt8] {
        while buffered.count < n {
            let chunk = try await receiveChunk()
            if chunk.isEmpty { throw ProxyError.connectionClosed }
            buffered += chunk
        }
        let result = Array(buffered.prefix(n))
        buffered.removeFirst(n)
        return result
    }
}

private enum ServerTestError: Error, Equatable { case authRejected }

/// Reads the client's SOCKS5 greeting/CONNECT off `transport`, replying with
/// whatever `auth` implies (no-auth, or RFC 1929 username/password), and
/// returns the decoded CONNECT target. Throws `authRejected` (after sending
/// the real failure reply) instead of crashing when credentials mismatch --
/// mirrors what a real server does when a chain hop is misconfigured.
private func socks5ServerAcceptConnect(auth: SOCKS5Auth, over transport: any (ByteStreamSource & ByteStreamSink)) async throws -> DecodedTarget {
    let greeting = try await transport.readExactly(2, timeout: nil) // ver, nmethods
    precondition(greeting[0] == 0x05, "unexpected SOCKS version")
    let methods = try await transport.readExactly(Int(greeting[1]), timeout: nil)
    let selected: UInt8 = { if case .usernamePassword = auth { return 0x02 } else { return 0x00 } }()
    precondition(methods.contains(selected), "client didn't offer expected method")
    try await transport.send([0x05, selected], timeout: nil)

    if case .usernamePassword(let expectedUser, let expectedPass) = auth {
        let head = try await transport.readExactly(2, timeout: nil)
        let uname = try await transport.readExactly(Int(head[1]), timeout: nil)
        let plen = try await transport.readExactly(1, timeout: nil)
        let passwd = try await transport.readExactly(Int(plen[0]), timeout: nil)
        let ok = String(decoding: uname, as: UTF8.self) == expectedUser && String(decoding: passwd, as: UTF8.self) == expectedPass
        try await transport.send([0x01, ok ? 0x00 : 0x01], timeout: nil)
        guard ok else { throw ServerTestError.authRejected }
    }

    let head = try await transport.readExactly(4, timeout: nil) // ver, cmd, rsv, atyp
    let target = try await decodeAddressPort(atyp: head[3], transport: transport)
    try await transport.send([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0], timeout: nil) // succeeded, bound addr unused
    return target
}

/// Server-side Shadowsocks framing over `inner`: consumes the client's salt
/// + address chunk on `acceptHandshake`, then transparently
/// encrypts/decrypts everything else, exposing the same
/// `ByteStreamSource & ByteStreamSink` shape so a further protocol can run
/// its own handshake directly on top of it -- the server-side mirror of
/// `ShadowsocksSession` itself.
private final class ShadowsocksServerAdapter: ByteStreamSource, ByteStreamSink {
    private let inner: any (ByteStreamSource & ByteStreamSink)
    private let cipher: ShadowsocksCipher
    private let masterKey: [UInt8]
    private var reader: ShadowsocksChunkCrypto!
    private var writer: ShadowsocksChunkCrypto!
    private var buffered: [UInt8] = []
    private(set) var chunksRead = 0

    init(inner: any (ByteStreamSource & ByteStreamSink), password: String, cipher: ShadowsocksCipher) {
        self.inner = inner
        self.cipher = cipher
        self.masterKey = evpBytesToKey(password: password, keyLength: cipher.keyLength)
    }

    func acceptHandshake() async throws -> DecodedTarget {
        let clientSalt = try await inner.readExactly(cipher.saltLength, timeout: nil)
        reader = ShadowsocksChunkCrypto(cipher: cipher, key: shadowsocksDeriveSubkey(masterKey: masterKey, salt: clientSalt, cipher: cipher))
        let addressBytes = try await reader.openChunk(from: inner, timeout: nil)
        chunksRead += 1

        let serverSalt = (0..<cipher.saltLength).map { _ in UInt8.random(in: 0...255) }
        writer = ShadowsocksChunkCrypto(cipher: cipher, key: shadowsocksDeriveSubkey(masterKey: masterKey, salt: serverSalt, cipher: cipher))
        try await inner.send(serverSalt, timeout: nil)

        let source = StaticByteSource(addressBytes)
        let atyp = try await source.readExactly(1, timeout: nil)[0]
        return try await decodeAddressPort(atyp: atyp, transport: source)
    }

    /// Splits into <= 0x3FFF-byte chunks, mirroring `ShadowsocksSession.send`
    /// -- `sealChunk` traps on anything larger, and a real server echoing an
    /// oversized payload back would chunk it the same way.
    func send(_ bytes: [UInt8], timeout: TimeInterval?) async throws {
        var offset = 0
        while offset < bytes.count {
            let end = min(offset + ShadowsocksMaxChunkSize.value, bytes.count)
            try await inner.send(writer.sealChunk(Array(bytes[offset..<end])), timeout: timeout)
            offset = end
        }
    }

    func readExactly(_ n: Int, timeout: TimeInterval?) async throws -> [UInt8] {
        while buffered.count < n {
            let chunk = try await reader.openChunk(from: inner, timeout: timeout)
            chunksRead += 1
            buffered += chunk
        }
        let result = Array(buffered.prefix(n))
        buffered.removeFirst(n)
        return result
    }
}

/// Decodes the client's real VMess AEAD request header off `inner` (the same
/// wire format `VMessRequest.build` produces -- see VMessSessionLiveSocketTests'
/// `FakeVMessServer` for the single-hop version this mirrors), replies with
/// a valid AEAD response header, and returns the decoded request target plus
/// the request body key/IV a caller needs to wrap `inner` in a
/// `VMessServerAdapter` for the (now AEAD-chunked) body that follows.
/// Only handles IPv4/domain targets (ATYP 1/2) -- enough for these tests.
private func vmessServerAcceptHandshake(cmdKey: [UInt8], inner: any (ByteStreamSource & ByteStreamSink), responseOptionByte: UInt8) async throws -> (target: DecodedTarget, requestBodyKey: [UInt8], requestBodyIV: [UInt8]) {
    let authID = try await inner.readExactly(16, timeout: nil)
    let lengthAndNonce = try await inner.readExactly(18 + 8, timeout: nil)
    let connectionNonce = Array(lengthAndNonce[18..<26])

    let lengthKey = vmessKDF16(key: cmdKey, path: [Array("VMess Header AEAD Key_Length".utf8), authID, connectionNonce])
    let lengthNonce = Array(vmessKDF(key: cmdKey, path: [Array("VMess Header AEAD Nonce_Length".utf8), authID, connectionNonce]).prefix(12))
    let lengthBytes = try aesGCMOpen(key: lengthKey, nonce: lengthNonce, sealed: Array(lengthAndNonce[0..<18]), aad: authID)
    let headerLen = Int(lengthBytes[0]) << 8 | Int(lengthBytes[1])

    let sealedHeader = try await inner.readExactly(headerLen + 16, timeout: nil)
    let requestPlain = try openVMessAEADHeader(key: cmdKey, authID: authID, remainder: lengthAndNonce + sealedHeader)

    let requestBodyIV = Array(requestPlain[1..<17])
    let requestBodyKey = Array(requestPlain[17..<33])
    let responseHeaderByte = requestPlain[33]
    let port = UInt16(requestPlain[38]) << 8 | UInt16(requestPlain[39])
    let atyp = requestPlain[40]
    let host: String
    switch atyp {
    case 0x01:
        host = requestPlain[41..<45].map { String($0) }.joined(separator: ".")
    case 0x02:
        let len = Int(requestPlain[41])
        host = String(decoding: requestPlain[42..<(42 + len)], as: UTF8.self)
    default:
        preconditionFailure("unsupported ATYP \(atyp) in test")
    }

    let responseBodyKey = Array(sha256(requestBodyKey).prefix(16))
    let responseBodyIV = Array(sha256(requestBodyIV).prefix(16))
    let header: [UInt8] = [responseHeaderByte, responseOptionByte, 0, 0]

    let respLengthKey = vmessKDF16(key: responseBodyKey, path: [Array("AEAD Resp Header Len Key".utf8)])
    let respLengthNonce = Array(vmessKDF(key: responseBodyIV, path: [Array("AEAD Resp Header Len IV".utf8)]).prefix(12))
    let sealedRespLength = aesGCMSeal(key: respLengthKey, nonce: respLengthNonce, plaintext: UInt16(header.count).bigEndianBytes, aad: [])

    let respHeaderKey = vmessKDF16(key: responseBodyKey, path: [Array("AEAD Resp Header Key".utf8)])
    let respHeaderNonce = Array(vmessKDF(key: responseBodyIV, path: [Array("AEAD Resp Header IV".utf8)]).prefix(12))
    let sealedRespHeader = aesGCMSeal(key: respHeaderKey, nonce: respHeaderNonce, plaintext: header, aad: [])

    try await inner.send(sealedRespLength + sealedRespHeader, timeout: nil)

    return (DecodedTarget(host: host, port: port), requestBodyKey, requestBodyIV)
}

/// Server-side AEAD body framing over `inner`: decrypts inbound chunks and
/// seals outbound ones using the same length-prefixed, per-chunk-counter
/// format `VMessSession`'s client side now speaks (see VMessCore's
/// `sealVMessBodyChunk`/`openVMessBodyChunkPayload`), exposing the same
/// `ByteStreamSource & ByteStreamSink` shape so a further protocol can run
/// its own handshake directly on top of it -- the server-side mirror of
/// `ShadowsocksServerAdapter` above.
private final class VMessServerAdapter: ByteStreamSource, ByteStreamSink {
    private let inner: any (ByteStreamSource & ByteStreamSink)
    private let requestBodyKey: [UInt8]
    private let requestBodyIV: [UInt8]
    private let responseBodyKey: [UInt8]
    private let responseBodyIV: [UInt8]
    private var buffered: [UInt8] = []
    private var inboundChunkCounter: UInt16 = 0
    private var outboundChunkCounter: UInt16 = 0

    init(inner: any (ByteStreamSource & ByteStreamSink), requestBodyKey: [UInt8], requestBodyIV: [UInt8]) {
        self.inner = inner
        self.requestBodyKey = requestBodyKey
        self.requestBodyIV = requestBodyIV
        self.responseBodyKey = Array(sha256(requestBodyKey).prefix(16))
        self.responseBodyIV = Array(sha256(requestBodyIV).prefix(16))
    }

    /// Server->client chunks are sealed under the *response* body key/IV --
    /// the same pair the real client derives to decrypt them (see
    /// `VMessSession`'s own `responseBodyKey`/`responseBodyIV`).
    func send(_ bytes: [UInt8], timeout: TimeInterval?) async throws {
        var offset = 0
        while offset < bytes.count {
            let end = min(offset + vmessMaxChunkPlaintext, bytes.count)
            let framed = sealVMessBodyChunk(key: responseBodyKey, iv: responseBodyIV, counter: outboundChunkCounter, plaintext: Array(bytes[offset..<end]))
            outboundChunkCounter &+= 1
            try await inner.send(framed, timeout: timeout)
            offset = end
        }
    }

    private func readNextChunk(timeout: TimeInterval?) async throws -> [UInt8] {
        let lengthBytes = try await inner.readExactly(2, timeout: timeout)
        let length = Int(lengthBytes[0]) << 8 | Int(lengthBytes[1])
        let sealed = try await inner.readExactly(length, timeout: timeout)
        let plaintext = try openVMessBodyChunkPayload(key: requestBodyKey, iv: requestBodyIV, counter: inboundChunkCounter, sealed: sealed)
        inboundChunkCounter &+= 1
        return plaintext
    }

    func readExactly(_ n: Int, timeout: TimeInterval?) async throws -> [UInt8] {
        while buffered.count < n {
            buffered += try await readNextChunk(timeout: timeout)
        }
        let result = Array(buffered.prefix(n))
        buffered.removeFirst(n)
        return result
    }
}

/// Which server-side role to play for one hop, mirroring `ProxyHopProtocol`
/// (ChainCore's client-side equivalent) but carrying whatever the server
/// needs to *verify* the handshake rather than to *dial* anything.
private enum ServerHopKind {
    case socks5(auth: SOCKS5Auth)
    case shadowsocks(password: String, cipher: ShadowsocksCipher)
    case vmess(uuid: String)
}

/// Layers server-side decode logic for each hop in `hops`, in order, over
/// `raw`, returning the decoded target for every hop (so a test can assert
/// hop *i* was asked to reach hop *i+1*'s declared address) plus the fully
/// unwrapped transport for exchanging the real application payload.
private func runServerHops(_ hops: [ServerHopKind], over raw: any (ByteStreamSource & ByteStreamSink)) async throws -> (targets: [DecodedTarget], transport: any (ByteStreamSource & ByteStreamSink), shadowsocksAdapters: [ShadowsocksServerAdapter]) {
    var transport: any (ByteStreamSource & ByteStreamSink) = raw
    var targets: [DecodedTarget] = []
    var shadowsocksAdapters: [ShadowsocksServerAdapter] = []
    for hop in hops {
        switch hop {
        case .socks5(let auth):
            targets.append(try await socks5ServerAcceptConnect(auth: auth, over: transport))
            // SOCKS5 adds no framing -- transport unchanged.
        case .shadowsocks(let password, let cipher):
            let adapter = ShadowsocksServerAdapter(inner: transport, password: password, cipher: cipher)
            targets.append(try await adapter.acceptHandshake())
            shadowsocksAdapters.append(adapter)
            transport = adapter
        case .vmess(let uuid):
            let cmdKey = md5(parseUUID(uuid) + cmdKeyMagic)
            let handshake = try await vmessServerAcceptHandshake(cmdKey: cmdKey, inner: transport, responseOptionByte: 7)
            targets.append(handshake.target)
            transport = VMessServerAdapter(inner: transport, requestBodyKey: handshake.requestBodyKey, requestBodyIV: handshake.requestBodyIV)
        }
    }
    return (targets, transport, shadowsocksAdapters)
}

private final class ChainTestServer {
    enum ServerError: Error { case noConnection }

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

    /// Runs the server side of `hops` over the one real connection, then
    /// echoes back exactly `payloadLength` bytes of whatever the fully
    /// unwrapped body carries.
    @discardableResult
    func handshakeAndEcho(_ hops: [ServerHopKind], payloadLength: Int) async throws -> (targets: [DecodedTarget], echoed: [UInt8], shadowsocksChunkCounts: [Int]) {
        try await waitForConnection()
        let raw = RawAdapter(connection: connection!)
        let (targets, transport, ssAdapters) = try await runServerHops(hops, over: raw)
        let received = try await transport.readExactly(payloadLength, timeout: nil)
        try await transport.send(received, timeout: nil)
        return (targets, received, ssAdapters.map(\.chunksRead))
    }

    /// Like `handshakeAndEcho`, but for tests that drive several separate
    /// send/receive round trips instead of one payload.
    func handshakeThen(_ hops: [ServerHopKind], _ body: (any (ByteStreamSource & ByteStreamSink)) async throws -> Void) async throws -> [DecodedTarget] {
        try await waitForConnection()
        let raw = RawAdapter(connection: connection!)
        let (targets, transport, _) = try await runServerHops(hops, over: raw)
        try await body(transport)
        return targets
    }

    /// Runs only the handshake (no payload exchange) -- for negative tests
    /// where the chain build itself is expected to fail partway through.
    @discardableResult
    func handshakeOnly(_ hops: [ServerHopKind]) async throws -> [DecodedTarget] {
        try await waitForConnection()
        let raw = RawAdapter(connection: connection!)
        return try await runServerHops(hops, over: raw).targets
    }

    func stop() {
        connection?.cancel()
        listener.cancel()
    }
}

// MARK: - Tests

final class ChainCoreLiveSocketTests: XCTestCase {
    private let uuidA = "0398d470-bc09-4cd5-889d-3ae4c569b6da"

    // MARK: Happy paths, various lengths and orders

    func testThreeHopChainSOCKS5ThenShadowsocksThenVMessOverRealSocket() async throws {
        let server = try ChainTestServer()
        let listenPort = try await server.start()
        defer { server.stop() }

        let ssPassword = "chain-test-password"
        let ssCipher = ShadowsocksCipher.aes128Gcm
        let payload = Array("hello through a 3-hop socks5->shadowsocks->vmess chain".utf8)

        async let serverSide = server.handshakeAndEcho(
            [.socks5(auth: .none), .shadowsocks(password: ssPassword, cipher: ssCipher), .vmess(uuid: uuidA)],
            payloadLength: payload.count
        )

        let hops = [
            ProxyHop(host: "127.0.0.1", port: listenPort, protocolConfig: .socks5(auth: .none)),
            ProxyHop(host: "127.0.0.1", port: 9001, protocolConfig: .shadowsocks(password: ssPassword, cipher: ssCipher)),
            ProxyHop(host: "127.0.0.1", port: 9002, protocolConfig: .vmess(uuid: uuidA)),
        ]
        let transport = try await ProxyChain.open(hops: hops, finalTargetHost: "example.com", finalTargetPort: 443)
        try await transport.send(payload, timeout: nil)
        let echoed = try await transport.readExactly(payload.count, timeout: nil)
        transport.close()

        let result = try await serverSide
        XCTAssertEqual(result.targets[0], DecodedTarget(host: "127.0.0.1", port: 9001)) // hop0 -> hop1's address
        XCTAssertEqual(result.targets[1], DecodedTarget(host: "127.0.0.1", port: 9002)) // hop1 -> hop2's address
        XCTAssertEqual(result.targets[2], DecodedTarget(host: "example.com", port: 443)) // hop2 (last) -> final target
        XCTAssertEqual(echoed, payload)
        XCTAssertEqual(result.echoed, payload)
    }

    func testTwoHopChainSOCKS5ThenShadowsocksOverRealSocket() async throws {
        let server = try ChainTestServer()
        let listenPort = try await server.start()
        defer { server.stop() }

        let ssPassword = "two-hop-test-password"
        let ssCipher = ShadowsocksCipher.aes256Gcm
        let payload = Array("hello through a 2-hop socks5->shadowsocks chain".utf8)

        async let serverSide = server.handshakeAndEcho(
            [.socks5(auth: .none), .shadowsocks(password: ssPassword, cipher: ssCipher)],
            payloadLength: payload.count
        )

        let hops = [
            ProxyHop(host: "127.0.0.1", port: listenPort, protocolConfig: .socks5(auth: .none)),
            ProxyHop(host: "127.0.0.1", port: 9500, protocolConfig: .shadowsocks(password: ssPassword, cipher: ssCipher)),
        ]
        let transport = try await ProxyChain.open(hops: hops, finalTargetHost: "example.org", finalTargetPort: 8080)
        try await transport.send(payload, timeout: nil)
        let echoed = try await transport.readExactly(payload.count, timeout: nil)
        transport.close()

        let result = try await serverSide
        XCTAssertEqual(result.targets[0], DecodedTarget(host: "127.0.0.1", port: 9500))
        XCTAssertEqual(result.targets[1], DecodedTarget(host: "example.org", port: 8080))
        XCTAssertEqual(echoed, payload)
    }

    /// Four hops, deliberately mixed order (VMess first, SOCKS5 repeated
    /// twice non-consecutively) -- the "combine any protocol, any order,
    /// any length" claim, not just a fixed canonical ordering.
    func testFourHopChainMixedOrderVMessSOCKS5ShadowsocksSOCKS5() async throws {
        let server = try ChainTestServer()
        let listenPort = try await server.start()
        defer { server.stop() }

        let ssPassword = "four-hop-mixed-password"
        let ssCipher = ShadowsocksCipher.chacha20IetfPoly1305
        let payload = Array("hello through a 4-hop mixed-order chain".utf8)

        async let serverSide = server.handshakeAndEcho(
            [.vmess(uuid: uuidA), .socks5(auth: .none), .shadowsocks(password: ssPassword, cipher: ssCipher), .socks5(auth: .none)],
            payloadLength: payload.count
        )

        let hops = [
            ProxyHop(host: "127.0.0.1", port: listenPort, protocolConfig: .vmess(uuid: uuidA)),
            ProxyHop(host: "127.0.0.1", port: 9101, protocolConfig: .socks5(auth: .none)),
            ProxyHop(host: "127.0.0.1", port: 9102, protocolConfig: .shadowsocks(password: ssPassword, cipher: ssCipher)),
            ProxyHop(host: "127.0.0.1", port: 9103, protocolConfig: .socks5(auth: .none)),
        ]
        let transport = try await ProxyChain.open(hops: hops, finalTargetHost: "final.example", finalTargetPort: 9999)
        try await transport.send(payload, timeout: nil)
        let echoed = try await transport.readExactly(payload.count, timeout: nil)
        transport.close()

        let result = try await serverSide
        XCTAssertEqual(result.targets[0], DecodedTarget(host: "127.0.0.1", port: 9101))
        XCTAssertEqual(result.targets[1], DecodedTarget(host: "127.0.0.1", port: 9102))
        XCTAssertEqual(result.targets[2], DecodedTarget(host: "127.0.0.1", port: 9103))
        XCTAssertEqual(result.targets[3], DecodedTarget(host: "final.example", port: 9999))
        XCTAssertEqual(echoed, payload)
    }

    /// A chain of length 1 is the degenerate case of chaining -- it should
    /// behave identically to calling that protocol's `Session.open` directly
    /// (same target: the final destination, since there's no next hop).
    func testSingleHopChainsMatchDirectSessionForEachProtocol() async throws {
        for protocolName in ["socks5", "shadowsocks", "vmess"] {
            let server = try ChainTestServer()
            let listenPort = try await server.start()
            defer { server.stop() }

            let payload = Array("hello single-hop \(protocolName)".utf8)
            let ssPassword = "single-hop-password"
            let ssCipher = ShadowsocksCipher.aes128Gcm

            let hopKind: ServerHopKind
            let hopConfig: ProxyHopProtocol
            switch protocolName {
            case "socks5": hopKind = .socks5(auth: .none); hopConfig = .socks5(auth: .none)
            case "shadowsocks": hopKind = .shadowsocks(password: ssPassword, cipher: ssCipher); hopConfig = .shadowsocks(password: ssPassword, cipher: ssCipher)
            default: hopKind = .vmess(uuid: uuidA); hopConfig = .vmess(uuid: uuidA)
            }

            async let serverSide = server.handshakeAndEcho([hopKind], payloadLength: payload.count)

            let hops = [ProxyHop(host: "127.0.0.1", port: listenPort, protocolConfig: hopConfig)]
            let transport = try await ProxyChain.open(hops: hops, finalTargetHost: "solo.example", finalTargetPort: 555)
            try await transport.send(payload, timeout: nil)
            let echoed = try await transport.readExactly(payload.count, timeout: nil)
            transport.close()

            let result = try await serverSide
            XCTAssertEqual(result.targets, [DecodedTarget(host: "solo.example", port: 555)], "protocol \(protocolName)")
            XCTAssertEqual(echoed, payload, "protocol \(protocolName)")
        }
    }

    // MARK: Auth as a non-first hop

    /// SOCKS5 username/password auth works the same whether SOCKS5 is hop 0
    /// or layered over a previous hop -- here it's hop 1, riding on top of a
    /// Shadowsocks tunnel.
    func testSOCKS5UsernamePasswordAuthAsMiddleHop() async throws {
        let server = try ChainTestServer()
        let listenPort = try await server.start()
        defer { server.stop() }

        let ssPassword = "auth-mid-chain-password"
        let ssCipher = ShadowsocksCipher.aes256Gcm
        let auth = SOCKS5Auth.usernamePassword(username: "chain-user", password: "chain-pass")
        let payload = Array("hello through shadowsocks->socks5(auth) chain".utf8)

        async let serverSide = server.handshakeAndEcho(
            [.shadowsocks(password: ssPassword, cipher: ssCipher), .socks5(auth: auth)],
            payloadLength: payload.count
        )

        let hops = [
            ProxyHop(host: "127.0.0.1", port: listenPort, protocolConfig: .shadowsocks(password: ssPassword, cipher: ssCipher)),
            ProxyHop(host: "127.0.0.1", port: 9600, protocolConfig: .socks5(auth: auth)),
        ]
        let transport = try await ProxyChain.open(hops: hops, finalTargetHost: "auth-target.example", finalTargetPort: 22)
        try await transport.send(payload, timeout: nil)
        let echoed = try await transport.readExactly(payload.count, timeout: nil)
        transport.close()

        let result = try await serverSide
        XCTAssertEqual(result.targets[0], DecodedTarget(host: "127.0.0.1", port: 9600))
        XCTAssertEqual(result.targets[1], DecodedTarget(host: "auth-target.example", port: 22))
        XCTAssertEqual(echoed, payload)
    }

    // MARK: Framing edge cases

    /// Shadowsocks caps each wire chunk at 0x3FFF plaintext bytes
    /// (`ShadowsocksMaxChunkSize`); a larger payload must still split
    /// correctly even when Shadowsocks isn't the first hop (its `send`
    /// receives bytes already having passed through SOCKS5's raw relay).
    func testOversizedPayloadSplitsAcrossChunksWhenShadowsocksIsNotFirstHop() async throws {
        let server = try ChainTestServer()
        let listenPort = try await server.start()
        defer { server.stop() }

        let ssPassword = "oversized-payload-password"
        let ssCipher = ShadowsocksCipher.aes256Gcm
        let payload = [UInt8](repeating: 0x37, count: ShadowsocksMaxChunkSize.value + 5000)

        async let serverSide = server.handshakeAndEcho(
            [.socks5(auth: .none), .shadowsocks(password: ssPassword, cipher: ssCipher)],
            payloadLength: payload.count
        )

        let hops = [
            ProxyHop(host: "127.0.0.1", port: listenPort, protocolConfig: .socks5(auth: .none)),
            ProxyHop(host: "127.0.0.1", port: 9700, protocolConfig: .shadowsocks(password: ssPassword, cipher: ssCipher)),
        ]
        let transport = try await ProxyChain.open(hops: hops, finalTargetHost: "big.example", finalTargetPort: 80)
        try await transport.send(payload, timeout: nil)
        let echoed = try await transport.readExactly(payload.count, timeout: nil)
        transport.close()

        let result = try await serverSide
        XCTAssertEqual(echoed, payload)
        XCTAssertEqual(result.echoed, payload)
        // 1 chunk for the address handshake + at least 2 for a payload that's
        // deliberately larger than one max-size chunk.
        XCTAssertGreaterThanOrEqual(result.shadowsocksChunkCounts[0], 3)
    }

    /// Several separate send/receive round trips through the same chain must
    /// stay in sync -- proving each layer's internal buffering (added so a
    /// `Session` can serve as the next hop's transport) doesn't leak or
    /// desync bytes across repeated use, not just a single round trip.
    func testMultipleRoundTripsStaySynchronizedAcrossThreeHopChain() async throws {
        let server = try ChainTestServer()
        let listenPort = try await server.start()
        defer { server.stop() }

        let ssPassword = "multi-roundtrip-password"
        let ssCipher = ShadowsocksCipher.aes128Gcm
        let messages = ["first message", "a somewhat longer second message here", "3rd"].map { Array($0.utf8) }

        async let serverSide: [DecodedTarget] = server.handshakeThen(
            [.socks5(auth: .none), .shadowsocks(password: ssPassword, cipher: ssCipher), .vmess(uuid: uuidA)]
        ) { transport in
            for message in messages {
                let received = try await transport.readExactly(message.count, timeout: nil)
                try await transport.send(received, timeout: nil)
            }
        }

        let hops = [
            ProxyHop(host: "127.0.0.1", port: listenPort, protocolConfig: .socks5(auth: .none)),
            ProxyHop(host: "127.0.0.1", port: 9800, protocolConfig: .shadowsocks(password: ssPassword, cipher: ssCipher)),
            ProxyHop(host: "127.0.0.1", port: 9801, protocolConfig: .vmess(uuid: uuidA)),
        ]
        let transport = try await ProxyChain.open(hops: hops, finalTargetHost: "roundtrip.example", finalTargetPort: 1234)

        for message in messages {
            try await transport.send(message, timeout: nil)
            let echoed = try await transport.readExactly(message.count, timeout: nil)
            XCTAssertEqual(echoed, message)
        }
        transport.close()

        _ = try await serverSide
    }

    // MARK: Failure modes

    func testEmptyHopsListThrowsEmptyChainError() async {
        do {
            _ = try await ProxyChain.open(hops: [], finalTargetHost: "example.com", finalTargetPort: 80)
            XCTFail("expected ProxyChainError.emptyChain")
        } catch ProxyChainError.emptyChain {
            // expected
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    /// Wrong credentials on a *middle* hop (not hop 0) must fail the whole
    /// chain build with that hop's real error, not hang or silently
    /// misattribute the failure to a different layer.
    func testWrongSOCKS5CredentialsAsMiddleHopFailsChainBuild() async throws {
        let server = try ChainTestServer()
        let listenPort = try await server.start()
        defer { server.stop() }

        let realAuth = SOCKS5Auth.usernamePassword(username: "user", password: "correct-password")

        async let serverSide: [DecodedTarget] = server.handshakeOnly([.socks5(auth: .none), .socks5(auth: realAuth)])

        let hops = [
            ProxyHop(host: "127.0.0.1", port: listenPort, protocolConfig: .socks5(auth: .none)),
            ProxyHop(host: "127.0.0.1", port: 9900, protocolConfig: .socks5(auth: .usernamePassword(username: "user", password: "WRONG-password"))),
        ]

        do {
            _ = try await ProxyChain.open(hops: hops, finalTargetHost: "unreachable.example", finalTargetPort: 80)
            XCTFail("expected chain build to fail on the middle hop's bad credentials")
        } catch SOCKS5Error.authenticationFailed(let status) {
            XCTAssertEqual(status, 0x01)
        }

        do {
            _ = try await serverSide
            XCTFail("server side should have observed the rejected auth too")
        } catch ServerTestError.authRejected {
            // expected
        }
    }

    // MARK: Teardown

    /// Closing the outermost session of an N-hop chain must cascade all the
    /// way down to the one real TCP connection at its root, and further
    /// operations after that must fail predictably rather than hang or crash.
    func testCloseCascadesThroughAllHopsAndSubsequentOperationsFail() async throws {
        let server = try ChainTestServer()
        let listenPort = try await server.start()
        defer { server.stop() }

        let ssPassword = "close-cascade-password"
        let ssCipher = ShadowsocksCipher.aes128Gcm
        let payload = Array("closing soon".utf8)

        async let serverSide = server.handshakeAndEcho(
            [.socks5(auth: .none), .shadowsocks(password: ssPassword, cipher: ssCipher)],
            payloadLength: payload.count
        )

        let hops = [
            ProxyHop(host: "127.0.0.1", port: listenPort, protocolConfig: .socks5(auth: .none)),
            ProxyHop(host: "127.0.0.1", port: 9950, protocolConfig: .shadowsocks(password: ssPassword, cipher: ssCipher)),
        ]
        let transport = try await ProxyChain.open(hops: hops, finalTargetHost: "close-test.example", finalTargetPort: 80)
        try await transport.send(payload, timeout: nil)
        _ = try await transport.readExactly(payload.count, timeout: nil)
        _ = try await serverSide

        transport.close()

        do {
            try await transport.send(Array("after close".utf8), timeout: nil)
            // Some platforms may accept the write locally before the RST is observed.
        } catch {
            // expected on most platforms
        }
    }
}
