import XCTest
import ProxyKit
@testable import TrojanCore
@testable import ChainCore

// MARK: - UDP-mode extension to `TrojanTestServer`
//
// `TrojanTestServer`/`SelfSignedIdentity` (both `internal`, defined in
// `TrojanSessionLiveSocketTests.swift`, same test target) already do the
// self-signed-TLS-server plumbing this needs -- reused as-is here rather
// than duplicated, which is why this file lives in `TrojanCoreTests` (with
// `ChainCore` added as a test-only dependency in Package.swift) instead of
// `ChainCoreTests`, even though what it actually exercises is ChainCore's
// `ProxyChain.openUDPRelay`/`TrojanUDPRelay`.

extension TrojanTestServer: ByteStreamSource {
    func readExactly(_ n: Int, timeout: TimeInterval?) async throws -> [UInt8] {
        try await readExactly(n)
    }
}

extension TrojanTestServer {
    /// Reads the credential + UDP-Associate request line (CMD=0x03, dummy
    /// ATYP+addr+port -- the same convention `TrojanUDPRelay.open` sends),
    /// then loops decoding `count` UDP relay frames and echoing each one
    /// back verbatim (same target, same payload) -- reusing `TrojanCore`'s
    /// own public `readTrojanUDPFrame`/`trojanUDPFrame`, exactly like
    /// `ChainCoreLiveSocketTests`' fake VMess server reuses `openVMessAEADHeader`
    /// rather than re-implementing the wire format independently.
    @discardableResult
    func handleUDPHandshakeAndEchoFrames(count: Int) async throws -> (passwordHex: String, decodedFrames: [(host: String, port: UInt16, payload: [UInt8])]) {
        try await waitForConnection()

        let passwordHexBytes = try await readExactly(56)
        guard let passwordHex = String(bytes: passwordHexBytes, encoding: .utf8) else { throw ServerError.malformedHeader }
        guard try await readExactly(2) == [0x0D, 0x0A] else { throw ServerError.malformedHeader }

        let cmd = try await readExactly(1)[0]
        guard cmd == TrojanCommand.udpAssociate else { throw ServerError.malformedHeader }

        let atyp = try await readExactly(1)[0]
        switch atyp {
        case 0x01: _ = try await readExactly(4)
        case 0x04: _ = try await readExactly(16)
        case 0x03:
            let len = try await readExactly(1)[0]
            _ = try await readExactly(Int(len))
        default: throw ServerError.malformedHeader
        }
        _ = try await readExactly(2) // dummy port
        guard try await readExactly(2) == [0x0D, 0x0A] else { throw ServerError.malformedHeader }

        var decoded: [(host: String, port: UInt16, payload: [UInt8])] = []
        for _ in 0..<count {
            let frame = try await readTrojanUDPFrame(from: self, timeout: nil)
            decoded.append((frame.target.displayHost, frame.targetPort, frame.payload))
            let echoFrame = try trojanUDPFrame(target: frame.target, targetPort: frame.targetPort, payload: frame.payload)
            try await write(echoFrame)
        }
        return (passwordHex, decoded)
    }
}

// MARK: - Tests

final class ChainCoreTrojanUDPRelayLiveSocketTests: XCTestCase {
    func testSingleHopTrojanUDPDispatchesAndRoundTripsOverRealTLSSocket() async throws {
        let identity = try SelfSignedIdentity()
        let server = try TrojanTestServer(identity: identity.secIdentity)
        let port = try await server.start()
        defer { server.stop() }

        let password = "udp-e2e-trojan-password"
        async let serverSide = server.handleUDPHandshakeAndEchoFrames(count: 1)

        let hops = [ProxyHop(host: "127.0.0.1", port: port, protocolConfig: .trojan(password: password, sni: "localhost", allowInsecure: true))]
        let relay = try await ProxyChain.openUDPRelay(hops: hops)
        defer { relay.close() }
        XCTAssertTrue(relay is TrojanUDPRelay)

        try await relay.send(targetHost: "dns.example", targetPort: 53, payload: Array("query".utf8), timeout: nil)

        let (passwordHex, decodedFrames) = try await serverSide
        XCTAssertEqual(passwordHex, trojanPasswordHex(password))
        XCTAssertEqual(decodedFrames.count, 1)
        XCTAssertEqual(decodedFrames[0].host, "dns.example")
        XCTAssertEqual(decodedFrames[0].port, 53)
        XCTAssertEqual(decodedFrames[0].payload, Array("query".utf8))

        let result = try await relay.receive(timeout: 5)
        XCTAssertEqual(result.fromHost, "dns.example")
        XCTAssertEqual(result.fromPort, 53)
        XCTAssertEqual(result.payload, Array("query".utf8))
    }

    /// Two different destinations, same association, same physical session
    /// -- the concrete proof `TrojanUDPRelay` needs no per-target session
    /// table the way `TunneledUDPRelay` (VMess/VLESS) does.
    func testSameSessionRelaysToTwoDifferentDestinations() async throws {
        let identity = try SelfSignedIdentity()
        let server = try TrojanTestServer(identity: identity.secIdentity)
        let port = try await server.start()
        defer { server.stop() }

        let password = "udp-multi-target-password"
        async let serverSide = server.handleUDPHandshakeAndEchoFrames(count: 2)

        let hops = [ProxyHop(host: "127.0.0.1", port: port, protocolConfig: .trojan(password: password, sni: "localhost", allowInsecure: true))]
        let relay = try await ProxyChain.openUDPRelay(hops: hops)
        defer { relay.close() }

        try await relay.send(targetHost: "first.example", targetPort: 111, payload: Array("one".utf8), timeout: nil)
        try await relay.send(targetHost: "second.example", targetPort: 222, payload: Array("two".utf8), timeout: nil)

        let (_, decodedFrames) = try await serverSide
        XCTAssertEqual(decodedFrames.map(\.host), ["first.example", "second.example"])
        XCTAssertEqual(decodedFrames.map(\.port), [111, 222])

        let resultA = try await relay.receive(timeout: 5)
        XCTAssertEqual(resultA.fromHost, "first.example")
        XCTAssertEqual(resultA.payload, Array("one".utf8))

        let resultB = try await relay.receive(timeout: 5)
        XCTAssertEqual(resultB.fromHost, "second.example")
        XCTAssertEqual(resultB.payload, Array("two".utf8))
    }
}
