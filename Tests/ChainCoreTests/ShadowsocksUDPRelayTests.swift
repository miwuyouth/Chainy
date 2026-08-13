import XCTest
import ProxyKit
import ShadowsocksCore
import VMessCore
@testable import ChainCore

/// Fast, in-memory coverage for `ShadowsocksUDPRelay` -- exercises the
/// nest-outward-on-send / peel-inward-on-receive logic against a fake
/// `DatagramTransport`, the same style `SOCKS5CoreTests`/`ShadowsocksCoreTests`
/// already use fake `ByteStreamSource`/`ByteStreamSink`s to test the TCP
/// path without a real socket. See `ChainCoreLiveSocketTests` for the real
/// -loopback-socket counterpart.
final class ShadowsocksUDPRelayTests: XCTestCase {
    private final class FakeDatagramTransport: DatagramTransport {
        private(set) var sent: [[UInt8]] = []
        private var incoming: [[UInt8]] = []
        private(set) var closed = false

        func enqueueIncoming(_ packet: [UInt8]) { incoming.append(packet) }

        func send(_ bytes: [UInt8], timeout: TimeInterval?) async throws {
            sent.append(bytes)
        }

        func receiveDatagram(timeout: TimeInterval?) async throws -> [UInt8] {
            guard !incoming.isEmpty else { throw ProxyError.connectionClosed }
            return incoming.removeFirst()
        }

        func close() { closed = true }
    }

    private func makeRelay(hops: [ProxyHop], transport: FakeDatagramTransport) async throws -> ShadowsocksUDPRelay {
        try await ShadowsocksUDPRelay.open(hops: hops, makeTransport: { _ in transport })
    }

    // MARK: - send

    func testSendSealsExactlyOnePacketForASingleHopChain() async throws {
        let hop = ProxyHop(host: "ss1.example", port: 8388, protocolConfig: .shadowsocks(password: "pw1", cipher: .aes256Gcm))
        let transport = FakeDatagramTransport()
        let relay = try await makeRelay(hops: [hop], transport: transport)

        try await relay.send(targetHost: "8.8.8.8", targetPort: 53, payload: Array("query".utf8))

        XCTAssertEqual(transport.sent.count, 1)
        let opened = try shadowsocksOpenUDPPacket(password: "pw1", cipher: .aes256Gcm, packet: transport.sent[0])
        XCTAssertEqual(opened.address, .ipv4([8, 8, 8, 8]))
        XCTAssertEqual(opened.port, 53)
        XCTAssertEqual(opened.payload, Array("query".utf8))
    }

    func testSendNestsOnceForEachHopInATwoHopChain() async throws {
        let hop0 = ProxyHop(host: "ss1.example", port: 1111, protocolConfig: .shadowsocks(password: "pw1", cipher: .aes256Gcm))
        let hop1 = ProxyHop(host: "ss2.example", port: 2222, protocolConfig: .shadowsocks(password: "pw2", cipher: .chacha20IetfPoly1305))
        let transport = FakeDatagramTransport()
        let relay = try await makeRelay(hops: [hop0, hop1], transport: transport)

        try await relay.send(targetHost: "real-target.example", targetPort: 443, payload: [0xAA, 0xBB])

        XCTAssertEqual(transport.sent.count, 1, "exactly one physical UDP datagram, regardless of hop count")
        // The one packet sent must be addressed at hop0 (that's who we dial)
        // and, once opened with hop0's own credentials, reveal a packet
        // addressed at hop1 -- never the real target directly.
        let outer = try shadowsocksOpenUDPPacket(password: "pw1", cipher: .aes256Gcm, packet: transport.sent[0])
        XCTAssertEqual(outer.address, .domain("ss2.example"))
        XCTAssertEqual(outer.port, 2222)

        let inner = try shadowsocksOpenUDPPacket(password: "pw2", cipher: .chacha20IetfPoly1305, packet: outer.payload)
        XCTAssertEqual(inner.address, .domain("real-target.example"))
        XCTAssertEqual(inner.port, 443)
        XCTAssertEqual(inner.payload, [0xAA, 0xBB])
    }

    // MARK: - receive

    func testReceivePeelsEachHopAndReturnsTheInnermostAddress() async throws {
        let hop0 = ProxyHop(host: "ss1.example", port: 1111, protocolConfig: .shadowsocks(password: "pw1", cipher: .aes256Gcm))
        let hop1 = ProxyHop(host: "ss2.example", port: 2222, protocolConfig: .shadowsocks(password: "pw2", cipher: .aes128Gcm))
        let transport = FakeDatagramTransport()

        // Hand-build the packet a real 2-hop reply would produce: hop1's
        // server wraps the real remote's reply addressed at itself
        // (from hop1's point of view, "who replied" = the real remote), then
        // hop0's server wraps *that* addressed at hop1 (from hop0's point of
        // view, "who replied" = hop1) -- exactly `shadowsocksSealUDPPacket`
        // nested twice, innermost first.
        let innermost = try shadowsocksSealUDPPacket(password: "pw2", cipher: .aes128Gcm, targetHost: .domain("real-remote.example"), targetPort: 53, payload: Array("reply".utf8))
        let outer = try shadowsocksSealUDPPacket(password: "pw1", cipher: .aes256Gcm, targetHost: .domain("ss2.example"), targetPort: 2222, payload: innermost)
        transport.enqueueIncoming(outer)

        let relay = try await makeRelay(hops: [hop0, hop1], transport: transport)
        let result = try await relay.receive()

        XCTAssertEqual(result.fromHost, "real-remote.example")
        XCTAssertEqual(result.fromPort, 53)
        XCTAssertEqual(result.payload, Array("reply".utf8))
    }

    // MARK: - validation

    func testOpenRefusesAChainContainingANonShadowsocksHop() async throws {
        let hop0 = ProxyHop(host: "ss1.example", port: 1111, protocolConfig: .shadowsocks(password: "pw1", cipher: .aes256Gcm))
        let hop1 = ProxyHop(host: "vmess1.example", port: 443, protocolConfig: .vmess(uuid: "11111111-1111-1111-1111-111111111111"))
        var transportRequested = false

        do {
            _ = try await ShadowsocksUDPRelay.open(hops: [hop0, hop1], makeTransport: { _ in
                transportRequested = true
                return FakeDatagramTransport()
            })
            XCTFail("expected udpUnsupportedHop")
        } catch ProxyChainError.udpUnsupportedHop(let index, let protocolName) {
            XCTAssertEqual(index, 1)
            XCTAssertEqual(protocolName, "VMess")
        }
        XCTAssertFalse(transportRequested, "must refuse before ever opening a socket")
    }

    func testOpenRejectsAnEmptyChain() async throws {
        do {
            _ = try await ShadowsocksUDPRelay.open(hops: [], makeTransport: { _ in FakeDatagramTransport() })
            XCTFail("expected emptyChain")
        } catch ProxyChainError.emptyChain {
            // expected
        }
    }

    // MARK: - close

    func testCloseClosesTheUnderlyingTransport() async throws {
        let hop = ProxyHop(host: "ss1.example", port: 8388, protocolConfig: .shadowsocks(password: "pw1", cipher: .aes256Gcm))
        let transport = FakeDatagramTransport()
        let relay = try await makeRelay(hops: [hop], transport: transport)

        relay.close()

        XCTAssertTrue(transport.closed)
    }
}
