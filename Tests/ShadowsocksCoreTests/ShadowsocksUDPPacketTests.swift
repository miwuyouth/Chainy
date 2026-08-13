import XCTest
import ProxyKit
@testable import ShadowsocksCore

/// Coverage for `shadowsocksSealUDPPacket`/`shadowsocksOpenUDPPacket` --
/// Shadowsocks UDP relay's per-packet framing, independent of the TCP path's
/// persistent `ShadowsocksChunkCrypto` (see `ShadowsocksCoreTests` for that).
final class ShadowsocksUDPPacketTests: XCTestCase {
    func testRoundTripWithIPv4Target() throws {
        let sealed = try shadowsocksSealUDPPacket(
            password: "udp-test-password", cipher: .aes256Gcm,
            targetHost: .ipv4([8, 8, 8, 8]), targetPort: 53, payload: Array("dns query".utf8)
        )
        let opened = try shadowsocksOpenUDPPacket(password: "udp-test-password", cipher: .aes256Gcm, packet: sealed)
        XCTAssertEqual(opened.address, .ipv4([8, 8, 8, 8]))
        XCTAssertEqual(opened.port, 53)
        XCTAssertEqual(opened.payload, Array("dns query".utf8))
    }

    func testRoundTripWithIPv6Target() throws {
        let addr6 = (0..<16).map { UInt8($0) }
        let sealed = try shadowsocksSealUDPPacket(
            password: "pw", cipher: .chacha20IetfPoly1305,
            targetHost: .ipv6(addr6), targetPort: 443, payload: [0x01, 0x02, 0x03]
        )
        let opened = try shadowsocksOpenUDPPacket(password: "pw", cipher: .chacha20IetfPoly1305, packet: sealed)
        XCTAssertEqual(opened.address, .ipv6(addr6))
        XCTAssertEqual(opened.port, 443)
        XCTAssertEqual(opened.payload, [0x01, 0x02, 0x03])
    }

    func testRoundTripWithDomainTarget() throws {
        let sealed = try shadowsocksSealUDPPacket(
            password: "pw", cipher: .aes128Gcm,
            targetHost: .domain("example.com"), targetPort: 80, payload: []
        )
        let opened = try shadowsocksOpenUDPPacket(password: "pw", cipher: .aes128Gcm, packet: sealed)
        XCTAssertEqual(opened.address, .domain("example.com"))
        XCTAssertEqual(opened.port, 80)
        XCTAssertEqual(opened.payload, [])
    }

    func testEachPacketUsesAnIndependentRandomSalt() throws {
        // Unlike the TCP chunk stream's shared, incrementing nonce, every
        // UDP packet must stand alone -- confirm two packets from the same
        // session-less call site don't collide (a fixed/zero salt would be
        // a real security bug: the same salt+zero-nonce would reuse the
        // same AEAD keystream across packets).
        let a = try shadowsocksSealUDPPacket(password: "pw", cipher: .aes256Gcm, targetHost: .domain("a.example"), targetPort: 1, payload: [0])
        let b = try shadowsocksSealUDPPacket(password: "pw", cipher: .aes256Gcm, targetHost: .domain("a.example"), targetPort: 1, payload: [0])
        XCTAssertNotEqual(a.prefix(32), b.prefix(32), "salts (first 32 bytes for aes-256-gcm) should differ")
    }

    func testWrongPasswordFailsToOpen() throws {
        let sealed = try shadowsocksSealUDPPacket(password: "right", cipher: .aes256Gcm, targetHost: .domain("x.example"), targetPort: 1, payload: [1, 2, 3])
        XCTAssertThrowsError(try shadowsocksOpenUDPPacket(password: "wrong", cipher: .aes256Gcm, packet: sealed))
    }

    func testTooShortPacketThrowsPacketTooShort() {
        XCTAssertThrowsError(try shadowsocksOpenUDPPacket(password: "pw", cipher: .aes256Gcm, packet: [0x01, 0x02])) { error in
            XCTAssertEqual(error as? ShadowsocksUDPError, .packetTooShort)
        }
    }

    /// Two layers, nested by hand exactly the way `ChainCore.ShadowsocksUDPRelay`
    /// builds an outbound packet for a 2-hop chain: the inner packet
    /// (addressed at the real final target) becomes the outer packet's own
    /// payload (addressed at the second hop). Peeling in hop order --
    /// outer first, then inner -- must recover the original target/payload,
    /// and the *outer* layer's own embedded address is only ever "hop 2",
    /// never the real target (only the innermost layer knows that).
    func testManuallyNestedTwoLayerPacketPeelsInHopOrder() throws {
        let innerPacket = try shadowsocksSealUDPPacket(
            password: "hop2-password", cipher: .aes256Gcm,
            targetHost: .domain("real-target.example"), targetPort: 53, payload: Array("payload".utf8)
        )
        let outerPacket = try shadowsocksSealUDPPacket(
            password: "hop1-password", cipher: .chacha20IetfPoly1305,
            targetHost: .domain("hop2.example"), targetPort: 8388, payload: innerPacket
        )

        let peeledOuter = try shadowsocksOpenUDPPacket(password: "hop1-password", cipher: .chacha20IetfPoly1305, packet: outerPacket)
        XCTAssertEqual(peeledOuter.address, .domain("hop2.example"))
        XCTAssertEqual(peeledOuter.port, 8388)
        XCTAssertEqual(peeledOuter.payload, innerPacket)

        let peeledInner = try shadowsocksOpenUDPPacket(password: "hop2-password", cipher: .aes256Gcm, packet: peeledOuter.payload)
        XCTAssertEqual(peeledInner.address, .domain("real-target.example"))
        XCTAssertEqual(peeledInner.port, 53)
        XCTAssertEqual(peeledInner.payload, Array("payload".utf8))
    }
}
