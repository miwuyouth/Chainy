import XCTest
import ChainCore

/// Compatibility gate against the real open-source Xray-core server.
///
/// Wire compatibility is established only against the real open-source
/// Xray-core implementation. These tests use Xray's VMess inbound plus a
/// real UDP socket echo target and compare the exact payload that left and
/// returned. They are intentionally part of InteropTests, which requires
/// `brew install xray` and is run separately from ordinary hermetic CI.
final class RealVMessUDPInteropTests: XCTestCase {
    private func roundTrip(_ hops: [ProxyHop], label: String) async throws {
        try XCTSkipUnless(XrayTestEnvironment.isAvailable, "real xray/openssl not installed")
        _ = XrayTestEnvironment.shared
        let (_, udp) = try await EchoTargets.shared.value
        let payload = Array("real-xray-vmess-udp:\(label)".utf8)
        let relay = try await ProxyChain.openUDPRelay(hops: hops, connectTimeout: 10, logID: "real-xray")
        defer { relay.close() }

        try await relay.send(targetHost: XrayTestEnvironment.host, targetPort: udp.port, payload: payload, timeout: 10)
        let reply = try await relay.receive(timeout: 10)
        XCTAssertEqual(reply.payload, payload)
    }

    func testSingleVMessHopUDPAgainstRealXray() async throws {
        try await roundTrip([CanonicalProtocol.vmess.hop()], label: "vmess")
    }

    func testSingleVMessChaChaHopUDPAgainstRealXray() async throws {
        let hop = ProxyHop(
            host: XrayTestEnvironment.host, port: XrayTestEnvironment.Ports.vmess,
            protocolConfig: .vmess(uuid: XrayTestEnvironment.vmessUUID, security: .chacha20Poly1305)
        )
        try await roundTrip([hop], label: "vmess-chacha20-poly1305")
    }

    func testShadowsocksThenVMessUDPAgainstRealXray() async throws {
        try await roundTrip(
            [CanonicalProtocol.shadowsocks.hop(), CanonicalProtocol.vmess.hop()],
            label: "shadowsocks-to-vmess"
        )
    }
}
