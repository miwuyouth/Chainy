import XCTest
import ChainCore

/// SOCKS5 UDP ASSOCIATE compatibility checks against a real Xray-core
/// inbound and a real UDP echo target. Multi-hop cases prove the SOCKS5 UDP
/// packets use the prefix chain's UDP relay instead of bypassing it.
final class RealSOCKS5UDPInteropTests: XCTestCase {
    private func roundTrip(_ hops: [ProxyHop], label: String) async throws {
        try XCTSkipUnless(XrayTestEnvironment.isAvailable, "real xray/openssl not installed")
        _ = XrayTestEnvironment.shared
        let (_, udp) = try await EchoTargets.shared.value
        let payload = Array("real-xray-socks5-udp:\(label)".utf8)
        let relay = try await ProxyChain.openUDPRelay(hops: hops, connectTimeout: 20, logID: "real-socks5-udp")
        defer { relay.close() }
        try await relay.send(targetHost: XrayTestEnvironment.host, targetPort: udp.port, payload: payload, timeout: 20)
        let reply = try await relay.receive(timeout: 20)
        XCTAssertEqual(reply.payload, payload)
    }

    func testSingleSOCKS5Hop() async throws {
        try await roundTrip([CanonicalProtocol.socks5.hop()], label: "socks5")
    }

    func testAuthenticatedSOCKS5Hop() async throws {
        try await roundTrip([
            ProxyHop(
                host: XrayTestEnvironment.host, port: XrayTestEnvironment.Ports.socks5WithAuth,
                protocolConfig: .socks5(auth: .usernamePassword(
                    username: XrayTestEnvironment.spotCheckUsername,
                    password: XrayTestEnvironment.spotCheckPassword
                ))
            ),
        ], label: "socks5-auth")
    }

    func testVMessThenSOCKS5() async throws {
        try await roundTrip([CanonicalProtocol.vmess.hop(), CanonicalProtocol.socks5.hop()], label: "vmess-socks5")
    }

    func testVLESSThenSOCKS5() async throws {
        try await roundTrip([CanonicalProtocol.vless.hop(), CanonicalProtocol.socks5.hop()], label: "vless-socks5")
    }

    func testTrojanThenSOCKS5() async throws {
        try await roundTrip([CanonicalProtocol.trojan.hop(), CanonicalProtocol.socks5.hop()], label: "trojan-socks5")
    }

    func testShadowsocksThenSOCKS5() async throws {
        try await roundTrip([CanonicalProtocol.shadowsocks.hop(), CanonicalProtocol.socks5.hop()], label: "shadowsocks-socks5")
    }

    func testSOCKS5ThenSOCKS5() async throws {
        try await roundTrip([CanonicalProtocol.socks5.hop(), CanonicalProtocol.socks5.hop()], label: "socks5-socks5")
    }

    func testHTTPPrefixIsRefusedRatherThanBypassed() async throws {
        do {
            _ = try await ProxyChain.openUDPRelay(hops: [CanonicalProtocol.http.hop(), CanonicalProtocol.socks5.hop()], connectTimeout: 10)
            XCTFail("HTTP prefix cannot carry SOCKS5 UDP relay packets")
        } catch ProxyChainError.udpUnsupportedLastHop(let protocolName) {
            XCTAssertEqual(protocolName, "HTTP")
        }
    }
}
