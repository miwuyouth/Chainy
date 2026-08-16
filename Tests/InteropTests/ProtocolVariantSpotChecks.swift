// ProtocolVariantSpotChecks.swift
//
// Parameter variants deliberately excluded from the exhaustive 6-protocol
// chain matrix (`ChainExhaustiveTCPTests`/`ChainExhaustiveUDPTests`), to
// avoid multiplying auxiliary axes into it: SOCKS5/HTTP with username+password
// auth, VLESS without TLS, Trojan without TLS (the non-default corner, unlike
// VLESS's own default-off), Shadowsocks with the other two supported ciphers,
// and WS transport for vmess/vless/trojan (the real-world-common "+ WS + TLS"
// deployment, this whole feature's original motivation). Each is a
// single-hop real dial against a dedicated xray-core inbound, proving the
// variant connects -- not folded into every chain length/position the way
// the 6 canonical protocols are.

import XCTest
import ChainCore
import ProxyKit
import SOCKS5Core
import HTTPProxyCore
import ShadowsocksCore
import VMessCore

final class ProtocolVariantSpotChecks: XCTestCase {
    private func skipIfUnavailable() throws {
        try XCTSkipUnless(XrayTestEnvironment.isAvailable, "xray/openssl not found on this machine")
    }

    private func assertRoundTrip(_ hop: ProxyHop, label: String) async throws {
        let (tcp, _) = try await EchoTargets.shared.value
        let payload = Array("hello-\(label)".utf8)
        let transport = try await ProxyChain.open(hops: [hop], finalTargetHost: XrayTestEnvironment.host, finalTargetPort: tcp.port)
        defer { transport.close() }
        try await transport.send(payload, timeout: 10)
        let echoed = try await transport.readExactly(payload.count, timeout: 10)
        XCTAssertEqual(echoed, payload, "\(label) round-trip mismatch")
    }

    func testSOCKS5WithUsernamePasswordAuth() async throws {
        try skipIfUnavailable()
        _ = XrayTestEnvironment.shared
        let hop = ProxyHop(
            host: XrayTestEnvironment.host, port: XrayTestEnvironment.Ports.socks5WithAuth,
            protocolConfig: .socks5(auth: .usernamePassword(username: XrayTestEnvironment.spotCheckUsername, password: XrayTestEnvironment.spotCheckPassword))
        )
        try await assertRoundTrip(hop, label: "socks5-auth")
    }

    func testHTTPWithUsernamePasswordAuth() async throws {
        try skipIfUnavailable()
        _ = XrayTestEnvironment.shared
        let hop = ProxyHop(
            host: XrayTestEnvironment.host, port: XrayTestEnvironment.Ports.httpWithAuth,
            protocolConfig: .http(auth: .usernamePassword(username: XrayTestEnvironment.spotCheckUsername, password: XrayTestEnvironment.spotCheckPassword))
        )
        try await assertRoundTrip(hop, label: "http-auth")
    }

    func testVLESSWithoutTLS() async throws {
        try skipIfUnavailable()
        _ = XrayTestEnvironment.shared
        let hop = ProxyHop(
            host: XrayTestEnvironment.host, port: XrayTestEnvironment.Ports.vlessNoTLS,
            protocolConfig: .vless(uuid: XrayTestEnvironment.vlessUUID, tls: false)
        )
        try await assertRoundTrip(hop, label: "vless-notls")
    }

    /// `security=none` in a subscription link -- the rarer real-world
    /// Trojan deployment (`TrojanServerConfig.tls == false`) that runs the
    /// handshake over plain TCP instead of Trojan's spec-correct TLS
    /// default. Confirmed live against an actual node before this support
    /// existed (it drops any real TLS ClientHello but accepts the
    /// unencrypted header).
    func testTrojanWithoutTLS() async throws {
        try skipIfUnavailable()
        _ = XrayTestEnvironment.shared
        let hop = ProxyHop(
            host: XrayTestEnvironment.host, port: XrayTestEnvironment.Ports.trojanNoTLS,
            protocolConfig: .trojan(password: XrayTestEnvironment.trojanPassword, tls: false)
        )
        try await assertRoundTrip(hop, label: "trojan-notls")
    }

    func testShadowsocksAes128Gcm() async throws {
        try skipIfUnavailable()
        _ = XrayTestEnvironment.shared
        let hop = ProxyHop(
            host: XrayTestEnvironment.host, port: XrayTestEnvironment.Ports.shadowsocksAes128Gcm,
            protocolConfig: .shadowsocks(password: XrayTestEnvironment.shadowsocksPassword, cipher: .aes128Gcm)
        )
        try await assertRoundTrip(hop, label: "ss-aes128gcm")
    }

    func testShadowsocksChacha20IetfPoly1305() async throws {
        try skipIfUnavailable()
        _ = XrayTestEnvironment.shared
        let hop = ProxyHop(
            host: XrayTestEnvironment.host, port: XrayTestEnvironment.Ports.shadowsocksChacha20,
            protocolConfig: .shadowsocks(password: XrayTestEnvironment.shadowsocksPassword, cipher: .chacha20IetfPoly1305)
        )
        try await assertRoundTrip(hop, label: "ss-chacha20")
    }

    func testShadowsocks2022Aes128Gcm() async throws {
        try skipIfUnavailable()
        _ = XrayTestEnvironment.shared
        let hop = ProxyHop(
            host: XrayTestEnvironment.host, port: XrayTestEnvironment.Ports.shadowsocks2022Aes128Gcm,
            protocolConfig: .shadowsocks(password: XrayTestEnvironment.shadowsocks2022PSK128, cipher: .aead2022Blake3Aes128Gcm)
        )
        try await assertRoundTrip(hop, label: "ss2022-aes128gcm")
    }

    func testShadowsocks2022Aes256Gcm() async throws {
        try skipIfUnavailable()
        _ = XrayTestEnvironment.shared
        let hop = ProxyHop(
            host: XrayTestEnvironment.host, port: XrayTestEnvironment.Ports.shadowsocks2022Aes256Gcm,
            protocolConfig: .shadowsocks(password: XrayTestEnvironment.shadowsocks2022PSK256, cipher: .aead2022Blake3Aes256Gcm)
        )
        try await assertRoundTrip(hop, label: "ss2022-aes256gcm")
    }

    func testShadowsocks2022Chacha20Poly1305() async throws {
        try skipIfUnavailable()
        _ = XrayTestEnvironment.shared
        let hop = ProxyHop(
            host: XrayTestEnvironment.host, port: XrayTestEnvironment.Ports.shadowsocks2022Chacha20,
            protocolConfig: .shadowsocks(password: XrayTestEnvironment.shadowsocks2022PSK256, cipher: .aead2022Blake3Chacha20Poly1305)
        )
        try await assertRoundTrip(hop, label: "ss2022-chacha20")
    }

    func testVMessWithWebSocketAndTLS() async throws {
        try skipIfUnavailable()
        _ = XrayTestEnvironment.shared
        let hop = ProxyHop(
            host: XrayTestEnvironment.host, port: XrayTestEnvironment.Ports.vmessWSTLS,
            protocolConfig: .vmess(uuid: XrayTestEnvironment.vmessUUID, tls: true, sni: "localhost", allowInsecure: true, wsPath: XrayTestEnvironment.vmessWSPath, wsHost: "localhost")
        )
        try await assertRoundTrip(hop, label: "vmess-ws-tls")
    }

    func testVMessChaCha20Poly1305AgainstRealXray() async throws {
        try skipIfUnavailable()
        _ = XrayTestEnvironment.shared
        let hop = ProxyHop(
            host: XrayTestEnvironment.host, port: XrayTestEnvironment.Ports.vmess,
            protocolConfig: .vmess(uuid: XrayTestEnvironment.vmessUUID, security: .chacha20Poly1305)
        )
        try await assertRoundTrip(hop, label: "vmess-chacha20-poly1305")
    }

    func testVMessAuthenticatedLengthAgainstRealXray() async throws {
        try skipIfUnavailable()
        _ = XrayTestEnvironment.shared
        let hop = ProxyHop(
            host: XrayTestEnvironment.host, port: XrayTestEnvironment.Ports.vmessAuthenticatedLength,
            protocolConfig: .vmess(
                uuid: XrayTestEnvironment.vmessUUID,
                bodyOptions: VMessBodyOptions(chunkMasking: true, globalPadding: true, authenticatedLength: true)
            )
        )
        try await assertRoundTrip(hop, label: "vmess-authenticated-length")
    }

    func testVLESSWithWebSocketAndTLS() async throws {
        try skipIfUnavailable()
        _ = XrayTestEnvironment.shared
        let hop = ProxyHop(
            host: XrayTestEnvironment.host, port: XrayTestEnvironment.Ports.vlessWSTLS,
            protocolConfig: .vless(uuid: XrayTestEnvironment.vlessUUID, tls: true, sni: "localhost", allowInsecure: true, wsPath: XrayTestEnvironment.vlessWSPath, wsHost: "localhost")
        )
        try await assertRoundTrip(hop, label: "vless-ws-tls")
    }

    func testTrojanWithWebSocket() async throws {
        try skipIfUnavailable()
        _ = XrayTestEnvironment.shared
        let hop = ProxyHop(
            host: XrayTestEnvironment.host, port: XrayTestEnvironment.Ports.trojanWS,
            protocolConfig: .trojan(password: XrayTestEnvironment.trojanPassword, sni: "localhost", allowInsecure: true, wsPath: XrayTestEnvironment.trojanWSPath, wsHost: "localhost")
        )
        try await assertRoundTrip(hop, label: "trojan-ws")
    }

    /// A 3-hop chain mixing a plain hop, a WS+TLS hop, and a plain-WS
    /// (no TLS) hop -- proves WS transport composes correctly mid-chain,
    /// not just as a single terminal hop.
    func testThreeHopChainMixingPlainAndWebSocketHops() async throws {
        try skipIfUnavailable()
        _ = XrayTestEnvironment.shared
        let (tcp, _) = try await EchoTargets.shared.value

        let hops = [
            ProxyHop(host: XrayTestEnvironment.host, port: XrayTestEnvironment.Ports.socks5, protocolConfig: .socks5(auth: .none)),
            ProxyHop(
                host: XrayTestEnvironment.host, port: XrayTestEnvironment.Ports.trojanWS,
                protocolConfig: .trojan(password: XrayTestEnvironment.trojanPassword, sni: "localhost", allowInsecure: true, wsPath: XrayTestEnvironment.trojanWSPath, wsHost: "localhost")
            ),
            ProxyHop(
                host: XrayTestEnvironment.host, port: XrayTestEnvironment.Ports.vmessWSTLS,
                protocolConfig: .vmess(uuid: XrayTestEnvironment.vmessUUID, tls: true, sni: "localhost", allowInsecure: true, wsPath: XrayTestEnvironment.vmessWSPath, wsHost: "localhost")
            ),
        ]
        let payload = Array("hello-3-hop-mixed-ws-chain".utf8)
        let transport = try await ProxyChain.open(hops: hops, finalTargetHost: XrayTestEnvironment.host, finalTargetPort: tcp.port)
        defer { transport.close() }
        try await transport.send(payload, timeout: 10)
        let echoed = try await transport.readExactly(payload.count, timeout: 10)
        XCTAssertEqual(echoed, payload)
    }
}
