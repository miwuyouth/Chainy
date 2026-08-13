import XCTest
import ProxyKit
@testable import ChainCore

/// Coverage for `ProxyChain.openUDPRelay`'s dispatch: an all-Shadowsocks
/// chain gets `ShadowsocksUDPRelay` (its own physical UDP socket, chained by
/// nested packets), a chain whose *last* hop is VMess/VLESS gets
/// `TunneledUDPRelay` (UDP-over-the-existing-TCP-tunnel, dialed lazily per
/// target), and anything else is refused up front. None of this needs a
/// reachable server: `ShadowsocksUDPRelay.open` only opens a UDP socket (no
/// handshake, so "connecting" to an unused local port still succeeds), and
/// `TunneledUDPRelay.open` doesn't dial anything at all until the first
/// `send` for a given target -- see each type's own doc comment.
///
/// A last-hop-Trojan chain also dispatches (to `TrojanUDPRelay`), but isn't
/// covered *here*: unlike the two mechanisms above, `TrojanUDPRelay.open`
/// dials and completes a real TLS handshake eagerly (one session handles
/// every destination, so there's no per-target laziness to exploit the way
/// `TunneledUDPRelay` has) -- see `ChainCoreTrojanUDPRelayLiveSocketTests`
/// (`Tests/TrojanCoreTests`) for that dispatch, verified against a real
/// self-signed TLS server instead.
final class ProxyChainUDPRelayDispatchTests: XCTestCase {
    func testAllShadowsocksChainDispatchesToShadowsocksUDPRelay() async throws {
        // A real (if silent) local UDP listener stands in for the hop's
        // server, so `ShadowsocksUDPRelay.open`'s own `UDPConn.connect`
        // has a genuinely bound port to "connect" to, rather than relying
        // on UDP's connectionless-dial behavior against a totally unused one.
        let listener = try UDPListener()
        try await listener.start(onAccept: { _ in }, onFailure: { _ in })
        defer { listener.cancel() }

        let hops = [
            ProxyHop(host: "127.0.0.1", port: listener.port!, protocolConfig: .shadowsocks(password: "pw", cipher: .aes256Gcm)),
            ProxyHop(host: "127.0.0.1", port: listener.port!, protocolConfig: .shadowsocks(password: "pw2", cipher: .aes128Gcm)),
        ]
        let relay = try await ProxyChain.openUDPRelay(hops: hops)
        defer { relay.close() }
        XCTAssertTrue(relay is ShadowsocksUDPRelay)
    }

    func testLastHopVMessChainDispatchesToTunneledUDPRelay() async throws {
        let hops = [
            ProxyHop(host: "socks.example", port: 1080, protocolConfig: .socks5(auth: .none)),
            ProxyHop(host: "vmess.example", port: 443, protocolConfig: .vmess(uuid: "11111111-1111-1111-1111-111111111111")),
        ]
        let relay = try await ProxyChain.openUDPRelay(hops: hops)
        defer { relay.close() }
        XCTAssertTrue(relay is TunneledUDPRelay)
    }

    func testLastHopVLESSChainDispatchesToTunneledUDPRelay() async throws {
        let hops = [ProxyHop(host: "vless.example", port: 443, protocolConfig: .vless(uuid: "11111111-1111-1111-1111-111111111111"))]
        let relay = try await ProxyChain.openUDPRelay(hops: hops)
        defer { relay.close() }
        XCTAssertTrue(relay is TunneledUDPRelay)
    }

    func testMixedChainEndingInShadowsocksIsRefusedNotSilentlyDowngraded() async throws {
        // Last hop is Shadowsocks, but hop 0 isn't -- doesn't qualify for
        // either mechanism (Shadowsocks UDP needs *every* hop to match;
        // TunneledUDPRelay only fires for a VMess/VLESS last hop).
        let hops = [
            ProxyHop(host: "socks.example", port: 1080, protocolConfig: .socks5(auth: .none)),
            ProxyHop(host: "ss.example", port: 8388, protocolConfig: .shadowsocks(password: "pw", cipher: .aes256Gcm)),
        ]
        do {
            _ = try await ProxyChain.openUDPRelay(hops: hops)
            XCTFail("expected udpUnsupportedLastHop")
        } catch ProxyChainError.udpUnsupportedLastHop(let protocolName) {
            XCTAssertEqual(protocolName, "Shadowsocks")
        }
    }

    func testLastHopHTTPIsRefused() async throws {
        let hops = [ProxyHop(host: "http-proxy.example", port: 8080, protocolConfig: .http())]
        do {
            _ = try await ProxyChain.openUDPRelay(hops: hops)
            XCTFail("expected udpUnsupportedLastHop")
        } catch ProxyChainError.udpUnsupportedLastHop(let protocolName) {
            XCTAssertEqual(protocolName, "HTTP")
        }
    }

    func testLastHopSOCKS5IsRefused() async throws {
        let hops = [ProxyHop(host: "socks.example", port: 1080, protocolConfig: .socks5(auth: .none))]
        do {
            _ = try await ProxyChain.openUDPRelay(hops: hops)
            XCTFail("expected udpUnsupportedLastHop")
        } catch ProxyChainError.udpUnsupportedLastHop(let protocolName) {
            XCTAssertEqual(protocolName, "SOCKS5")
        }
    }

    func testEmptyChainThrowsEmptyChain() async throws {
        do {
            _ = try await ProxyChain.openUDPRelay(hops: [])
            XCTFail("expected emptyChain")
        } catch ProxyChainError.emptyChain {
            // expected
        }
    }
}
