// ChainExhaustiveUDPTests.swift
//
// Part C of the plan: UDP dispatch across the same 9,330-combination matrix
// as `ChainExhaustiveTCPTests`. Unlike TCP, UDP is not uniform across every
// chain shape (`ProxyChain.openUDPRelay`, see `ChainCore/TunneledUDPRelay.swift`):
//
//   - every hop Shadowsocks               -> ShadowsocksUDPRelay (real relay)
//   - last hop VMess/VLESS/Trojan         -> Tunneled/TrojanUDPRelay (real relay,
//                                             any protocol mix before it)
//   - last hop SOCKS5                     -> SOCKS5UDPRelay when its prefix can
//                                             itself carry UDP (single-hop included)
//   - anything else                       -> refused (ProxyChainError.udpUnsupportedLastHop)
//
// So each combination either gets a real end-to-end UDP relay against the
// local UDP echo target, or an assertion that it's refused for the right
// reason -- both are "the real dispatch behavior for this exact shape",
// exhaustively.
//
import XCTest
import ChainCore
import ProxyKit

final class ChainExhaustiveUDPTests: XCTestCase {
    private func skipIfUnavailable() throws {
        try XCTSkipUnless(XrayTestEnvironment.isAvailable, "xray/openssl not found on this machine")
    }

    private func expectsRealRelay(_ hops: [CanonicalProtocol]) -> Bool {
        if hops.allSatisfy({ $0 == .shadowsocks }) { return true }
        switch hops.last! {
        case .vmess, .vless, .trojan: return true
        case .socks5: return hops.count == 1 || expectsRealRelay(Array(hops.dropLast()))
        case .http, .shadowsocks: return false
        }
    }

    private func refusedProtocolName(_ hops: [CanonicalProtocol]) -> String {
        if hops.last == .socks5, hops.count > 1 { return refusedProtocolName(Array(hops.dropLast())) }
        return hops.last!.chainCoreLogName
    }

    /// One real-relay attempt: opens a fresh relay, sends one payload,
    /// reads back the echo, and closes it -- throws on any failure.
    private func attemptRealRelay(_ hops: [CanonicalProtocol], label: String, udpEchoPort: UInt16) async throws {
        let proxyHops = hops.map { $0.hop() }
        let relay = try await ProxyChain.openUDPRelay(hops: proxyHops, connectTimeout: 20)
        defer { relay.close() }

        let payload = Array("udp-chain:\(label)".utf8)
        try await relay.send(targetHost: XrayTestEnvironment.host, targetPort: udpEchoPort, payload: payload, timeout: 20)
        let (_, _, echoed) = try await relay.receive(timeout: 20)
        guard echoed == payload else {
            XCTFail("chain [\(label)] UDP echo mismatch")
            return
        }
    }

    private func runCombo(_ hops: [CanonicalProtocol], udpEchoPort: UInt16) async {
        let label = hops.map(\.rawValue).joined(separator: "->")
        let proxyHops = hops.map { $0.hop() }

        if expectsRealRelay(hops) {
            // A shared local test target juggling thousands of concurrent
            // UDP sessions occasionally sees a transient timeout that isn't
            // reproducible in isolation (confirmed: retrying the exact same
            // chain alone always succeeds) -- one retry absorbs that without
            // hiding a real, deterministic protocol bug, which fails the
            // same way on retry too.
            do {
                try await attemptRealRelay(hops, label: label, udpEchoPort: udpEchoPort)
            } catch {
                do {
                    try await attemptRealRelay(hops, label: label, udpEchoPort: udpEchoPort)
                } catch {
                    XCTFail("chain [\(label)] expected a real UDP relay but failed twice (last error): \(error)")
                }
            }
        } else {
            do {
                _ = try await ProxyChain.openUDPRelay(hops: proxyHops, connectTimeout: 10)
                XCTFail("chain [\(label)] expected UDP to be refused (last hop \(hops.last!.rawValue)) but openUDPRelay succeeded")
            } catch ProxyChainError.udpUnsupportedLastHop(let protocolName) {
                XCTAssertEqual(protocolName, refusedProtocolName(hops), "chain [\(label)] refused for the wrong unsupported prefix hop")
            } catch {
                XCTFail("chain [\(label)] expected udpUnsupportedLastHop but got: \(error)")
            }
        }
    }

    private func runExhaustive(length: Int, maxConcurrency: Int = 4) async throws {
        try skipIfUnavailable()
        _ = XrayTestEnvironment.shared
        let (_, udp) = try await EchoTargets.shared.value
        let port = udp.port

        var iterator = CanonicalProtocol.combinations(length: length).makeIterator()
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<maxConcurrency {
                guard let combo = iterator.next() else { break }
                group.addTask { await self.runCombo(combo, udpEchoPort: port) }
            }
            while await group.next() != nil {
                if let combo = iterator.next() {
                    group.addTask { await self.runCombo(combo, udpEchoPort: port) }
                }
            }
        }
    }

    func testAllLength1Chains() async throws { try await runExhaustive(length: 1) }
    func testAllLength2Chains() async throws { try await runExhaustive(length: 2) }
    func testAllLength3Chains() async throws { try await runExhaustive(length: 3) }
    func testAllLength4Chains() async throws { try await runExhaustive(length: 4) }
    func testAllLength5Chains() async throws { try await runExhaustive(length: 5) }
}
