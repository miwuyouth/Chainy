// ChainExhaustiveTCPTests.swift
//
// Part B of the plan: every ordered sequence of the 6 canonical protocols
// (`CanonicalProtocol`, see `XrayTestEnvironment.swift`) at every chain
// length 1-5 (6+36+216+1296+7776 = 9,330 total), each dialed via
// `ProxyChain.open` against the one shared real xray-core process and
// echoed off the local TCP target -- proving the real chain-building logic
// relays correctly regardless of protocol order, length, or repeats (a
// chain can and does reuse the same protocol/port at multiple positions;
// see `XrayTestEnvironment`'s doc comment on why that's not a problem for a
// `freedom`-outbound server).
//
// Split into one test method per length so a failure at, say, length 4
// doesn't block seeing results for the other four lengths, and so the
// (bounded-concurrency) run time for each is independently visible.

import XCTest
import ChainCore
import ProxyKit

final class ChainExhaustiveTCPTests: XCTestCase {
    private func skipIfUnavailable() throws {
        try XCTSkipUnless(XrayTestEnvironment.isAvailable, "xray/openssl not found on this machine")
    }

    private func runChain(_ hops: [CanonicalProtocol], tcpEchoPort: UInt16) async {
        let label = hops.map(\.rawValue).joined(separator: "->")
        let proxyHops = hops.map { $0.hop() }
        let payload = Array("chain:\(label)".utf8)

        let transport: any ProxyTransport
        do {
            transport = try await ProxyChain.open(
                hops: proxyHops, finalTargetHost: XrayTestEnvironment.host, finalTargetPort: tcpEchoPort, connectTimeout: 10
            )
        } catch {
            XCTFail("chain [\(label)] failed to open: \(error)")
            return
        }
        defer { transport.close() }

        do {
            try await transport.send(payload, timeout: 10)
            let echoed = try await transport.readExactly(payload.count, timeout: 10)
            XCTAssertEqual(echoed, payload, "chain [\(label)] echo mismatch")
        } catch {
            XCTFail("chain [\(label)] failed to relay: \(error)")
        }
    }

    /// Runs every combination at `length`, bounded to `maxConcurrency`
    /// in-flight chains at once (all sharing the one real xray-core process
    /// and one loopback TCP echo target) -- exhaustive coverage without
    /// paying for it serially.
    private func runExhaustive(length: Int, maxConcurrency: Int = 48) async throws {
        try skipIfUnavailable()
        _ = XrayTestEnvironment.shared
        let (tcp, _) = try await EchoTargets.shared.value
        let port = tcp.port

        var iterator = CanonicalProtocol.combinations(length: length).makeIterator()
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<maxConcurrency {
                guard let combo = iterator.next() else { break }
                group.addTask { await self.runChain(combo, tcpEchoPort: port) }
            }
            while await group.next() != nil {
                if let combo = iterator.next() {
                    group.addTask { await self.runChain(combo, tcpEchoPort: port) }
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
