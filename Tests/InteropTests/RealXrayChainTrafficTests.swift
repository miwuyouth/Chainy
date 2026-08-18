// RealXrayChainTrafficTests.swift
//
// Traffic-oriented integration coverage through a real local xray-core.
// ChainExhaustiveTCPTests proves every protocol ordering opens; these tests
// exercise the other axis seen in production: framing boundaries, sustained
// traffic on one connection, connection churn, and hundreds of simultaneous
// connections. Random choices use a fixed seed so a failure is reproducible.

import XCTest
import ChainCore
import ProxyKit

final class RealXrayChainTrafficTests: XCTestCase {
    private struct SplitMix64 {
        var state: UInt64

        mutating func next() -> UInt64 {
            state &+= 0x9E3779B97F4A7C15
            var value = state
            value = (value ^ (value >> 30)) &* 0xBF58476D1CE4E5B9
            value = (value ^ (value >> 27)) &* 0x94D049BB133111EB
            return value ^ (value >> 31)
        }

        mutating func int(in range: Range<Int>) -> Int {
            range.lowerBound + Int(next() % UInt64(range.count))
        }
    }

    private struct Scenario: Sendable {
        let id: Int
        let protocols: [CanonicalProtocol]
        let payloadSize: Int

        var label: String {
            "#\(id) \(protocols.map(\.rawValue).joined(separator: "->")) bytes=\(payloadSize)"
        }
    }

    private func requireEnvironment() async throws -> UInt16 {
        try XCTSkipUnless(XrayTestEnvironment.isAvailable, "xray/openssl not found on this machine")
        _ = XrayTestEnvironment.shared
        return try await EchoTargets.shared.value.tcp.port
    }

    private static func payload(size: Int, seed: UInt64) -> [UInt8] {
        var random = SplitMix64(state: seed)
        return (0..<size).map { _ in UInt8(truncatingIfNeeded: random.next()) }
    }

    private static func scenarios(count: Int, sizes: [Int], seed: UInt64) -> [Scenario] {
        var random = SplitMix64(state: seed)
        let protocols = CanonicalProtocol.allCases
        return (0..<count).map { id in
            // Guarantee every batch covers all depths evenly; the protocols
            // at each position remain pseudo-random (and may repeat).
            let hopCount = (id % 4) + 1
            let hops = (0..<hopCount).map { _ in protocols[random.int(in: 0..<protocols.count)] }
            return Scenario(id: id, protocols: hops, payloadSize: sizes[random.int(in: 0..<sizes.count)])
        }
    }

    private static func roundTrip(_ scenario: Scenario, port: UInt16, timeout: TimeInterval = 20) async -> String? {
        let transport: any ProxyTransport
        do {
            transport = try await ProxyChain.open(
                hops: scenario.protocols.map { $0.hop() },
                finalTargetHost: XrayTestEnvironment.host,
                finalTargetPort: port,
                connectTimeout: timeout
            )
        } catch {
            return "\(scenario.label): open failed: \(error)"
        }
        defer { transport.close() }

        let sent = payload(size: scenario.payloadSize, seed: UInt64(scenario.id) ^ 0xC0FFEE)
        do {
            try await transport.send(sent, timeout: timeout)
            let received = try await transport.readExactly(sent.count, timeout: timeout)
            return received == sent ? nil : "\(scenario.label): data mismatch (received \(received.count) bytes)"
        } catch {
            return "\(scenario.label): transfer failed: \(error)"
        }
    }

    private func runConcurrently(_ scenarios: [Scenario], port: UInt16, limit: Int) async -> [String] {
        var iterator = scenarios.makeIterator()
        return await withTaskGroup(of: String?.self, returning: [String].self) { group in
            for _ in 0..<min(limit, scenarios.count) {
                guard let scenario = iterator.next() else { break }
                group.addTask { await Self.roundTrip(scenario, port: port) }
            }

            var failures: [String] = []
            while let result = await group.next() {
                if let result { failures.append(result) }
                if let scenario = iterator.next() {
                    group.addTask { await Self.roundTrip(scenario, port: port) }
                }
            }
            return failures
        }
    }

    func testPayloadBoundariesAndLongTransferOnOneConnection() async throws {
        let port = try await requireEnvironment()
        // Use the four-hop member for the heaviest stream/framing case.
        let scenario = Self.scenarios(count: 4, sizes: [1], seed: 0xB0A7D4)[3]
        let transport = try await ProxyChain.open(
            hops: scenario.protocols.map { $0.hop() },
            finalTargetHost: XrayTestEnvironment.host,
            finalTargetPort: port,
            connectTimeout: 20
        )
        defer { transport.close() }

        // Values immediately around common TLS/AEAD record boundaries catch
        // truncation, split-frame, and off-by-one bugs. Reusing one connection
        // also verifies stream state across many consecutive records.
        let sizes = [1, 2, 31, 255, 1_023, 16_383, 16_384, 16_385, 65_535, 262_144]
        var total = 0
        for (index, size) in sizes.enumerated() {
            let sent = Self.payload(size: size, seed: UInt64(index) ^ 0x51A7E)
            try await transport.send(sent, timeout: 20)
            let received = try await transport.readExactly(size, timeout: 20)
            XCTAssertEqual(received, sent, "payload boundary failed at \(size) bytes via \(scenario.label)")
            total += size
        }

        // Eight 1 MiB records make this a genuinely long transfer without
        // requiring a single giant allocation or depending on packet splits.
        for index in 0..<8 {
            let sent = Self.payload(size: 1_048_576, seed: UInt64(index) ^ 0x10A6DA7A)
            try await transport.send(sent, timeout: 30)
            let received = try await transport.readExactly(sent.count, timeout: 30)
            XCTAssertEqual(received, sent, "long-transfer chunk \(index) corrupted via \(scenario.label)")
            total += sent.count
        }
        XCTAssertGreaterThan(total, 8 * 1_048_576)
    }

    func testThreeHundredConcurrentRandomChainsWithMixedPayloads() async throws {
        let port = try await requireEnvironment()
        let scenarios = Self.scenarios(
            count: 300,
            sizes: [1, 7, 64, 511, 4_096, 16_383, 16_384, 16_385, 65_536],
            seed: 0x300C0A7
        )
        let failures = await runConcurrently(scenarios, port: port, limit: 64)
        XCTAssertTrue(failures.isEmpty, "\(failures.count)/300 real-xray connections failed:\n\(failures.prefix(20).joined(separator: "\n"))")
    }

    func testConcurrentLargeTransfersAcrossRandomChains() async throws {
        let port = try await requireEnvironment()
        let scenarios = Self.scenarios(count: 32, sizes: [524_288, 1_048_576], seed: 0x1A26E)
        let failures = await runConcurrently(scenarios, port: port, limit: 16)
        XCTAssertTrue(failures.isEmpty, "\(failures.count)/32 large real-xray transfers failed:\n\(failures.joined(separator: "\n"))")
    }

    func testRepeatedConnectionOpenTransferCloseChurn() async throws {
        let port = try await requireEnvironment()
        // Serial churn catches teardown/resource-reuse defects that can be
        // hidden by a single long-lived connection or a one-shot burst.
        let scenarios = Self.scenarios(count: 100, sizes: [3, 127, 4_097], seed: 0xC4A2A)
        for scenario in scenarios {
            if let failure = await Self.roundTrip(scenario, port: port) {
                XCTFail(failure)
                return
            }
        }
    }
}
