// TunneledUDPRelayMultiTargetTests.swift
//
// Covers the one axis that every other UDP interop test misses:
// `TunneledUDPRelay` (VMess / VLESS last hop) maintains a per-target
// session table (`tunnels: [TargetKey: Tunnel]`). All existing tests
// send to the same target for the whole lifetime of a relay, so the
// table never grows beyond one entry and only the "new tunnel" branch
// of `send` is exercised -- the "second destination triggers a second
// tunnel" and "two pumpReplies tasks running concurrently" paths are
// entirely untouched.
//
// The tests here fix that:
//
//   testVMessRelayDeliversToTwoDistinctTargetsOnTheSameRelay
//     Opens one VMess relay, sends a unique payload to target-A,
//     then a different payload to target-B (a separately spun-up echo
//     server), then collects both replies and asserts each arrived from
//     the right port with the right content. This forces the session
//     table to grow to 2 entries and two independent pumpReplies tasks
//     to run in parallel.
//
//   testVLESSRelayDeliversToTwoDistinctTargetsOnTheSameRelay
//     Same scenario via VLESS (length-prefixed framing instead of VMess
//     body-chunk framing), since the two last-hop protocols follow
//     different code paths in sendDatagram / pumpReplies.
//
//   testShadowsocksThenVMessRelayDeliversToTwoDistinctTargets
//     Same scenario through a two-hop prefix chain (SS -> VMess),
//     verifying the table logic is correct regardless of prefix length.
//
//   testVMessRelayReusesBothSessionsAfterInitialDial
//     After both tunnels are open, sends a second round to each target,
//     exercising the "if let existing { return }" fast-path in send
//     with two distinct keys simultaneously in the table.

import XCTest
import ChainCore
import ProxyKit

final class TunneledUDPRelayMultiTargetTests: XCTestCase {

    // MARK: - Helpers

    private func requireEnvironment() async throws -> LoopbackUDPEchoServer {
        try XCTSkipUnless(XrayTestEnvironment.isAvailable, "xray/openssl not found")
        _ = XrayTestEnvironment.shared
        return try await EchoTargets.shared.value.udp
    }

    /// Spins up a second ephemeral UDP echo server for the duration of one
    /// test. Having a real second listener on a distinct port is the simplest
    /// way to give the relay two genuinely independent targets: xray's
    /// freedom outbound dials whatever address the last hop names, so both
    /// ports are reachable through the same chain without any config changes.
    private func makeExtraEchoServer() async throws -> LoopbackUDPEchoServer {
        let server = try LoopbackUDPEchoServer()
        try await server.start()
        return server
    }

    /// Collects two replies from the relay's shared incoming stream and
    /// returns them keyed by fromPort. Replies from either target can
    /// arrive in either order because two pumpReplies tasks feed the same
    /// AsyncStream concurrently.
    private func collectTwoReplies(
        from relay: any UDPRelay,
        timeout: TimeInterval
    ) async throws -> [UInt16: [UInt8]] {
        var result: [UInt16: [UInt8]] = [:]
        for _ in 0..<2 {
            let r = try await relay.receive(timeout: timeout)
            result[r.fromPort] = r.payload
        }
        return result
    }

    // MARK: - VMess

    func testVMessRelayDeliversToTwoDistinctTargetsOnTheSameRelay() async throws {
        let echoA = try await requireEnvironment()
        let echoB = try await makeExtraEchoServer()
        defer { echoB.stop() }

        let relay = try await ProxyChain.openUDPRelay(
            hops: [CanonicalProtocol.vmess.hop()],
            connectTimeout: 20,
            logID: "multi-target-vmess"
        )
        defer { relay.close() }

        let host = XrayTestEnvironment.host
        let payloadA = Array("vmess-multi-target:A".utf8)
        let payloadB = Array("vmess-multi-target:B".utf8)

        // First send creates tunnels[keyA] and starts pumpReplies for A.
        try await relay.send(targetHost: host, targetPort: echoA.port, payload: payloadA, timeout: 20)
        // Second send creates tunnels[keyB] and starts pumpReplies for B.
        // At this point two independent pumpReplies tasks are running concurrently.
        try await relay.send(targetHost: host, targetPort: echoB.port, payload: payloadB, timeout: 20)

        let replies = try await collectTwoReplies(from: relay, timeout: 20)

        XCTAssertNotNil(replies[echoA.port], "no reply from target A (port \(echoA.port))")
        XCTAssertNotNil(replies[echoB.port], "no reply from target B (port \(echoB.port))")
        XCTAssertEqual(replies[echoA.port], payloadA, "VMess multi-target: payload A corrupted")
        XCTAssertEqual(replies[echoB.port], payloadB, "VMess multi-target: payload B corrupted")
    }

    // MARK: - VLESS

    func testVLESSRelayDeliversToTwoDistinctTargetsOnTheSameRelay() async throws {
        let echoA = try await requireEnvironment()
        let echoB = try await makeExtraEchoServer()
        defer { echoB.stop() }

        // VLESS uses length-prefixed datagram framing (LengthPrefixedDatagram)
        // instead of VMess body-chunk framing, so sendDatagram and pumpReplies
        // follow different code paths -- worth a separate test case.
        let relay = try await ProxyChain.openUDPRelay(
            hops: [CanonicalProtocol.vless.hop()],
            connectTimeout: 20,
            logID: "multi-target-vless"
        )
        defer { relay.close() }

        let host = XrayTestEnvironment.host
        let payloadA = Array("vless-multi-target:A".utf8)
        let payloadB = Array("vless-multi-target:B".utf8)

        try await relay.send(targetHost: host, targetPort: echoA.port, payload: payloadA, timeout: 20)
        try await relay.send(targetHost: host, targetPort: echoB.port, payload: payloadB, timeout: 20)

        let replies = try await collectTwoReplies(from: relay, timeout: 20)

        XCTAssertNotNil(replies[echoA.port], "no reply from target A (port \(echoA.port))")
        XCTAssertNotNil(replies[echoB.port], "no reply from target B (port \(echoB.port))")
        XCTAssertEqual(replies[echoA.port], payloadA, "VLESS multi-target: payload A corrupted")
        XCTAssertEqual(replies[echoB.port], payloadB, "VLESS multi-target: payload B corrupted")
    }

    // MARK: - Multi-hop prefix

    /// Verifies the session table still works correctly when the relay is
    /// built through a two-hop prefix (Shadowsocks -> VMess), not just a
    /// single direct hop. The earlier hops are TCP tunnels; the table
    /// logic itself is identical, but this catches any dial-path regression
    /// introduced by the prefix chain wrapping.
    func testShadowsocksThenVMessRelayDeliversToTwoDistinctTargets() async throws {
        let echoA = try await requireEnvironment()
        let echoB = try await makeExtraEchoServer()
        defer { echoB.stop() }

        let relay = try await ProxyChain.openUDPRelay(
            hops: [CanonicalProtocol.shadowsocks.hop(), CanonicalProtocol.vmess.hop()],
            connectTimeout: 20,
            logID: "multi-target-ss-vmess"
        )
        defer { relay.close() }

        let host = XrayTestEnvironment.host
        let payloadA = Array("ss-vmess-multi-target:A".utf8)
        let payloadB = Array("ss-vmess-multi-target:B".utf8)

        try await relay.send(targetHost: host, targetPort: echoA.port, payload: payloadA, timeout: 20)
        try await relay.send(targetHost: host, targetPort: echoB.port, payload: payloadB, timeout: 20)

        let replies = try await collectTwoReplies(from: relay, timeout: 20)

        XCTAssertNotNil(replies[echoA.port], "no reply from target A (port \(echoA.port))")
        XCTAssertNotNil(replies[echoB.port], "no reply from target B (port \(echoB.port))")
        XCTAssertEqual(replies[echoA.port], payloadA, "SS->VMess multi-target: payload A corrupted")
        XCTAssertEqual(replies[echoB.port], payloadB, "SS->VMess multi-target: payload B corrupted")
    }

    // MARK: - Session reuse with two entries in the table

    /// After both tunnels are open (table has 2 entries), sends a second
    /// payload to each target. Both sends hit the "if let existing { return }"
    /// fast-path in TunneledUDPRelay.send with two distinct keys in the table.
    /// This is the only test that exercises that fast-path beyond the trivial
    /// single-entry case.
    func testVMessRelayReusesBothSessionsAfterInitialDial() async throws {
        let echoA = try await requireEnvironment()
        let echoB = try await makeExtraEchoServer()
        defer { echoB.stop() }

        let relay = try await ProxyChain.openUDPRelay(
            hops: [CanonicalProtocol.vmess.hop()],
            connectTimeout: 20,
            logID: "multi-target-reuse-vmess"
        )
        defer { relay.close() }

        let host = XrayTestEnvironment.host

        // Round 1: open both tunnels.
        try await relay.send(targetHost: host, targetPort: echoA.port, payload: Array("r1-A".utf8), timeout: 20)
        try await relay.send(targetHost: host, targetPort: echoB.port, payload: Array("r1-B".utf8), timeout: 20)
        _ = try await collectTwoReplies(from: relay, timeout: 20)

        // Round 2: both sends now hit the existing-session fast-path.
        let p2A = Array("r2-A".utf8)
        let p2B = Array("r2-B".utf8)
        try await relay.send(targetHost: host, targetPort: echoA.port, payload: p2A, timeout: 20)
        try await relay.send(targetHost: host, targetPort: echoB.port, payload: p2B, timeout: 20)

        let replies = try await collectTwoReplies(from: relay, timeout: 20)

        XCTAssertEqual(replies[echoA.port], p2A, "reuse A: payload mismatch")
        XCTAssertEqual(replies[echoB.port], p2B, "reuse B: payload mismatch")
    }
}
