import XCTest
import ChainCore

final class UDPStressInteropTests: XCTestCase {
    private static func hops(for id: Int) -> [CanonicalProtocol] {
        let depth = (id % 4) + 1
        // Shadowsocks is the native datagram chain: every hop handles each
        // UDP packet, so this stresses 1-4 layers of real encryption/relay.
        // TCP-tunnel UDP protocol combinations are exhaustively checked by
        // ChainExhaustiveUDPTests, one datagram per independently-open relay.
        return [CanonicalProtocol](repeating: .shadowsocks, count: depth)
    }

    private static func payload(relayID: Int, sequence: Int, size: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: size)
        if size >= 8 {
            bytes[0] = UInt8(relayID >> 8)
            bytes[1] = UInt8(truncatingIfNeeded: relayID)
            bytes[2] = UInt8(sequence >> 8)
            bytes[3] = UInt8(truncatingIfNeeded: sequence)
        }
        for index in 4..<size {
            bytes[index] = UInt8(truncatingIfNeeded: relayID &* 31 + sequence &* 17 + index)
        }
        return bytes
    }

    private static func runRelay(id: Int, targetPort: UInt16) async -> String? {
        let protocols = hops(for: id)
        let label = protocols.map(\.rawValue).joined(separator: "->")
        do {
            let relay = try await ProxyChain.openUDPRelay(hops: protocols.map { $0.hop() }, connectTimeout: 20)
            defer { relay.close() }
            let sizes = [8, 15, 16, 17, 63, 255, 256, 511, 1_024, 1_400]
            for sequence in 0..<sizes.count {
                let sent = payload(relayID: id, sequence: sequence, size: sizes[sequence])
                try await relay.send(
                    targetHost: XrayTestEnvironment.host, targetPort: targetPort,
                    payload: sent, timeout: 20
                )
                let (_, replyPort, received) = try await relay.receive(timeout: 20)
                guard replyPort == targetPort, received == sent else {
                    return "relay \(id) [\(label)] datagram \(sequence) mismatch"
                }
            }
            return nil
        } catch {
            return "relay \(id) [\(label)] failed: \(error)"
        }
    }

    func testSixtyRelaysTransferSixHundredDatagramsWithoutLossOrCrossTalk() async throws {
        try XCTSkipUnless(XrayTestEnvironment.isAvailable, "xray/openssl not found")
        _ = XrayTestEnvironment.shared
        let targetPort = try await EchoTargets.shared.value.udp.port

        let failures = await withTaskGroup(of: (Int, String?).self, returning: [String].self) { group in
            var nextID = 0
            for id in 0..<4 {
                group.addTask { (id, await Self.runRelay(id: id, targetPort: targetPort)) }
                nextID += 1
            }
            var failures: [String] = []
            while let (_, result) = await group.next() {
                if let result { failures.append(result) }
                if nextID < 60 {
                    let id = nextID
                    group.addTask { (id, await Self.runRelay(id: id, targetPort: targetPort)) }
                    nextID += 1
                }
            }
            return failures
        }
        XCTAssertTrue(failures.isEmpty, "\(failures.count)/60 UDP relays failed:\n\(failures.joined(separator: "\n"))")
    }
}
