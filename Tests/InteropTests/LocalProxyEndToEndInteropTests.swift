import XCTest
import ProxyKit
@testable import Chainy

final class LocalProxyEndToEndInteropTests: XCTestCase {
    private enum ClientKind { case socks5, httpConnect }

    private static func runClient(id: Int, kind: ClientKind, proxyPort: UInt16, targetPort: UInt16) async -> String? {
        let conn = TCPConn(host: "127.0.0.1", port: proxyPort)
        var stage = "connect"
        do {
            try await conn.connect(timeout: 20)
            switch kind {
            case .httpConnect:
                stage = "HTTP CONNECT handshake"
                let request = "CONNECT 127.0.0.1:\(targetPort) HTTP/1.1\r\nHost: 127.0.0.1:\(targetPort)\r\n\r\n"
                try await conn.send(Array(request.utf8), timeout: 20)
                let reply = try await conn.readExactly(39, timeout: 20)
                guard String(decoding: reply, as: UTF8.self) == "HTTP/1.1 200 Connection Established\r\n\r\n" else {
                    throw ClientError.badHTTPReply
                }
            case .socks5:
                stage = "SOCKS5 greeting"
                try await conn.send([0x05, 0x01, 0x00], timeout: 20)
                guard try await conn.readExactly(2, timeout: 20) == [0x05, 0x00] else { throw ClientError.badSOCKSReply }
                let portBytes = [UInt8(targetPort >> 8), UInt8(targetPort & 0xff)]
                try await conn.send([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1] + portBytes, timeout: 20)
                let head = try await conn.readExactly(4, timeout: 20)
                guard head[0] == 0x05, head[1] == 0x00 else { throw ClientError.badSOCKSReply }
                switch head[3] {
                case 0x01: _ = try await conn.readExactly(6, timeout: 20)
                case 0x04: _ = try await conn.readExactly(18, timeout: 20)
                case 0x03:
                    let length = try await conn.readExactly(1, timeout: 20)[0]
                    _ = try await conn.readExactly(Int(length) + 2, timeout: 20)
                default: throw ClientError.badSOCKSReply
                }
            }

            let payload = Array("local-proxy-client-\(id)-\(kind)".utf8)
            stage = "echo payload"
            try await conn.send(payload, timeout: 20)
            let echoed = try await conn.readExactly(payload.count, timeout: 20)
            conn.close()
            return echoed == payload ? nil : "client \(id) \(kind): echo mismatch"
        } catch {
            conn.close()
            return "client \(id) \(kind) at \(stage): \(error)"
        }
    }

    private enum ClientError: Error { case badHTTPReply, badSOCKSReply }

    func testMixedSOCKS5AndHTTPClientsTraverseProductionLocalProxyAndRealXrayChain() async throws {
        try XCTSkipUnless(XrayTestEnvironment.isAvailable, "xray/openssl not found")
        _ = XrayTestEnvironment.shared
        let targetPort = try await EchoTargets.shared.value.tcp.port
        let server = await MainActor.run { LocalProxyServer() }
        // Multi-hop traffic is stressed directly in the other interop tests;
        // this case isolates the production mixed local listener and pump.
        let hops = [CanonicalProtocol.vmess].map { $0.hop() }
        let proxyPort = try await server.start(
            port: 0, hops: hops, chainName: "interop-4-hop", onUnexpectedStop: { _ in }
        )

        let failures = await withTaskGroup(of: (Int, String?).self, returning: [String].self) { group in
            // A mixed burst exercises the production first-byte protocol
            // sniffing and both client-facing handshakes on the same port.
            var nextID = 0
            for id in 0..<20 {
                let kind: ClientKind = id.isMultiple(of: 2) ? .socks5 : .httpConnect
                group.addTask { (id, await Self.runClient(id: id, kind: kind, proxyPort: proxyPort, targetPort: targetPort)) }
                nextID += 1
            }
            var failures: [String] = []
            while let (_, result) = await group.next() {
                if let result { failures.append(result) }
                if nextID < 100 {
                    let id = nextID
                    let kind: ClientKind = id.isMultiple(of: 2) ? .socks5 : .httpConnect
                    group.addTask { (id, await Self.runClient(id: id, kind: kind, proxyPort: proxyPort, targetPort: targetPort)) }
                    nextID += 1
                }
            }
            return failures
        }

        let counts = await server.snapshotByteCounts()
        let outcomes = await server.snapshotConnectionOutcomeCounts()
        await server.stop()
        XCTAssertTrue(failures.isEmpty, "\(failures.count)/100 local proxy clients failed:\n\(failures.prefix(20).joined(separator: "\n"))")
        XCTAssertEqual(outcomes.total, 100)
        XCTAssertEqual(outcomes.timedOut, 0)
        XCTAssertGreaterThan(counts.upload, 0)
        XCTAssertEqual(counts.upload, counts.download)
    }
}
