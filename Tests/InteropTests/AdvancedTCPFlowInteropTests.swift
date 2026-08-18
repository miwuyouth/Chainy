import XCTest
import ChainCore
import ProxyKit

private actor FlowResultRecorder {
    private var results: [Result<Void, Error>] = []
    func record(_ result: Result<Void, Error>) { results.append(result) }
    func first() -> Result<Void, Error>? { results.first }
}

private final class ControlledTCPFlowTarget {
    enum Mode { case fullDuplex, slowBackpressure }

    private let listener: TCPListener
    private let expectedUpload: [UInt8]
    private let download: [UInt8]
    private let mode: Mode
    let recorder = FlowResultRecorder()

    init(expectedUpload: [UInt8], download: [UInt8], mode: Mode) throws {
        self.expectedUpload = expectedUpload
        self.download = download
        self.mode = mode
        listener = try TCPListener(port: 0)
    }

    var port: UInt16 { listener.port! }

    func start() async throws {
        try await listener.start(onAccept: { [expectedUpload, download, mode, recorder] conn in
            Task {
                do {
                    try await conn.connect(timeout: 10)
                    switch mode {
                    case .fullDuplex:
                        async let received = Self.readSlowly(conn, count: expectedUpload.count, chunkSize: 2_003, delay: 100_000)
                        try await Self.writeSlowly(conn, bytes: download, chunkSize: 3_001, delay: 100_000)
                        let upload = try await received
                        guard upload == expectedUpload else { throw FlowError.uploadMismatch }
                    case .slowBackpressure:
                        let upload = try await Self.readSlowly(conn, count: expectedUpload.count, chunkSize: 1_024, delay: 1_000_000)
                        guard upload == expectedUpload else { throw FlowError.uploadMismatch }
                        try await Self.writeSlowly(conn, bytes: download, chunkSize: 777, delay: 1_000_000)
                    }
                    await recorder.record(.success(()))
                } catch {
                    await recorder.record(.failure(error))
                }
                conn.close()
            }
        }, onFailure: { _ in })
    }

    func stop() { listener.cancel() }

    private enum FlowError: Error { case uploadMismatch }

    private static func readSlowly(_ conn: TCPConn, count: Int, chunkSize: Int, delay: UInt64) async throws -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(count)
        while result.count < count {
            let amount = min(chunkSize, count - result.count)
            result += try await conn.readExactly(amount, timeout: 30)
            if delay > 0 { try await Task.sleep(nanoseconds: delay) }
        }
        return result
    }

    private static func writeSlowly(_ conn: TCPConn, bytes: [UInt8], chunkSize: Int, delay: UInt64) async throws {
        var offset = 0
        while offset < bytes.count {
            let end = min(offset + chunkSize, bytes.count)
            try await conn.send(Array(bytes[offset..<end]), timeout: 30)
            offset = end
            if delay > 0 { try await Task.sleep(nanoseconds: delay) }
        }
    }
}

final class AdvancedTCPFlowInteropTests: XCTestCase {
    private func bytes(count: Int, salt: UInt64) -> [UInt8] {
        (0..<count).map { index in
            UInt8(truncatingIfNeeded: UInt64(index) &* 0x9E3779B97F4A7C15 &+ salt)
        }
    }

    private func fourHopChain() -> [ProxyHop] {
        [CanonicalProtocol.vmess, .shadowsocks, .vless, .trojan].map { $0.hop() }
    }

    private func awaitServer(_ recorder: FlowResultRecorder) async throws {
        for _ in 0..<500 {
            if let result = await recorder.first() {
                try result.get()
                return
            }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("controlled target did not finish in 5 seconds")
    }

    func testSimultaneousUploadAndDownloadThroughFourRealXrayHops() async throws {
        try XCTSkipUnless(XrayTestEnvironment.isAvailable, "xray/openssl not found")
        _ = XrayTestEnvironment.shared
        let upload = bytes(count: 2 * 1_048_576, salt: 0xA11CE)
        let download = bytes(count: 2 * 1_048_576, salt: 0xD0A1)
        let target = try ControlledTCPFlowTarget(expectedUpload: upload, download: download, mode: .fullDuplex)
        try await target.start()
        defer { target.stop() }

        let transport = try await ProxyChain.open(
            hops: fourHopChain(), finalTargetHost: XrayTestEnvironment.host,
            finalTargetPort: target.port, connectTimeout: 20
        )
        defer { transport.close() }

        async let sending: Void = transport.send(upload, timeout: 30)
        async let receiving: [UInt8] = transport.readExactly(download.count, timeout: 30)
        let (_, received) = try await (sending, receiving)
        XCTAssertEqual(received, download)
        try await awaitServer(target.recorder)
    }

    func testSlowReaderAndTinyResponseChunksApplyBackpressureWithoutCorruption() async throws {
        try XCTSkipUnless(XrayTestEnvironment.isAvailable, "xray/openssl not found")
        _ = XrayTestEnvironment.shared
        let upload = bytes(count: 512 * 1_024, salt: 0xBACC)
        let download = bytes(count: 384 * 1_024, salt: 0x510A)
        let target = try ControlledTCPFlowTarget(expectedUpload: upload, download: download, mode: .slowBackpressure)
        try await target.start()
        defer { target.stop() }

        let transport = try await ProxyChain.open(
            hops: fourHopChain(), finalTargetHost: XrayTestEnvironment.host,
            finalTargetPort: target.port, connectTimeout: 20
        )
        defer { transport.close() }
        try await transport.send(upload, timeout: 30)
        let received = try await transport.readExactly(download.count, timeout: 30)
        XCTAssertEqual(received, download)
        try await awaitServer(target.recorder)
    }
}
