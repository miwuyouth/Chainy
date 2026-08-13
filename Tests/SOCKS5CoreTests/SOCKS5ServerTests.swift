import XCTest
import ProxyKit
@testable import SOCKS5Core

/// Fast, in-memory coverage for `SOCKS5Server.acceptConnect` -- the server
/// (accept) role's counterpart to `SOCKS5CoreTests`' own client-side fake
/// transport tests.
final class SOCKS5ServerTests: XCTestCase {
    private final class FakeSOCKS5Transport: ByteStreamSource, ByteStreamSink {
        private(set) var sent: [[UInt8]] = []
        private var readBuffer: [UInt8]

        init(clientBytes: [UInt8]) { self.readBuffer = clientBytes }

        func send(_ bytes: [UInt8], timeout: TimeInterval?) async throws { sent.append(bytes) }

        func readExactly(_ n: Int, timeout: TimeInterval?) async throws -> [UInt8] {
            guard readBuffer.count >= n else { throw ProxyError.connectionClosed }
            let result = Array(readBuffer.prefix(n))
            readBuffer.removeFirst(n)
            return result
        }
    }

    private let successReply: [UInt8] = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]

    func testAcceptConnectDecodesIPv4Target() async throws {
        let clientBytes: [UInt8] = [0x05, 0x01, 0x00] + [0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x01, 0xBB]
        let transport = FakeSOCKS5Transport(clientBytes: clientBytes)
        let request = try await SOCKS5Server.acceptConnect(over: transport)
        XCTAssertEqual(request, SOCKS5IncomingRequest(host: "93.184.216.34", port: 443))
        XCTAssertEqual(transport.sent, [[0x05, 0x00], successReply])
    }

    func testAcceptConnectDecodesIPv6Target() async throws {
        let addr6 = (0..<16).map { UInt8($0) }
        let clientBytes: [UInt8] = [0x05, 0x01, 0x00] + [0x05, 0x01, 0x00, 0x04] + addr6 + [0x00, 0x50]
        let transport = FakeSOCKS5Transport(clientBytes: clientBytes)
        let request = try await SOCKS5Server.acceptConnect(over: transport)
        XCTAssertEqual(request, SOCKS5IncomingRequest(host: "1:203:405:607:809:a0b:c0d:e0f", port: 80))
    }

    func testAcceptConnectDecodesDomainTarget() async throws {
        let domainBytes = Array("example.com".utf8)
        let clientBytes: [UInt8] = [0x05, 0x01, 0x00] + [0x05, 0x01, 0x00, 0x03, UInt8(domainBytes.count)] + domainBytes + [0x00, 0x50]
        let transport = FakeSOCKS5Transport(clientBytes: clientBytes)
        let request = try await SOCKS5Server.acceptConnect(over: transport)
        XCTAssertEqual(request, SOCKS5IncomingRequest(host: "example.com", port: 80))
    }

    func testAcceptConnectRejectsWrongClientVersion() async throws {
        let transport = FakeSOCKS5Transport(clientBytes: [0x04, 0x01, 0x00])
        do {
            _ = try await SOCKS5Server.acceptConnect(over: transport)
            XCTFail("expected error")
        } catch SOCKS5ServerError.unsupportedVersion(let v) {
            XCTAssertEqual(v, 0x04)
        }
        XCTAssertTrue(transport.sent.isEmpty, "must fail before replying to a bogus version")
    }

    func testAcceptConnectRepliesNoAcceptableWhenClientNeverOffersNoAuth() async throws {
        let transport = FakeSOCKS5Transport(clientBytes: [0x05, 0x01, 0x02]) // offers only username/password
        do {
            _ = try await SOCKS5Server.acceptConnect(over: transport)
            XCTFail("expected error")
        } catch SOCKS5ServerError.noAcceptableMethodOffered {
            // expected
        }
        XCTAssertEqual(transport.sent, [[0x05, 0xFF]])
    }

    func testAcceptConnectRepliesCommandNotSupportedForNonConnect() async throws {
        // 0x02 = BIND, unsupported -- no address/port bytes needed since
        // acceptConnect must reject right after reading the request head.
        let clientBytes: [UInt8] = [0x05, 0x01, 0x00] + [0x05, 0x02, 0x00, 0x01]
        let transport = FakeSOCKS5Transport(clientBytes: clientBytes)
        do {
            _ = try await SOCKS5Server.acceptConnect(over: transport)
            XCTFail("expected error")
        } catch SOCKS5ServerError.unsupportedCommand(let cmd) {
            XCTAssertEqual(cmd, 0x02)
        }
        XCTAssertEqual(transport.sent.last, [0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
    }
}
