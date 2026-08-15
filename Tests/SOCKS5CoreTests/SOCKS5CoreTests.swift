import XCTest
import ProxyKit
@testable import SOCKS5Core

final class SOCKS5CoreTests: XCTestCase {

    // MARK: - In-memory duplex fake, driving the handshake without a real socket
    // (same idea as ShadowsocksCoreTests' FakeByteSource, but bidirectional
    // since the SOCKS5 handshake is a request/response conversation, not a
    // one-way decrypt).

    private final class FakeSOCKS5Transport: ByteStreamSource, ByteStreamSink {
        private(set) var sent: [[UInt8]] = []
        private var readBuffer: [UInt8]

        init(serverBytes: [UInt8]) { self.readBuffer = serverBytes }

        func send(_ bytes: [UInt8], timeout: TimeInterval?) async throws { sent.append(bytes) }

        func readExactly(_ n: Int, timeout: TimeInterval?) async throws -> [UInt8] {
            guard readBuffer.count >= n else { throw ProxyError.connectionClosed }
            let result = Array(readBuffer.prefix(n))
            readBuffer.removeFirst(n)
            return result
        }
    }

    // MARK: - Greeting / method selection

    func testGreetingOffersOnlyNoAuthWhenUnauthenticated() async throws {
        let transport = FakeSOCKS5Transport(serverBytes: [0x05, 0x00])
        try await sendGreetingAndSelectMethod(transport: transport, auth: .none, timeout: nil)
        XCTAssertEqual(transport.sent, [[0x05, 0x01, 0x00]])
    }

    func testGreetingOffersOnlyUsernamePasswordWhenCredentialsConfigured() async throws {
        let transport = FakeSOCKS5Transport(serverBytes: [0x05, 0x02])
        try await sendGreetingAndSelectMethod(transport: transport, auth: .usernamePassword(username: "u", password: "p"), timeout: nil)
        XCTAssertEqual(transport.sent, [[0x05, 0x01, 0x02]])
    }

    func testGreetingRejectsWrongServerVersion() async throws {
        let transport = FakeSOCKS5Transport(serverBytes: [0x04, 0x00])
        do {
            try await sendGreetingAndSelectMethod(transport: transport, auth: .none, timeout: nil)
            XCTFail("expected error")
        } catch SOCKS5Error.unsupportedServerVersion(let v) {
            XCTAssertEqual(v, 0x04)
        }
    }

    func testGreetingNoAcceptableMethodThrows() async throws {
        let transport = FakeSOCKS5Transport(serverBytes: [0x05, 0xFF])
        do {
            try await sendGreetingAndSelectMethod(transport: transport, auth: .none, timeout: nil)
            XCTFail("expected error")
        } catch SOCKS5Error.noAcceptableAuthMethod {
            // expected
        }
    }

    func testGreetingSelectingUnofferedMethodThrows() async throws {
        // We offer noAuth (0x00); a server claiming to have picked 0x02
        // (which we never offered) must be treated as a protocol violation,
        // not silently followed into a subnegotiation we didn't ask for.
        let transport = FakeSOCKS5Transport(serverBytes: [0x05, 0x02])
        do {
            try await sendGreetingAndSelectMethod(transport: transport, auth: .none, timeout: nil)
            XCTFail("expected error")
        } catch SOCKS5Error.unexpectedAuthMethod(let m) {
            XCTAssertEqual(m, 0x02)
        }
    }

    // MARK: - RFC 1929 username/password subnegotiation

    func testUsernamePasswordAuthSuccessSendsLengthPrefixedWireFormat() async throws {
        let transport = FakeSOCKS5Transport(serverBytes: [0x01, 0x00])
        try await performUsernamePasswordAuth(transport: transport, username: "alice", password: "hunter2", timeout: nil)
        XCTAssertEqual(transport.sent, [[0x01, 0x05] + Array("alice".utf8) + [0x07] + Array("hunter2".utf8)])
    }

    func testUsernamePasswordAuthFailureThrowsWithStatus() async throws {
        let transport = FakeSOCKS5Transport(serverBytes: [0x01, 0x01])
        do {
            try await performUsernamePasswordAuth(transport: transport, username: "alice", password: "wrong", timeout: nil)
            XCTFail("expected error")
        } catch SOCKS5Error.authenticationFailed(let status) {
            XCTAssertEqual(status, 0x01)
        }
    }

    func testUsernamePasswordAuthRejectsOverlongCredentialInsteadOfCrashing() async throws {
        // RFC 1929 length-prefixes username/password with a single byte each
        // (max 255 bytes) -- this used to be `UInt8(bytes.count)` territory,
        // which traps on overflow instead of throwing (see ProxyAddress's
        // own domainTooLong check for the same class of bug).
        let transport = FakeSOCKS5Transport(serverBytes: [])
        let tooLong = String(repeating: "a", count: 256)
        do {
            try await performUsernamePasswordAuth(transport: transport, username: tooLong, password: "p", timeout: nil)
            XCTFail("expected error")
        } catch SOCKS5Error.credentialTooLong {
            // expected
        }
        XCTAssertTrue(transport.sent.isEmpty, "must fail before sending anything")
    }

    // MARK: - CONNECT request / reply

    func testConnectRequestWireFormatForIPv4Target() async throws {
        let transport = FakeSOCKS5Transport(serverBytes: [0x05, 0x00, 0x00, 0x01] + [0, 0, 0, 0] + [0, 0])
        _ = try await sendConnectRequestAndAwaitReply(transport: transport, target: .ipv4([93, 184, 216, 34]), targetPort: 443, timeout: nil)
        XCTAssertEqual(transport.sent, [[0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x01, 0xBB]])
    }

    func testConnectRequestWireFormatForDomainTarget() async throws {
        let transport = FakeSOCKS5Transport(serverBytes: [0x05, 0x00, 0x00, 0x01] + [0, 0, 0, 0] + [0, 0])
        _ = try await sendConnectRequestAndAwaitReply(transport: transport, target: .domain("example.com"), targetPort: 80, timeout: nil)
        let expected: [UInt8] = [0x05, 0x01, 0x00, 0x03, UInt8("example.com".utf8.count)] + Array("example.com".utf8) + [0x00, 0x50]
        XCTAssertEqual(transport.sent, [expected])
    }

    func testConnectRequestDecodesIPv4BoundAddress() async throws {
        let transport = FakeSOCKS5Transport(serverBytes: [0x05, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x1F, 0x90])
        let bound = try await sendConnectRequestAndAwaitReply(transport: transport, target: .domain("example.com"), targetPort: 80, timeout: nil)
        XCTAssertEqual(bound, .ipv4([10, 0, 0, 1]))
    }

    func testConnectRequestDecodesIPv6BoundAddress() async throws {
        let addr6 = (0..<16).map { UInt8($0) }
        let transport = FakeSOCKS5Transport(serverBytes: [0x05, 0x00, 0x00, 0x04] + addr6 + [0, 0])
        let bound = try await sendConnectRequestAndAwaitReply(transport: transport, target: .domain("example.com"), targetPort: 80, timeout: nil)
        XCTAssertEqual(bound, .ipv6(addr6))
    }

    func testConnectRequestDecodesDomainBoundAddress() async throws {
        let domainBytes = Array("relay.example".utf8)
        let transport = FakeSOCKS5Transport(serverBytes: [0x05, 0x00, 0x00, 0x03, UInt8(domainBytes.count)] + domainBytes + [0, 0])
        let bound = try await sendConnectRequestAndAwaitReply(transport: transport, target: .domain("example.com"), targetPort: 80, timeout: nil)
        XCTAssertEqual(bound, .domain("relay.example"))
    }

    func testConnectRequestFailureCarriesReplyCode() async throws {
        let transport = FakeSOCKS5Transport(serverBytes: [0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]) // 0x05 = Connection refused
        do {
            _ = try await sendConnectRequestAndAwaitReply(transport: transport, target: .domain("example.com"), targetPort: 80, timeout: nil)
            XCTFail("expected error")
        } catch SOCKS5Error.requestFailed(let code) {
            XCTAssertEqual(code, 0x05)
            XCTAssertEqual(SOCKS5ReplyCode.name(forReplyCode: code), "connectionRefused")
        }
    }

    func testConnectRequestUnknownAddressTypeThrowsMalformedReply() async throws {
        let transport = FakeSOCKS5Transport(serverBytes: [0x05, 0x00, 0x00, 0x7F])
        do {
            _ = try await sendConnectRequestAndAwaitReply(transport: transport, target: .domain("example.com"), targetPort: 80, timeout: nil)
            XCTFail("expected error")
        } catch SOCKS5Error.malformedReply {
            // expected
        }
    }

    func testUnassignedReplyCodeStillProducesAReadableName() {
        XCTAssertEqual(SOCKS5ReplyCode.name(forReplyCode: 0x00), "unassigned(0x00)") // 0x00 is "succeeded", not a failure code
        XCTAssertEqual(SOCKS5ReplyCode.name(forReplyCode: 0x7F), "unassigned(0x7f)")
    }

    // MARK: - UDP ASSOCIATE request / reply

    func testAssociateRequestUsesUnspecifiedClientEndpointAndDecodesRelay() async throws {
        let transport = FakeSOCKS5Transport(serverBytes: [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x46, 0xB5])
        let endpoint = try await sendAssociateRequestAndAwaitReply(transport: transport, timeout: nil)
        XCTAssertEqual(transport.sent, [[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]])
        XCTAssertEqual(endpoint.address, .ipv4([127, 0, 0, 1]))
        XCTAssertEqual(endpoint.port, 18101)
    }

    func testAssociateRequestFailureCarriesReplyCode() async throws {
        let transport = FakeSOCKS5Transport(serverBytes: [0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        do {
            _ = try await sendAssociateRequestAndAwaitReply(transport: transport, timeout: nil)
            XCTFail("expected error")
        } catch SOCKS5Error.requestFailed(let code) {
            XCTAssertEqual(code, SOCKS5ReplyCode.commandNotSupported.rawValue)
        }
    }

    func testAssociateRejectsZeroRelayPort() async throws {
        let transport = FakeSOCKS5Transport(serverBytes: [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
        do {
            _ = try await sendAssociateRequestAndAwaitReply(transport: transport, timeout: nil)
            XCTFail("expected malformed reply")
        } catch SOCKS5Error.malformedReply {
            // expected
        }
    }
}
