import XCTest
import ProxyKit
@testable import HTTPProxyCore

/// Fast, in-memory coverage for `HTTPProxySession` -- the HTTP counterpart
/// to `SOCKS5CoreTests`' own client-side tests, driving the CONNECT
/// request/reply framing against a fake transport instead of a real socket.
final class HTTPProxyClientTests: XCTestCase {
    private final class FakeHTTPProxyTransport: ByteStreamSource, ByteStreamSink, ByteStreamAvailableReader, ByteStreamCloser {
        private(set) var sent: [[UInt8]] = []
        private var readBuffer: [UInt8]

        init(serverText: String) { self.readBuffer = Array(serverText.utf8) }

        func send(_ bytes: [UInt8], timeout: TimeInterval?) async throws { sent.append(bytes) }

        func readExactly(_ n: Int, timeout: TimeInterval?) async throws -> [UInt8] {
            guard readBuffer.count >= n else { throw ProxyError.connectionClosed }
            let result = Array(readBuffer.prefix(n))
            readBuffer.removeFirst(n)
            return result
        }

        func readAvailable(timeout: TimeInterval?) async throws -> [UInt8] {
            let result = readBuffer
            readBuffer = []
            return result
        }

        func close() {}
    }

    private func sentText(_ transport: FakeHTTPProxyTransport) -> String {
        String(decoding: transport.sent.flatMap { $0 }, as: UTF8.self)
    }

    // MARK: - Request framing

    func testSendsCONNECTRequestForDomainTargetWithNoAuth() async throws {
        let transport = FakeHTTPProxyTransport(serverText: "HTTP/1.1 200 Connection Established\r\n\r\n")
        _ = try await HTTPProxySession.open(over: transport, targetHost: "example.com", targetPort: 443, timeout: nil)
        XCTAssertEqual(sentText(transport), "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
    }

    func testSendsProxyAuthorizationBasicHeaderWhenCredentialsConfigured() async throws {
        let transport = FakeHTTPProxyTransport(serverText: "HTTP/1.1 200 Connection Established\r\n\r\n")
        _ = try await HTTPProxySession.open(over: transport, auth: .usernamePassword(username: "alice", password: "hunter2"), targetHost: "example.com", targetPort: 443, timeout: nil)

        let expectedCredentials = Data("alice:hunter2".utf8).base64EncodedString()
        XCTAssertEqual(sentText(transport), "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic \(expectedCredentials)\r\n\r\n")
    }

    func testBracketsIPv6TargetInRequestLineAndHostHeader() async throws {
        let transport = FakeHTTPProxyTransport(serverText: "HTTP/1.1 200 Connection Established\r\n\r\n")
        _ = try await HTTPProxySession.open(over: transport, targetHost: "::1", targetPort: 8443, timeout: nil)
        XCTAssertEqual(sentText(transport), "CONNECT [::1]:8443 HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n")
    }

    // MARK: - Reply handling

    func testAcceptsPlain200StatusWithNoHeaders() async throws {
        let transport = FakeHTTPProxyTransport(serverText: "HTTP/1.1 200 Connection Established\r\n\r\n")
        _ = try await HTTPProxySession.open(over: transport, targetHost: "example.com", targetPort: 443, timeout: nil)
        // No throw is the assertion -- open() returning at all means the
        // status line and header block were both consumed successfully.
    }

    func testDiscardsResponseHeadersBeforeExposingTheTunnel() async throws {
        // A real proxy (e.g. Squid) can send extra headers alongside its
        // 200 reply -- these must be consumed here, not left on the wire
        // to be misread as the start of the tunneled application data.
        let transport = FakeHTTPProxyTransport(serverText: "HTTP/1.1 200 Connection Established\r\nVia: 1.1 proxy\r\nProxy-Agent: test\r\n\r\nhello")
        let session = try await HTTPProxySession.open(over: transport, targetHost: "example.com", targetPort: 443, timeout: nil)
        let payload = try await session.readExactly(5, timeout: nil)
        XCTAssertEqual(String(decoding: payload, as: UTF8.self), "hello")
    }

    func testAcceptsNon200SuccessStatusCode() async throws {
        // 2xx besides 200 shouldn't happen for CONNECT in practice, but
        // nothing in RFC 7231 requires exactly 200 -- only "success".
        let transport = FakeHTTPProxyTransport(serverText: "HTTP/1.1 201 Created\r\n\r\n")
        _ = try await HTTPProxySession.open(over: transport, targetHost: "example.com", targetPort: 443, timeout: nil)
    }

    // MARK: - Errors

    func testThrowsRequestFailedForProxyAuthenticationRequired() async throws {
        let transport = FakeHTTPProxyTransport(serverText: "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
        do {
            _ = try await HTTPProxySession.open(over: transport, targetHost: "example.com", targetPort: 443, timeout: nil)
            XCTFail("expected error")
        } catch HTTPProxyClientError.requestFailed(let statusCode, let statusLine) {
            XCTAssertEqual(statusCode, 407)
            XCTAssertEqual(statusLine, "HTTP/1.1 407 Proxy Authentication Required")
        }
    }

    func testThrowsRequestFailedForConnectionRefusedStatus() async throws {
        let transport = FakeHTTPProxyTransport(serverText: "HTTP/1.1 502 Bad Gateway\r\n\r\n")
        do {
            _ = try await HTTPProxySession.open(over: transport, targetHost: "example.com", targetPort: 443, timeout: nil)
            XCTFail("expected error")
        } catch HTTPProxyClientError.requestFailed(let statusCode, _) {
            XCTAssertEqual(statusCode, 502)
        }
    }

    func testThrowsMalformedStatusLineForGarbageReply() async throws {
        let transport = FakeHTTPProxyTransport(serverText: "GARBAGE\r\n\r\n")
        do {
            _ = try await HTTPProxySession.open(over: transport, targetHost: "example.com", targetPort: 443, timeout: nil)
            XCTFail("expected error")
        } catch HTTPProxyClientError.malformedStatusLine {
            // expected
        }
    }
}
