import XCTest
import ProxyKit
@testable import HTTPProxyCore

/// Fast, in-memory coverage for `HTTPProxyServer.acceptConnect` -- the HTTP
/// counterpart to `SOCKS5CoreTests`' `SOCKS5ServerTests`, driving the parser
/// against a fake transport instead of a real socket.
final class HTTPProxyServerTests: XCTestCase {
    private final class FakeHTTPProxyTransport: ByteStreamSource, ByteStreamSink {
        private(set) var sent: [[UInt8]] = []
        private var readBuffer: [UInt8]

        init(clientText: String) { self.readBuffer = Array(clientText.utf8) }

        func send(_ bytes: [UInt8], timeout: TimeInterval?) async throws { sent.append(bytes) }

        func readExactly(_ n: Int, timeout: TimeInterval?) async throws -> [UInt8] {
            guard readBuffer.count >= n else { throw ProxyError.connectionClosed }
            let result = Array(readBuffer.prefix(n))
            readBuffer.removeFirst(n)
            return result
        }
    }

    // MARK: - CONNECT

    func testAcceptConnectHandlesCONNECTWithExplicitPort() async throws {
        let transport = FakeHTTPProxyTransport(clientText: "CONNECT example.com:8443 HTTP/1.1\r\nHost: example.com:8443\r\nUser-Agent: test\r\n\r\n")
        let request = try await HTTPProxyServer.acceptConnect(over: transport)
        XCTAssertEqual(request, HTTPProxyIncomingRequest(host: "example.com", port: 8443))
        XCTAssertEqual(transport.sent, [Array("HTTP/1.1 200 Connection Established\r\n\r\n".utf8)])
    }

    func testAcceptConnectDefaultsPortTo443WhenMissing() async throws {
        let transport = FakeHTTPProxyTransport(clientText: "CONNECT example.com HTTP/1.1\r\n\r\n")
        let request = try await HTTPProxyServer.acceptConnect(over: transport)
        XCTAssertEqual(request.host, "example.com")
        XCTAssertEqual(request.port, 443)
    }

    func testAcceptConnectIsCaseInsensitiveOnMethod() async throws {
        let transport = FakeHTTPProxyTransport(clientText: "connect example.com:443 HTTP/1.1\r\n\r\n")
        let request = try await HTTPProxyServer.acceptConnect(over: transport)
        XCTAssertEqual(request.host, "example.com")
        XCTAssertTrue(request.replayToOutbound.isEmpty, "CONNECT has nothing to replay -- the tunnel starts clean")
    }

    // MARK: - Plain HTTP (absolute-form)

    func testAcceptConnectRewritesAbsoluteFormRequestToOriginForm() async throws {
        let transport = FakeHTTPProxyTransport(clientText: "GET http://example.com/a/b?x=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")
        let request = try await HTTPProxyServer.acceptConnect(over: transport)
        XCTAssertEqual(request.host, "example.com")
        XCTAssertEqual(request.port, 80)
        let replayed = String(decoding: request.replayToOutbound, as: UTF8.self)
        XCTAssertEqual(replayed, "GET /a/b?x=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")
        XCTAssertTrue(transport.sent.isEmpty, "a plain request gets no reply from this proxy itself -- only CONNECT does")
    }

    func testAcceptConnectUsesExplicitPortInAbsoluteFormURI() async throws {
        let transport = FakeHTTPProxyTransport(clientText: "GET http://example.com:8080/ HTTP/1.1\r\nHost: example.com:8080\r\n\r\n")
        let request = try await HTTPProxyServer.acceptConnect(over: transport)
        XCTAssertEqual(request.port, 8080)
    }

    func testAcceptConnectDefaultsToRootPathWhenURIHasNone() async throws {
        let transport = FakeHTTPProxyTransport(clientText: "GET http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n")
        let request = try await HTTPProxyServer.acceptConnect(over: transport)
        let replayed = String(decoding: request.replayToOutbound, as: UTF8.self)
        XCTAssertTrue(replayed.hasPrefix("GET / HTTP/1.1\r\n"), "got: \(replayed)")
    }

    func testAcceptConnectStripsProxyAddressedHeaders() async throws {
        let transport = FakeHTTPProxyTransport(
            clientText: "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic abc123\r\nAccept: */*\r\n\r\n"
        )
        let request = try await HTTPProxyServer.acceptConnect(over: transport)
        let replayed = String(decoding: request.replayToOutbound, as: UTF8.self)
        XCTAssertFalse(replayed.lowercased().contains("proxy-connection"))
        XCTAssertFalse(replayed.lowercased().contains("proxy-authorization"))
        XCTAssertTrue(replayed.contains("Host: example.com"))
        XCTAssertTrue(replayed.contains("Accept: */*"))
    }

    // MARK: - Errors

    func testAcceptConnectRejectsMalformedRequestLine() async throws {
        let transport = FakeHTTPProxyTransport(clientText: "GARBAGE\r\n\r\n")
        do {
            _ = try await HTTPProxyServer.acceptConnect(over: transport)
            XCTFail("expected error")
        } catch HTTPProxyServerError.malformedRequestLine {
            // expected
        }
    }

    func testAcceptConnectRejectsOriginFormTargetOnPlainRequest() async throws {
        // A client that mistakes this proxy for an origin server (no
        // "http://host" prefix) -- real proxies never see this from a
        // correctly-configured client, but it must fail cleanly, not crash.
        let transport = FakeHTTPProxyTransport(clientText: "GET /just-a-path HTTP/1.1\r\nHost: example.com\r\n\r\n")
        do {
            _ = try await HTTPProxyServer.acceptConnect(over: transport)
            XCTFail("expected error")
        } catch HTTPProxyServerError.notAbsoluteFormURI {
            // expected
        }
    }

    func testAcceptConnectRejectsNonHTTPScheme() async throws {
        let transport = FakeHTTPProxyTransport(clientText: "GET ftp://example.com/ HTTP/1.1\r\n\r\n")
        do {
            _ = try await HTTPProxyServer.acceptConnect(over: transport)
            XCTFail("expected error")
        } catch HTTPProxyServerError.unsupportedScheme(let scheme) {
            XCTAssertEqual(scheme, "ftp")
        }
    }
}
