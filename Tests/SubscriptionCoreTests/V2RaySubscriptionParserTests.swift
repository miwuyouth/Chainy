import XCTest
import ShadowsocksCore
import VMessCore
import HTTPProxyCore
@testable import ChainCore
@testable import SubscriptionCore

final class V2RaySubscriptionParserTests: XCTestCase {
    private func base64(_ s: String) -> String {
        Data(s.utf8).base64EncodedString()
    }

    private func percentEncoded(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? s
    }

    private func vmessLink(ps: String, add: String, port: Any, id: String, net: String? = nil, tls: String? = nil, path: String? = nil, host: String? = nil, scy: String? = nil) -> String {
        var json: [String: Any] = ["v": "2", "ps": ps, "add": add, "port": port, "id": id, "aid": 0]
        if let net { json["net"] = net }
        if let tls { json["tls"] = tls }
        if let path { json["path"] = path }
        if let host { json["host"] = host }
        if let scy { json["scy"] = scy }
        let data = try! JSONSerialization.data(withJSONObject: json)
        return "vmess://" + data.base64EncodedString()
    }

    func testParsesSIP002ShadowsocksLink() {
        let uri = "ss://\(base64("aes-256-gcm:hunter2"))@hk01.example.com:443/?group=g#\(percentEncoded("HK 01"))"
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertEqual(result.nodes, [
            SubscriptionNode(name: "HK 01", host: "hk01.example.com", port: 443, protocolConfig: .shadowsocks(password: "hunter2", cipher: .aes256Gcm)),
        ])
        XCTAssertTrue(result.skipped.isEmpty)
    }

    func testParsesLegacyFullyEncodedShadowsocksLink() {
        let uri = "ss://\(base64("chacha20-ietf-poly1305:hunter3@jp01.example.com:8443"))#\(percentEncoded("JP 01"))"
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertEqual(result.nodes, [
            SubscriptionNode(name: "JP 01", host: "jp01.example.com", port: 8443, protocolConfig: .shadowsocks(password: "hunter3", cipher: .chacha20IetfPoly1305)),
        ])
    }

    func testSkipsUnsupportedStreamCipher() {
        let uri = "ss://\(base64("chacha20:hunter2"))@old.example.com:1/?group=g#name"
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertTrue(result.nodes.isEmpty)
        XCTAssertEqual(result.skipped.first?.reason, "unsupported cipher \"chacha20\"")
    }

    func testParsesPlainTCPVMessLink() {
        let uri = vmessLink(ps: "VMess Plain", add: "vm01.example.com", port: 443, id: "11111111-1111-1111-1111-111111111111")
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertEqual(result.nodes, [
            SubscriptionNode(name: "VMess Plain", host: "vm01.example.com", port: 443, protocolConfig: .vmess(uuid: "11111111-1111-1111-1111-111111111111")),
        ])
    }

    func testParsesVMessLinkWithStringPort() {
        // Some generators send "port" as a JSON string instead of a number.
        let uri = vmessLink(ps: "VMess StrPort", add: "vm05.example.com", port: "443", id: "44444444-4444-4444-4444-444444444444")
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertEqual(result.nodes.first?.port, 443)
    }

    func testParsesVMessLinkWithWebSocketTransport() {
        let uri = vmessLink(ps: "VMess WS", add: "vm02.example.com", port: 443, id: "22222222-2222-2222-2222-222222222222", net: "ws", path: "/ws", host: "cdn.example.com")
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertEqual(result.nodes, [
            SubscriptionNode(name: "VMess WS", host: "vm02.example.com", port: 443, protocolConfig: .vmess(uuid: "22222222-2222-2222-2222-222222222222", wsPath: "/ws", wsHost: "cdn.example.com")),
        ])
        XCTAssertTrue(result.skipped.isEmpty)
    }

    func testParsesVMessLinkWithTLS() {
        let uri = vmessLink(ps: "VMess TLS", add: "vm03.example.com", port: 443, id: "33333333-3333-3333-3333-333333333333", tls: "tls")
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertEqual(result.nodes, [
            SubscriptionNode(name: "VMess TLS", host: "vm03.example.com", port: 443, protocolConfig: .vmess(uuid: "33333333-3333-3333-3333-333333333333", tls: true)),
        ])
        XCTAssertTrue(result.skipped.isEmpty)
    }

    func testSkipsVMessLinkWithRealitySecurity() {
        let uri = vmessLink(ps: "VMess Reality", add: "vm07.example.com", port: 443, id: "77777777-7777-7777-7777-777777777777", tls: "reality")
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertTrue(result.nodes.isEmpty)
        XCTAssertEqual(result.skipped.first?.name, "VMess Reality")
    }

    func testParsesEveryStandardVMessCipherPreference() {
        let cases: [(String, VMessSecurity)] = [
            ("auto", .auto), ("aes-128-gcm", .aes128GCM),
            ("chacha20-poly1305", .chacha20Poly1305), ("none", .aes128GCM),
        ]
        for (cipher, expectedSecurity) in cases {
            let uri = vmessLink(ps: "VMess Cipher", add: "vm08.example.com", port: 443, id: "88888888-8888-8888-8888-888888888888", scy: cipher)
            let result = V2RaySubscriptionParser.parse(uri)
            XCTAssertEqual(result.nodes.count, 1, cipher)
            XCTAssertTrue(result.skipped.isEmpty, cipher)
            XCTAssertEqual(result.nodes.first?.protocolConfig, .vmess(uuid: "88888888-8888-8888-8888-888888888888", security: expectedSecurity), cipher)
        }
    }

    func testSkipsVMessLinkWithUnknownCipher() {
        let uri = vmessLink(ps: "VMess Cipher", add: "vm08.example.com", port: 443, id: "88888888-8888-8888-8888-888888888888", scy: "rc4-md5")
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertTrue(result.nodes.isEmpty)
        XCTAssertEqual(result.skipped.first?.reason, "vmess cipher \"rc4-md5\" is not recognized")
    }

    func testSkipsVMessLinkWithInvalidUUID() {
        let uri = vmessLink(ps: "VMess Bad UUID", add: "vm04.example.com", port: 443, id: "not-a-uuid")
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertTrue(result.nodes.isEmpty)
        XCTAssertEqual(result.skipped.first?.name, "VMess Bad UUID")
    }

    func testSkipsUnsupportedProtocolScheme() {
        let result = V2RaySubscriptionParser.parse("hysteria2://uuid@h2.example.com:443?sni=x#name")
        XCTAssertTrue(result.nodes.isEmpty)
        XCTAssertEqual(result.skipped.first?.reason, "unsupported protocol \"hysteria2\"")
    }

    func testParsesTrojanLinkWithSNIAndAllowInsecure() {
        let uri = "trojan://\(percentEncoded("hunter2"))@trojan.example.com:443?sni=front.example.com&allowInsecure=1#\(percentEncoded("Trojan 01"))"
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertEqual(result.nodes, [
            SubscriptionNode(name: "Trojan 01", host: "trojan.example.com", port: 443,
                              protocolConfig: .trojan(password: "hunter2", sni: "front.example.com", allowInsecure: true)),
        ])
        XCTAssertTrue(result.skipped.isEmpty)
    }

    func testParsesTrojanLinkWithoutQueryParamsDefaultsSNIToNilAndAllowInsecureToFalse() {
        let uri = "trojan://hunter2@trojan.example.com:443#name"
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertEqual(result.nodes, [
            SubscriptionNode(name: "name", host: "trojan.example.com", port: 443,
                              protocolConfig: .trojan(password: "hunter2", sni: nil, allowInsecure: false)),
        ])
    }

    func testParsesTrojanLinkWithWebSocketTransport() {
        let uri = "trojan://hunter2@trojan.example.com:443?type=ws&path=%2Fws&host=cdn.example.com#WS"
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertEqual(result.nodes, [
            SubscriptionNode(name: "WS", host: "trojan.example.com", port: 443, protocolConfig: .trojan(password: "hunter2", wsPath: "/ws", wsHost: "cdn.example.com")),
        ])
        XCTAssertTrue(result.skipped.isEmpty)
    }

    /// Unlike VLESS (`security` absent means no TLS), Trojan's own wire
    /// format implies TLS, so an explicit `security=none` -- confirmed
    /// against a real-world node that runs the trojan handshake over plain
    /// TCP -- is what's needed to opt out.
    func testParsesTrojanLinkWithSecurityNoneSkipsTLS() {
        let uri = "trojan://\(percentEncoded("hunter2"))@trojan.example.com:443?type=tcp&security=none#name"
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertEqual(result.nodes, [
            SubscriptionNode(name: "name", host: "trojan.example.com", port: 443,
                              protocolConfig: .trojan(password: "hunter2", tls: false)),
        ])
        XCTAssertTrue(result.skipped.isEmpty)
    }

    func testParsesTrojanLinkWithSecurityTLSExplicitlyKeepsTLSOn() {
        let uri = "trojan://hunter2@trojan.example.com:443?security=tls#name"
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertEqual(result.nodes, [
            SubscriptionNode(name: "name", host: "trojan.example.com", port: 443,
                              protocolConfig: .trojan(password: "hunter2", tls: true)),
        ])
    }

    func testSkipsTrojanLinkWithUnsupportedSecurity() {
        let uri = "trojan://hunter2@trojan.example.com:443?security=reality#name"
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertTrue(result.nodes.isEmpty)
        XCTAssertEqual(result.skipped.first?.reason, "trojan security \"reality\" is not supported (none/tls only)")
    }

    func testSkipsTrojanLinkWithGRPCTransport() {
        let uri = "trojan://hunter2@trojan.example.com:443?type=grpc#GRPC"
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertTrue(result.nodes.isEmpty)
        XCTAssertEqual(result.skipped.first?.name, "GRPC")
    }

    func testSkipsMalformedTrojanLinkMissingPassword() {
        let result = V2RaySubscriptionParser.parse("trojan://trojan.example.com:443#name")
        XCTAssertTrue(result.nodes.isEmpty)
        XCTAssertFalse(result.skipped.isEmpty)
    }

    func testParsesHTTPLinkWithUsernameAndPassword() {
        let uri = "http://\(percentEncoded("alice")):\(percentEncoded("hunter2"))@proxy.example.com:8080#\(percentEncoded("HTTP 01"))"
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertEqual(result.nodes, [
            SubscriptionNode(name: "HTTP 01", host: "proxy.example.com", port: 8080,
                              protocolConfig: .http(auth: .usernamePassword(username: "alice", password: "hunter2"))),
        ])
        XCTAssertTrue(result.skipped.isEmpty)
    }

    func testParsesHTTPLinkWithoutCredentialsDefaultsToNoAuth() {
        let uri = "http://proxy.example.com:8080#name"
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertEqual(result.nodes, [
            SubscriptionNode(name: "name", host: "proxy.example.com", port: 8080, protocolConfig: .http(auth: .none)),
        ])
    }

    func testSkipsMalformedHTTPLinkMissingHostPort() {
        let result = V2RaySubscriptionParser.parse("http://#name")
        XCTAssertTrue(result.nodes.isEmpty)
        XCTAssertFalse(result.skipped.isEmpty)
    }

    func testSkipsHTTPSSchemeAsTLSWrappedHTTPProxyNotSupported() {
        let result = V2RaySubscriptionParser.parse("https://proxy.example.com:8443#name")
        XCTAssertTrue(result.nodes.isEmpty)
        XCTAssertEqual(result.skipped.first?.reason, "unsupported protocol \"https\"")
    }

    func testParsesVLESSLinkWithTLSAndSNI() {
        let uuid = "11111111-1111-1111-1111-111111111111"
        let uri = "vless://\(uuid)@vless.example.com:443?security=tls&sni=front.example.com&type=tcp#\(percentEncoded("VLESS 01"))"
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertEqual(result.nodes, [
            SubscriptionNode(name: "VLESS 01", host: "vless.example.com", port: 443,
                              protocolConfig: .vless(uuid: uuid, tls: true, sni: "front.example.com", allowInsecure: false)),
        ])
        XCTAssertTrue(result.skipped.isEmpty)
    }

    func testParsesVLESSLinkWithoutSecurityDefaultsToNoTLS() {
        let uuid = "22222222-2222-2222-2222-222222222222"
        let uri = "vless://\(uuid)@vless.example.com:80#name"
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertEqual(result.nodes, [
            SubscriptionNode(name: "name", host: "vless.example.com", port: 80,
                              protocolConfig: .vless(uuid: uuid, tls: false, sni: nil, allowInsecure: false)),
        ])
    }

    func testParsesVLESSLinkWithAllowInsecure() {
        let uuid = "33333333-3333-3333-3333-333333333333"
        let uri = "vless://\(uuid)@vless.example.com:443?security=tls&allowInsecure=1#name"
        let result = V2RaySubscriptionParser.parse(uri)
        XCTAssertEqual(result.nodes, [
            SubscriptionNode(name: "name", host: "vless.example.com", port: 443,
                              protocolConfig: .vless(uuid: uuid, tls: true, sni: nil, allowInsecure: true)),
        ])
    }

    func testSkipsVLESSLinkWithRealitySecurity() {
        let uuid = "44444444-4444-4444-4444-444444444444"
        let result = V2RaySubscriptionParser.parse("vless://\(uuid)@vless.example.com:443?security=reality&pbk=x&sid=y#Reality")
        XCTAssertTrue(result.nodes.isEmpty)
        XCTAssertEqual(result.skipped.first?.name, "Reality")
    }

    func testSkipsVLESSLinkWithXTLSVisionFlow() {
        let uuid = "55555555-5555-5555-5555-555555555555"
        let result = V2RaySubscriptionParser.parse("vless://\(uuid)@vless.example.com:443?security=tls&flow=xtls-rprx-vision#Flow")
        XCTAssertTrue(result.nodes.isEmpty)
        XCTAssertEqual(result.skipped.first?.name, "Flow")
    }

    func testParsesVLESSLinkWithWebSocketTransport() {
        let uuid = "66666666-6666-6666-6666-666666666666"
        let result = V2RaySubscriptionParser.parse("vless://\(uuid)@vless.example.com:443?security=tls&type=ws&path=%2Fws&host=cdn.example.com#WS")
        XCTAssertEqual(result.nodes, [
            SubscriptionNode(name: "WS", host: "vless.example.com", port: 443, protocolConfig: .vless(uuid: uuid, tls: true, wsPath: "/ws", wsHost: "cdn.example.com")),
        ])
        XCTAssertTrue(result.skipped.isEmpty)
    }

    func testSkipsVLESSLinkWithGRPCTransport() {
        let uuid = "66666666-6666-6666-6666-666666666666"
        let result = V2RaySubscriptionParser.parse("vless://\(uuid)@vless.example.com:443?type=grpc#GRPC")
        XCTAssertTrue(result.nodes.isEmpty)
        XCTAssertEqual(result.skipped.first?.name, "GRPC")
    }

    func testSkipsVLESSLinkWithInvalidUUID() {
        let result = V2RaySubscriptionParser.parse("vless://not-a-uuid@vless.example.com:443#Bad")
        XCTAssertTrue(result.nodes.isEmpty)
        XCTAssertEqual(result.skipped.first?.name, "Bad")
    }

    func testSkipsMalformedVLESSLinkMissingHostPort() {
        let result = V2RaySubscriptionParser.parse("vless://#name")
        XCTAssertTrue(result.nodes.isEmpty)
        XCTAssertFalse(result.skipped.isEmpty)
    }

    func testParsesWholeSubscriptionBlobBase64EncodedWithMultipleLines() {
        let ssURI = "ss://\(base64("aes-256-gcm:hunter2"))@hk01.example.com:443/?group=g#\(percentEncoded("HK 01"))"
        let vmessURI = vmessLink(ps: "VMess Plain", add: "vm01.example.com", port: 443, id: "11111111-1111-1111-1111-111111111111")
        let trojanURI = "trojan://pw@trojan.example.com:443#Trojan"
        let vlessURI = "vless://uuid@vless.example.com:443#skip"
        let blob = [ssURI, vmessURI, trojanURI, vlessURI].joined(separator: "\n")
        let wholeSubscription = Data(blob.utf8).base64EncodedString()

        let result = V2RaySubscriptionParser.parse(wholeSubscription)
        XCTAssertEqual(result.nodes.count, 3)
        XCTAssertEqual(result.skipped.count, 1)
    }

    func testParsesWholeSubscriptionBlobBase64EncodedWithCRLFLines() {
        // Some subscription servers emit CRLF line endings. Swift treats
        // "\r\n" as a single `Character` (grapheme cluster), distinct from a
        // lone "\n", so a naive `split(separator: "\n")` fails to split at
        // all and every node past the first gets swallowed into it.
        let trojanURI1 = "trojan://pw@trojan1.example.com:443#One"
        let trojanURI2 = "trojan://pw@trojan2.example.com:443#Two"
        let trojanURI3 = "trojan://pw@trojan3.example.com:443#Three"
        let blob = [trojanURI1, trojanURI2, trojanURI3].joined(separator: "\r\n") + "\r\n"
        let wholeSubscription = Data(blob.utf8).base64EncodedString()

        let result = V2RaySubscriptionParser.parse(wholeSubscription)
        XCTAssertEqual(result.nodes.count, 3)
        XCTAssertTrue(result.skipped.isEmpty)
        XCTAssertEqual(result.nodes.map(\.name), ["One", "Two", "Three"])
    }

    func testAutoDetectRoutesToV2RayParserForNonClashInput() {
        let ssURI = "ss://\(base64("aes-256-gcm:hunter2"))@hk01.example.com:443/?group=g#\(percentEncoded("HK 01"))"
        let result = SubscriptionParser.parse(ssURI)
        XCTAssertEqual(result.nodes.count, 1)
    }

    func testSubscriptionNodeExposesHopForConnecting() {
        let node = SubscriptionNode(name: "n", host: "h", port: 1, protocolConfig: .socks5(auth: .none))
        XCTAssertEqual(node.hop, ProxyHop(host: "h", port: 1, protocolConfig: .socks5(auth: .none)))
    }
}
