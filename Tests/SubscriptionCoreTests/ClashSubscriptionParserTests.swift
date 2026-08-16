import XCTest
import SOCKS5Core
import ShadowsocksCore
import HTTPProxyCore
@testable import ChainCore
@testable import SubscriptionCore

final class ClashSubscriptionParserTests: XCTestCase {
    // Synthetic (not real-world) fixture mirroring the exact flow-mapping
    // shapes real Clash subscription generators emit, including the
    // surrounding dns/proxy-groups sections the parser must ignore, and a
    // nested `ws-opts` map (to exercise brace-depth tracking).
    private let fixture = """
    port: 7890
    mode: Rule
    dns:
      enable: true
      nameserver:
        - 223.5.5.5
    proxies:
      - {name: 🇭🇰 HK 01, server: hk01.example.com, port: 443, type: ss, cipher: aes-256-gcm, password: hunter2, udp: true}
      - {name: JP 01, server: jp01.example.com, port: 8443, type: ss, cipher: chacha20-ietf-poly1305, password: hunter3, udp: true}
      - {name: Legacy Cipher, server: old.example.com, port: 1, type: ss, cipher: rc4-md5, password: pw}
      - {name: Obfs Node, server: obfs.example.com, port: 2, type: ss, cipher: aes-256-gcm, password: pw, plugin: obfs-local, plugin-opts: {mode: http}}
      - {name: VMess Plain, server: vm01.example.com, port: 443, type: vmess, uuid: 11111111-1111-1111-1111-111111111111, alterId: 0, cipher: auto, tls: false, udp: true}
      - {name: VMess WS, server: vm02.example.com, port: 443, type: vmess, uuid: 22222222-2222-2222-2222-222222222222, alterId: 0, cipher: auto, tls: false, network: ws, ws-opts: {path: /ws, headers: {Host: cdn.example.com}}, udp: true}
      - {name: VMess TLS, server: vm03.example.com, port: 443, type: vmess, uuid: 33333333-3333-3333-3333-333333333333, alterId: 0, cipher: auto, tls: true, udp: true}
      - {name: VMess Bad UUID, server: vm04.example.com, port: 443, type: vmess, uuid: not-a-uuid, alterId: 0, cipher: auto, tls: false}
      - {name: SOCKS5 Auth, server: socks.example.com, port: 1080, type: socks5, username: u, password: p}
      - {name: SOCKS5 Open, server: open.example.com, port: 1080, type: socks5}
      - {name: Trojan Node, server: trojan.example.com, port: 443, type: trojan, password: pw, sni: front.example.com}
      - {name: Trojan Insecure, server: trojan2.example.com, port: 443, type: trojan, password: pw2, skip-cert-verify: true}
      - {name: Trojan GRPC, server: trojan3.example.com, port: 443, type: trojan, password: pw3, network: grpc}
      - {name: Trojan No Password, server: trojan4.example.com, port: 443, type: trojan}
      - {name: VLESS TLS, server: vless.example.com, port: 443, type: vless, uuid: 11111111-1111-1111-1111-111111111111, tls: true, servername: front.example.com}
      - {name: VLESS Plain, server: vless2.example.com, port: 80, type: vless, uuid: 22222222-2222-2222-2222-222222222222}
      - {name: VLESS Bad UUID, server: vless3.example.com, port: 443, type: vless, uuid: not-a-uuid, tls: true}
      - {name: VLESS Flow, server: vless4.example.com, port: 443, type: vless, uuid: 33333333-3333-3333-3333-333333333333, tls: true, flow: xtls-rprx-vision}
      - {name: VLESS WS, server: vless5.example.com, port: 443, type: vless, uuid: 44444444-4444-4444-4444-444444444444, tls: true, network: ws, ws-opts: {path: /vless-ws}}
      - {name: VLESS WS No Path, server: vless6.example.com, port: 443, type: vless, uuid: 55555555-5555-5555-5555-555555555555, tls: true, network: ws}
      - {name: VMess GRPC, server: vm05.example.com, port: 443, type: vmess, uuid: 66666666-6666-6666-6666-666666666666, network: grpc}
      - {name: VMess AES Cipher, server: vm06.example.com, port: 443, type: vmess, uuid: 77777777-7777-7777-7777-777777777777, cipher: aes-128-gcm}
      - {name: VMess Bad Cipher, server: vm07.example.com, port: 443, type: vmess, uuid: 88888888-8888-8888-8888-888888888888, cipher: rc4-md5}
      - {name: HTTP Auth, server: http.example.com, port: 8080, type: http, username: u, password: p}
      - {name: HTTP Open, server: httpopen.example.com, port: 8080, type: http}
      - {name: HTTPS TLS, server: https.example.com, port: 8443, type: http, tls: true}
    proxy-groups:
      - name: Auto
        type: select
        proxies:
          - HK 01
    """

    func testDetectsClashYAML() {
        XCTAssertTrue(ClashSubscriptionParser.looksLikeClashYAML(fixture))
        XCTAssertFalse(ClashSubscriptionParser.looksLikeClashYAML("ss://abc\nvmess://def"))
    }

    func testParsesSupportedShadowsocksNodes() {
        let result = ClashSubscriptionParser.parse(fixture)
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "🇭🇰 HK 01", host: "hk01.example.com", port: 443,
            protocolConfig: .shadowsocks(password: "hunter2", cipher: .aes256Gcm)
        )))
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "JP 01", host: "jp01.example.com", port: 8443,
            protocolConfig: .shadowsocks(password: "hunter3", cipher: .chacha20IetfPoly1305)
        )))
    }

    func testParsesSupportedVMessAndSocks5Nodes() {
        let result = ClashSubscriptionParser.parse(fixture)
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "VMess Plain", host: "vm01.example.com", port: 443,
            protocolConfig: .vmess(uuid: "11111111-1111-1111-1111-111111111111")
        )))
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "VMess WS", host: "vm02.example.com", port: 443,
            protocolConfig: .vmess(uuid: "22222222-2222-2222-2222-222222222222", wsPath: "/ws", wsHost: "cdn.example.com")
        )))
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "VMess TLS", host: "vm03.example.com", port: 443,
            protocolConfig: .vmess(uuid: "33333333-3333-3333-3333-333333333333", tls: true)
        )))
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "VMess AES Cipher", host: "vm06.example.com", port: 443,
            protocolConfig: .vmess(uuid: "77777777-7777-7777-7777-777777777777", security: .aes128GCM)
        )))
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "SOCKS5 Auth", host: "socks.example.com", port: 1080,
            protocolConfig: .socks5(auth: .usernamePassword(username: "u", password: "p"))
        )))
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "SOCKS5 Open", host: "open.example.com", port: 1080,
            protocolConfig: .socks5(auth: .none)
        )))
    }

    func testParsesSupportedTrojanNodes() {
        let result = ClashSubscriptionParser.parse(fixture)
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "Trojan Node", host: "trojan.example.com", port: 443,
            protocolConfig: .trojan(password: "pw", sni: "front.example.com", allowInsecure: false)
        )))
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "Trojan Insecure", host: "trojan2.example.com", port: 443,
            protocolConfig: .trojan(password: "pw2", sni: nil, allowInsecure: true)
        )))
    }

    func testParsesSupportedVLESSNodes() {
        let result = ClashSubscriptionParser.parse(fixture)
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "VLESS TLS", host: "vless.example.com", port: 443,
            protocolConfig: .vless(uuid: "11111111-1111-1111-1111-111111111111", tls: true, sni: "front.example.com", allowInsecure: false)
        )))
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "VLESS Plain", host: "vless2.example.com", port: 80,
            protocolConfig: .vless(uuid: "22222222-2222-2222-2222-222222222222", tls: false, sni: nil, allowInsecure: false)
        )))
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "VLESS WS", host: "vless5.example.com", port: 443,
            protocolConfig: .vless(uuid: "44444444-4444-4444-4444-444444444444", tls: true, wsPath: "/vless-ws")
        )))
    }

    func testParsesSupportedHTTPNodes() {
        let result = ClashSubscriptionParser.parse(fixture)
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "HTTP Auth", host: "http.example.com", port: 8080,
            protocolConfig: .http(auth: .usernamePassword(username: "u", password: "p"))
        )))
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "HTTP Open", host: "httpopen.example.com", port: 8080,
            protocolConfig: .http(auth: .none)
        )))
    }

    func testSkipsUnsupportedCipherPluginTransportAndProtocol() {
        let result = ClashSubscriptionParser.parse(fixture)
        let skippedNames = Set(result.skipped.compactMap(\.name))

        XCTAssertTrue(skippedNames.contains("Legacy Cipher"))
        XCTAssertTrue(skippedNames.contains("Obfs Node"))
        XCTAssertTrue(skippedNames.contains("VMess Bad UUID"))
        XCTAssertTrue(skippedNames.contains("VMess GRPC"))
        XCTAssertTrue(skippedNames.contains("VMess Bad Cipher"))
        XCTAssertTrue(skippedNames.contains("Trojan GRPC"))
        XCTAssertTrue(skippedNames.contains("Trojan No Password"))
        XCTAssertTrue(skippedNames.contains("VLESS Bad UUID"))
        XCTAssertTrue(skippedNames.contains("VLESS Flow"))
        XCTAssertTrue(skippedNames.contains("VLESS WS No Path"))
        XCTAssertTrue(skippedNames.contains("HTTPS TLS"))

        XCTAssertEqual(
            result.skipped.first { $0.name == "VMess Bad Cipher" }?.reason,
            "vmess cipher \"rc4-md5\" is not recognized"
        )
        XCTAssertEqual(
            result.skipped.first { $0.name == "VLESS WS No Path" }?.reason,
            "vless node's \"ws-opts\" is missing a \"path\""
        )
    }

    func testTotalNodeAndSkipCounts() {
        let result = ClashSubscriptionParser.parse(fixture)
        // ss: HK 01, JP 01 ; vmess: Plain, WS, TLS, AES ; socks5: Auth, Open ;
        // trojan: Node, Insecure ; vless: TLS, Plain, WS ; http: Auth, Open = 15 supported
        XCTAssertEqual(result.nodes.count, 15)
        // Legacy Cipher, Obfs Node, VMess Bad UUID, VMess GRPC, VMess Bad Cipher, Trojan GRPC,
        // Trojan No Password, VLESS Bad UUID, VLESS Flow, VLESS WS No Path, HTTPS TLS = 11 skipped
        XCTAssertEqual(result.skipped.count, 11)
    }

    func testIgnoresNonProxiesYAMLSections() {
        let result = ClashSubscriptionParser.parse(fixture)
        XCTAssertFalse(result.nodes.contains { $0.name == "Auto" })
    }

    func testEmptyTextYieldsNoProxies() {
        let result = ClashSubscriptionParser.parse("mode: Rule\n")
        XCTAssertEqual(result.nodes.count, 0)
        XCTAssertEqual(result.skipped.count, 0)
    }

    // MARK: - Block-mapping proxies (mihomo's own default export shape)

    // Regression fixture for a real-world bug: some generators (confirmed
    // against a live subscription) emit each proxy as a standard YAML block
    // mapping -- one "key: value" per line -- rather than the single-line
    // `{key: value, ...}` flow mapping the parser originally only
    // understood. Includes a REALITY node (`reality-opts:`, a nested map)
    // and a WS node (`ws-opts:`, a nested map with its own nested `headers:`
    // map) to prove nested children are skipped by indentation rather than
    // mis-read as top-level fields, plus one inline flow-mapping entry mixed
    // into the same list to prove both shapes can coexist.
    private let blockStyleFixture = """
    mixed-port: 7890
    proxies:
      - name: 🇭🇰 HK Block
        type: ss
        server: hk01.example.com
        port: 443
        cipher: aes-256-gcm
        password: hunter2
        udp: true
      - name: JP VMess Block
        type: vmess
        server: jp01.example.com
        port: 443
        uuid: 11111111-1111-1111-1111-111111111111
        alterId: 0
        cipher: auto
        tls: false
        udp: true
      - name: RU Reality Block
        type: vless
        server: 89.169.39.55
        port: 443
        uuid: c61ec320-29f1-4e00-9272-8b676e6957b4
        servername: max.ru
        tls: true
        flow: xtls-rprx-vision
        client-fingerprint: chrome
        reality-opts:
          public-key: Lbug_wz0y9xgKeDK44D9kuUap0fXzNKyv_nMJxnZRzU
          short-id: 28a059440d3d5ba1
        skip-cert-verify: true
        udp: true
      - name: DE VMess WS Block
        type: vmess
        server: de01.example.com
        port: 443
        uuid: 22222222-2222-2222-2222-222222222222
        alterId: 0
        cipher: auto
        tls: false
        network: ws
        ws-opts:
          path: /ws
          headers:
            Host: cdn.example.com
        udp: true
      - name: FR VMess WS Inline Block
        type: vmess
        server: fr01.example.com
        port: 443
        uuid: 44444444-4444-4444-4444-444444444444
        cipher: auto
        tls: false
        network: ws
        ws-opts: {path: /ws-inline, headers: {Host: cdn-inline.example.com}}
        udp: true
      - name: CA Reality No Flow Block
        type: vless
        server: 99.169.39.55
        port: 443
        uuid: d61ec320-29f1-4e00-9272-8b676e6957b4
        servername: max.ca
        tls: true
        client-fingerprint: chrome
        reality-opts:
          public-key: Lbug_wz0y9xgKeDK44D9kuUap0fXzNKyv_nMJxnZRzU
          short-id: 28a059440d3d5ba1
        udp: true
      - name: Commented Fields Block  # a display name, not a comment target
        type: ss
        server: commented.example.com  # primary node
        port: 8443 # inline comment right after the value
        cipher: aes-256-gcm
        password: hunter2
      - {name: Inline Flow Alongside Block, server: flow.example.com, port: 8443, type: ss, cipher: aes-256-gcm, password: pw} # 100Mbps node
    proxy-groups:
      - name: Auto
        type: select
        proxies:
          - HK Block
    """

    func testParsesBlockStyleShadowsocksAndVMessNodes() {
        let result = ClashSubscriptionParser.parse(blockStyleFixture)
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "🇭🇰 HK Block", host: "hk01.example.com", port: 443,
            protocolConfig: .shadowsocks(password: "hunter2", cipher: .aes256Gcm)
        )))
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "JP VMess Block", host: "jp01.example.com", port: 443,
            protocolConfig: .vmess(uuid: "11111111-1111-1111-1111-111111111111")
        )))
    }

    func testBlockStyleNestedMapFieldsAreSkippedNotMisparsedAsTopLevel() {
        let result = ClashSubscriptionParser.parse(blockStyleFixture)
        // "RU Reality Block" is skipped for its own unsupported feature
        // (REALITY, detected via the nested `reality-opts:` map's mere
        // presence as a key -- see `ClashSubscriptionParser`'s vless case),
        // proving that same nested map didn't clobber or corrupt the
        // sibling top-level fields this parser reads.
        XCTAssertEqual(
            result.skipped.first { $0.name == "RU Reality Block" }?.reason,
            "vless REALITY is not supported"
        )
        // "DE VMess WS Block" is the one nested map this parser *does* read
        // into (`ws-opts.path`/`ws-opts.headers.Host`, flattened by
        // `parseWSOpts`) -- proves that capture resumes correctly at the
        // sibling `udp: true` field afterward instead of losing its place.
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "DE VMess WS Block", host: "de01.example.com", port: 443,
            protocolConfig: .vmess(uuid: "22222222-2222-2222-2222-222222222222", wsPath: "/ws", wsHost: "cdn.example.com")
        )))
    }

    /// Regression test: some generators keep `ws-opts` as an inline flow map
    /// even inside an otherwise block-style entry
    /// (`ws-opts: {path: ..., headers: {...}}`) rather than as its own
    /// nested block (`DE VMess WS Block`'s shape, above). This used to be
    /// silently dropped -- `parseWSOpts` would start scanning at the
    /// *next* line (a sibling field at the same indentation) and
    /// immediately give up, so the node was skipped entirely with a
    /// misleading "missing a path" reason even though the path was right
    /// there on the `ws-opts:` line itself.
    func testBlockStyleEntryWithInlineFlowStyleWSOptsIsNotDropped() {
        let result = ClashSubscriptionParser.parse(blockStyleFixture)
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "FR VMess WS Inline Block", host: "fr01.example.com", port: 443,
            protocolConfig: .vmess(uuid: "44444444-4444-4444-4444-444444444444", wsPath: "/ws-inline", wsHost: "cdn-inline.example.com")
        )))
    }

    /// Regression test: mihomo signals REALITY purely via a nested
    /// `reality-opts:` map, with no separate "security: reality" field --
    /// unlike `flow`, which a real REALITY node can leave unset (XTLS
    /// vision flow is optional for REALITY). A REALITY node missing `flow`
    /// used to sail through every guard and get imported as if it were an
    /// ordinary TLS VLESS node, which would fail to connect at runtime
    /// since this client has no REALITY key exchange.
    func testVLESSRealityWithoutFlowIsStillSkipped() {
        let result = ClashSubscriptionParser.parse(blockStyleFixture)
        XCTAssertEqual(
            result.skipped.first { $0.name == "CA Reality No Flow Block" }?.reason,
            "vless REALITY is not supported"
        )
    }

    /// Regression test: nothing in the value-parsing path used to strip a
    /// trailing `# comment` -- a per-field block-style comment left stray
    /// text in the value (failing e.g. `UInt16.init` on "8443 # inline
    /// comment..." and silently skipping an otherwise-valid entry), and a
    /// flow-style comment after the closing `}` broke the `hasSuffix("}")`
    /// check, leaving the brace (and comment text) appended onto the last
    /// field's value instead of being dropped.
    func testInlineYAMLCommentsAreStrippedInBothBlockAndFlowStyles() {
        let result = ClashSubscriptionParser.parse(blockStyleFixture)
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "Commented Fields Block", host: "commented.example.com", port: 8443,
            protocolConfig: .shadowsocks(password: "hunter2", cipher: .aes256Gcm)
        )))
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "Inline Flow Alongside Block", host: "flow.example.com", port: 8443,
            protocolConfig: .shadowsocks(password: "pw", cipher: .aes256Gcm)
        )))
    }

    func testMixesBlockAndFlowStyleEntriesInTheSameProxiesList() {
        let result = ClashSubscriptionParser.parse(blockStyleFixture)
        XCTAssertTrue(result.nodes.contains(SubscriptionNode(
            name: "Inline Flow Alongside Block", host: "flow.example.com", port: 8443,
            protocolConfig: .shadowsocks(password: "pw", cipher: .aes256Gcm)
        )))
    }

    func testIgnoresNonProxiesYAMLSectionsForBlockStyle() {
        let result = ClashSubscriptionParser.parse(blockStyleFixture)
        XCTAssertFalse(result.nodes.contains { $0.name == "Auto" })
    }
}
