import XCTest
import SOCKS5Core
import ShadowsocksCore
import HTTPProxyCore
import VMessCore
@testable import ChainCore

final class ChainySettingsTests: XCTestCase {
    private let chainID = UUID(uuidString: "3F2504E0-4F89-11D3-9A0C-0305E82C3301")!

    private var oneChainJSON: String {
        """
        {
          "chains": [
            {
              "id": "\(chainID.uuidString)",
              "name": "Home relay",
              "hops": [
                { "protocol": "socks5", "host": "127.0.0.1", "port": 28401 },
                { "protocol": "shadowsocks", "host": "127.0.0.1", "port": 28402, "password": "mypassword", "cipher": "aes-256-gcm" },
                { "protocol": "vmess", "host": "127.0.0.1", "port": 28403, "uuid": "0398d470-bc09-4cd5-889d-3ae4c569b6da" }
              ]
            }
          ],
          "activeChainID": "\(chainID.uuidString)"
        }
        """
    }

    func testDecodesChainWithHops() throws {
        let store = try JSONDecoder().decode(ChainySettings.self, from: Data(oneChainJSON.utf8))

        XCTAssertEqual(store.chains.count, 1)
        let chain = store.chains[0]
        XCTAssertEqual(chain.id, chainID)
        XCTAssertEqual(chain.name, "Home relay")
        XCTAssertEqual(chain.hops, [
            ProxyHop(host: "127.0.0.1", port: 28401, protocolConfig: .socks5(auth: .none)),
            ProxyHop(host: "127.0.0.1", port: 28402, protocolConfig: .shadowsocks(password: "mypassword", cipher: .aes256Gcm)),
            ProxyHop(host: "127.0.0.1", port: 28403, protocolConfig: .vmess(uuid: "0398d470-bc09-4cd5-889d-3ae4c569b6da")),
        ])
    }

    func testActiveChainResolvesToMatchingChain() throws {
        let store = try JSONDecoder().decode(ChainySettings.self, from: Data(oneChainJSON.utf8))
        XCTAssertEqual(store.activeChain?.id, chainID)
    }

    func testDecodesMultipleChainsAndNoActiveSelection() throws {
        let json = """
        {
          "chains": [
            { "id": "3F2504E0-4F89-11D3-9A0C-0305E82C3301", "name": "A",
              "hops": [{ "protocol": "socks5", "host": "h1", "port": 1 }] },
            { "id": "5C6A9F1E-2B33-4D8A-9E11-8F2C7A0B4D55", "name": "B",
              "hops": [{ "protocol": "vmess", "host": "h2", "port": 2, "uuid": "0398d470-bc09-4cd5-889d-3ae4c569b6da" }] }
          ]
        }
        """
        let store = try JSONDecoder().decode(ChainySettings.self, from: Data(json.utf8))
        XCTAssertEqual(store.chains.map(\.name), ["A", "B"])
        XCTAssertNil(store.activeChainID)
        XCTAssertNil(store.activeChain)
    }

    func testDecodesSocks5WithUsernamePassword() throws {
        let json = """
        { "chains": [{ "id": "3F2504E0-4F89-11D3-9A0C-0305E82C3301", "name": "n",
            "hops": [{ "protocol": "socks5", "host": "h", "port": 1, "username": "u", "password": "p" }] }] }
        """
        let store = try JSONDecoder().decode(ChainySettings.self, from: Data(json.utf8))
        XCTAssertEqual(store.chains[0].hops, [
            ProxyHop(host: "h", port: 1, protocolConfig: .socks5(auth: .usernamePassword(username: "u", password: "p"))),
        ])
    }

    func testRoundTripsThroughEncodeAndDecode() throws {
        let original = ChainySettings(
            chains: [
                NamedProxyChain(
                    id: chainID,
                    name: "Home relay",
                    hops: [
                        ProxyHop(host: "127.0.0.1", port: 1, protocolConfig: .socks5(auth: .usernamePassword(username: "u", password: "p"))),
                        ProxyHop(host: "127.0.0.1", port: 2, protocolConfig: .shadowsocks(password: "pw", cipher: .chacha20IetfPoly1305)),
                        ProxyHop(host: "127.0.0.1", port: 3, protocolConfig: .vmess(uuid: "0398d470-bc09-4cd5-889d-3ae4c569b6da")),
                        ProxyHop(host: "127.0.0.1", port: 4, protocolConfig: .trojan(password: "tpw", sni: "example.com", allowInsecure: true)),
                        ProxyHop(host: "127.0.0.1", port: 5, protocolConfig: .http(auth: .usernamePassword(username: "u", password: "p"))),
                        ProxyHop(host: "127.0.0.1", port: 6, protocolConfig: .vless(uuid: "0398d470-bc09-4cd5-889d-3ae4c569b6da", tls: true, sni: "example.com", allowInsecure: true)),
                        ProxyHop(host: "127.0.0.1", port: 7, protocolConfig: .trojan(password: "tpw2", tls: false)),
                    ]
                ),
            ],
            activeChainID: chainID
        )

        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(ChainySettings.self, from: data)
        XCTAssertEqual(decoded, original)
    }

    func testDecodesTrojanHop() throws {
        let json = """
        { "chains": [{ "id": "3F2504E0-4F89-11D3-9A0C-0305E82C3301", "name": "n",
            "hops": [{ "protocol": "trojan", "host": "h", "port": 443, "password": "pw", "sni": "front.example.com", "allowInsecure": true }] }] }
        """
        let store = try JSONDecoder().decode(ChainySettings.self, from: Data(json.utf8))
        XCTAssertEqual(store.chains[0].hops, [
            ProxyHop(host: "h", port: 443, protocolConfig: .trojan(password: "pw", sni: "front.example.com", allowInsecure: true)),
        ])
    }

    func testDecodesTrojanHopWithoutOptionalFieldsDefaultsSNIToNilAndAllowInsecureToFalse() throws {
        let json = """
        { "chains": [{ "id": "3F2504E0-4F89-11D3-9A0C-0305E82C3301", "name": "n",
            "hops": [{ "protocol": "trojan", "host": "h", "port": 443, "password": "pw" }] }] }
        """
        let store = try JSONDecoder().decode(ChainySettings.self, from: Data(json.utf8))
        XCTAssertEqual(store.chains[0].hops, [
            ProxyHop(host: "h", port: 443, protocolConfig: .trojan(password: "pw", sni: nil, allowInsecure: false)),
        ])
    }

    /// Trojan's own wire format implies TLS, so unlike vmess/vless (default
    /// off, `"tls": true` only written when on), trojan defaults *on* and
    /// only the non-default `"tls": false` is ever written/decoded --
    /// covers the real-world server that runs the handshake over plain TCP
    /// instead (a `security=none` subscription link).
    func testDecodesTrojanHopWithTLSExplicitlyFalse() throws {
        let json = """
        { "chains": [{ "id": "3F2504E0-4F89-11D3-9A0C-0305E82C3301", "name": "n",
            "hops": [{ "protocol": "trojan", "host": "h", "port": 443, "password": "pw", "tls": false }] }] }
        """
        let store = try JSONDecoder().decode(ChainySettings.self, from: Data(json.utf8))
        XCTAssertEqual(store.chains[0].hops, [
            ProxyHop(host: "h", port: 443, protocolConfig: .trojan(password: "pw", tls: false)),
        ])
    }

    func testRejectsTrojanHopMissingPassword() {
        let json = """
        { "chains": [{ "id": "3F2504E0-4F89-11D3-9A0C-0305E82C3301", "name": "n",
            "hops": [{ "protocol": "trojan", "host": "h", "port": 443 }] }] }
        """
        XCTAssertThrowsError(try JSONDecoder().decode(ChainySettings.self, from: Data(json.utf8)))
    }

    func testDecodesVLESSHopWithTLS() throws {
        let json = """
        { "chains": [{ "id": "3F2504E0-4F89-11D3-9A0C-0305E82C3301", "name": "n",
            "hops": [{ "protocol": "vless", "host": "h", "port": 443, "uuid": "0398d470-bc09-4cd5-889d-3ae4c569b6da", "tls": true, "sni": "front.example.com", "allowInsecure": true }] }] }
        """
        let store = try JSONDecoder().decode(ChainySettings.self, from: Data(json.utf8))
        XCTAssertEqual(store.chains[0].hops, [
            ProxyHop(host: "h", port: 443, protocolConfig: .vless(uuid: "0398d470-bc09-4cd5-889d-3ae4c569b6da", tls: true, sni: "front.example.com", allowInsecure: true)),
        ])
    }

    func testDecodesVLESSHopWithoutOptionalFieldsDefaultsToNoTLS() throws {
        let json = """
        { "chains": [{ "id": "3F2504E0-4F89-11D3-9A0C-0305E82C3301", "name": "n",
            "hops": [{ "protocol": "vless", "host": "h", "port": 443, "uuid": "0398d470-bc09-4cd5-889d-3ae4c569b6da" }] }] }
        """
        let store = try JSONDecoder().decode(ChainySettings.self, from: Data(json.utf8))
        XCTAssertEqual(store.chains[0].hops, [
            ProxyHop(host: "h", port: 443, protocolConfig: .vless(uuid: "0398d470-bc09-4cd5-889d-3ae4c569b6da", tls: false, sni: nil, allowInsecure: false)),
        ])
    }

    func testRejectsVLESSHopWithInvalidUUID() {
        let json = """
        { "chains": [{ "id": "3F2504E0-4F89-11D3-9A0C-0305E82C3301", "name": "n",
            "hops": [{ "protocol": "vless", "host": "h", "port": 443, "uuid": "not-a-uuid" }] }] }
        """
        XCTAssertThrowsError(try JSONDecoder().decode(ChainySettings.self, from: Data(json.utf8)))
    }

    func testDecodesHTTPHopWithUsernamePassword() throws {
        let json = """
        { "chains": [{ "id": "3F2504E0-4F89-11D3-9A0C-0305E82C3301", "name": "n",
            "hops": [{ "protocol": "http", "host": "h", "port": 8080, "username": "u", "password": "p" }] }] }
        """
        let store = try JSONDecoder().decode(ChainySettings.self, from: Data(json.utf8))
        XCTAssertEqual(store.chains[0].hops, [
            ProxyHop(host: "h", port: 8080, protocolConfig: .http(auth: .usernamePassword(username: "u", password: "p"))),
        ])
    }

    func testDecodesHTTPHopWithoutCredentialsDefaultsToNoAuth() throws {
        let json = """
        { "chains": [{ "id": "3F2504E0-4F89-11D3-9A0C-0305E82C3301", "name": "n",
            "hops": [{ "protocol": "http", "host": "h", "port": 8080 }] }] }
        """
        let store = try JSONDecoder().decode(ChainySettings.self, from: Data(json.utf8))
        XCTAssertEqual(store.chains[0].hops, [
            ProxyHop(host: "h", port: 8080, protocolConfig: .http(auth: .none)),
        ])
    }

    func testLoadAndSaveRoundTripThroughDisk() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".json")
        defer { try? FileManager.default.removeItem(at: url) }

        try Data(oneChainJSON.utf8).write(to: url)
        var store = try ChainySettings.load(contentsOf: url)
        XCTAssertEqual(store.chains.count, 1)

        store.chains.append(NamedProxyChain(name: "Work relay", hops: [
            ProxyHop(host: "127.0.0.1", port: 28501, protocolConfig: .vmess(uuid: "b1e6c8a2-9d34-4f77-8c2e-1a5b6d9e0f3a")),
        ]))
        try store.save(to: url)

        let reloaded = try ChainySettings.load(contentsOf: url)
        XCTAssertEqual(reloaded, store)
        XCTAssertEqual(reloaded.chains.count, 2)
    }

    func testLoadsCheckedInExampleFile() throws {
        // Tests/ChainCoreTests/ChainySettingsTests.swift -> repo root is two levels up.
        let thisFile = URL(fileURLWithPath: #filePath)
        let repoRoot = thisFile.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let exampleURL = repoRoot.appendingPathComponent("ChainySettings.example.json")

        // Chainy's AppStore persists ChainySettings nested under a
        // top-level "settings" key alongside its own "library"/"subscriptions"
        // arrays (see ChainySettings.swift's header comment) -- this
        // fixture is the checked-in copy of that combined shape.
        struct AppDataFixture: Decodable { let settings: ChainySettings }
        let data = try Data(contentsOf: exampleURL)
        let store = try JSONDecoder().decode(AppDataFixture.self, from: data).settings

        XCTAssertEqual(store.chains.count, 2)
        XCTAssertEqual(store.chains.map(\.name), ["Home relay", "Work relay"])
        XCTAssertEqual(store.activeChain?.name, "Home relay")
    }

    func testRejectsEmptyHopListInAChain() {
        let json = """
        { "chains": [{ "id": "3F2504E0-4F89-11D3-9A0C-0305E82C3301", "name": "n", "hops": [] }] }
        """
        XCTAssertThrowsError(try JSONDecoder().decode(ChainySettings.self, from: Data(json.utf8)))
    }

    func testRejectsUnknownProtocol() {
        let json = """
        { "chains": [{ "id": "3F2504E0-4F89-11D3-9A0C-0305E82C3301", "name": "n",
            "hops": [{ "protocol": "wireguard", "host": "h", "port": 1 }] }] }
        """
        XCTAssertThrowsError(try JSONDecoder().decode(ChainySettings.self, from: Data(json.utf8)))
    }

    func testRejectsShadowsocksHopMissingPassword() {
        let json = """
        { "chains": [{ "id": "3F2504E0-4F89-11D3-9A0C-0305E82C3301", "name": "n",
            "hops": [{ "protocol": "shadowsocks", "host": "h", "port": 1, "cipher": "aes-256-gcm" }] }] }
        """
        XCTAssertThrowsError(try JSONDecoder().decode(ChainySettings.self, from: Data(json.utf8)))
    }

    func testRejectsShadowsocksHopWithUnknownCipher() {
        let json = """
        { "chains": [{ "id": "3F2504E0-4F89-11D3-9A0C-0305E82C3301", "name": "n",
            "hops": [{ "protocol": "shadowsocks", "host": "h", "port": 1, "password": "pw", "cipher": "rot13" }] }] }
        """
        XCTAssertThrowsError(try JSONDecoder().decode(ChainySettings.self, from: Data(json.utf8)))
    }

    func testRejectsVmessHopWithInvalidUUID() {
        let json = """
        { "chains": [{ "id": "3F2504E0-4F89-11D3-9A0C-0305E82C3301", "name": "n",
            "hops": [{ "protocol": "vmess", "host": "h", "port": 1, "uuid": "not-a-uuid" }] }] }
        """
        XCTAssertThrowsError(try JSONDecoder().decode(ChainySettings.self, from: Data(json.utf8)))
    }

    func testVMessChaChaSecurityRoundTripsThroughJSON() throws {
        let hop = ProxyHop(
            host: "vmess.example", port: 443,
            protocolConfig: .vmess(
                uuid: "11111111-1111-1111-1111-111111111111", security: .chacha20Poly1305,
                bodyOptions: VMessBodyOptions(chunkMasking: true, globalPadding: true, authenticatedLength: true)
            )
        )
        let data = try JSONEncoder().encode(hop)
        XCTAssertEqual(try JSONDecoder().decode(ProxyHop.self, from: data), hop)
        XCTAssertTrue(String(decoding: data, as: UTF8.self).contains("chacha20-poly1305"))
        XCTAssertTrue(String(decoding: data, as: UTF8.self).contains("authenticatedLength"))
    }

    func testRejectsActiveChainIDNotMatchingAnyChain() {
        let json = """
        { "chains": [{ "id": "3F2504E0-4F89-11D3-9A0C-0305E82C3301", "name": "n",
            "hops": [{ "protocol": "socks5", "host": "h", "port": 1 }] }],
          "activeChainID": "5C6A9F1E-2B33-4D8A-9E11-8F2C7A0B4D55" }
        """
        XCTAssertThrowsError(try JSONDecoder().decode(ChainySettings.self, from: Data(json.utf8)))
    }
}
