import XCTest
import ChainCore
@testable import Chainy

/// AppStore persists one combined JSON file -- settings (ChainCore's
/// ChainySettings) plus this target's own library/subscriptions arrays
/// (see AppStore.swift) -- nested under top-level "settings"/"library"/
/// "subscriptions" keys. ChainySettingsTests (in ChainCoreTests) checks
/// the "settings" portion decodes correctly using only ChainCore types; this
/// test checks the whole checked-in fixture, including the Chainy-only
/// "library" and "subscriptions" arrays that test target can't see.
final class AppDataExampleFileTests: XCTestCase {
    private struct AppDataFixture: Decodable {
        let settings: ChainySettings
        let library: [LibraryNode]
        let subscriptions: [SavedSubscription]
    }

    private func loadFixture() throws -> AppDataFixture {
        // Tests/ChainyTests/AppDataExampleFileTests.swift -> repo root is two levels up.
        let thisFile = URL(fileURLWithPath: #filePath)
        let repoRoot = thisFile.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let exampleURL = repoRoot.appendingPathComponent("ChainySettings.example.json")

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(AppDataFixture.self, from: Data(contentsOf: exampleURL))
    }

    func testDecodesLibraryNodes() throws {
        let fixture = try loadFixture()

        XCTAssertEqual(fixture.library.count, 2)

        let socks5Node = fixture.library[0]
        XCTAssertEqual(socks5Node.name, "Home SOCKS5")
        XCTAssertEqual(socks5Node.hop, ProxyHop(host: "127.0.0.1", port: 28401, protocolConfig: .socks5(auth: .none)))

        let shadowsocksNode = fixture.library[1]
        XCTAssertEqual(shadowsocksNode.name, "Relay Shadowsocks")
        XCTAssertEqual(shadowsocksNode.hop, ProxyHop(host: "127.0.0.1", port: 28402, protocolConfig: .shadowsocks(password: "mypassword", cipher: .aes256Gcm)))
    }

    func testDecodesSubscriptions() throws {
        let fixture = try loadFixture()

        XCTAssertEqual(fixture.subscriptions.count, 1)
        let subscription = fixture.subscriptions[0]
        XCTAssertEqual(subscription.name, "Example subscription")
        XCTAssertEqual(subscription.urlString, "https://example.com/subscribe")
        XCTAssertEqual(subscription.lastImportedCount, 12)
        XCTAssertEqual(subscription.lastSkippedCount, 1)
        XCTAssertNotNil(subscription.lastImportedAt)
    }
}
