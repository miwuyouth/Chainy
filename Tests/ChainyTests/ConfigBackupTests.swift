import XCTest
import ChainCore
@testable import Chainy

/// Coverage for `AppStore.exportBackupData()`/`importBackup(from:)` -- the
/// "Export Configuration"/"Import Configuration" buttons in `SettingsView`'s
/// Backup section, which exist so moving to a new computer doesn't mean
/// re-adding every node/chain/subscription and re-tuning every setting by
/// hand.
@MainActor
final class ConfigBackupTests: XCTestCase {
    private func makeStore() -> AppStore {
        AppStore(directoryURL: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true))
    }

    private func hop(port: UInt16 = 28401) -> ProxyHop {
        ProxyHop(host: "127.0.0.1", port: port, protocolConfig: .socks5(auth: .none))
    }

    func testExportThenImportRoundTripsNodesChainsAndSubscriptions() throws {
        let source = makeStore()
        let node = LibraryNode(name: "Home SOCKS5", hop: hop())
        source.addNode(node)
        let chain = NamedProxyChain(name: "Direct", hops: [node.hop])
        source.addChain(chain, hopLibraryNodeIDs: [node.id])
        source.addSubscription(name: "Example", urlString: "https://example.com/subscribe")

        let data = try XCTUnwrap(source.exportBackupData())

        let destination = makeStore()
        XCTAssertTrue(destination.importBackup(from: data))

        XCTAssertEqual(destination.library.map(\.name), ["Home SOCKS5"])
        XCTAssertEqual(destination.settings.chains.map(\.name), ["Direct"])
        XCTAssertEqual(destination.subscriptions.map(\.name), ["Example"])
        // The hop-to-library-node link travels with the export, not just the
        // raw chain/library arrays -- confirms `chainHopLinks` round-trips
        // too, so the imported chain still resolves back to its node.
        XCTAssertEqual(destination.resolvedLibraryNodes(for: destination.settings.chains[0]).map { $0?.name }, ["Home SOCKS5"])
    }

    func testImportOfInvalidDataFailsAndLeavesExistingDataUntouched() {
        let store = makeStore()
        let node = LibraryNode(name: "Untouched", hop: hop())
        store.addNode(node)

        XCTAssertFalse(store.importBackup(from: Data("not json".utf8)))

        XCTAssertEqual(store.library.map(\.name), ["Untouched"])
    }

    /// Preferences live in `UserDefaults`, not `AppData.json`, so this checks
    /// the export/import round trip separately from the nodes/chains/
    /// subscriptions covered above. Saves and restores the real key around
    /// the test since `AppStore` reads/writes `UserDefaults.standard`
    /// directly, same as every other preference in `SettingsView`.
    func testImportRestoresPreferencesFromUserDefaults() throws {
        let defaults = UserDefaults.standard
        let key = "localProxyPort"
        let original = defaults.object(forKey: key)
        defer {
            if let original { defaults.set(original, forKey: key) } else { defaults.removeObject(forKey: key) }
        }

        defaults.set(9999, forKey: key)
        let data = try XCTUnwrap(makeStore().exportBackupData())

        defaults.set(1111, forKey: key)
        XCTAssertTrue(makeStore().importBackup(from: data))

        XCTAssertEqual(defaults.integer(forKey: key), 9999)
    }
}
