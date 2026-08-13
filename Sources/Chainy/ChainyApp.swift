import SwiftUI
import Darwin

@main
struct ChainyApp: App {
    @StateObject private var store: AppStore
    @AppStorage("autoConnectOnLaunch") private var autoConnectOnLaunch = false
    @AppStorage("showInMenuBar") private var showInMenuBar = true

    init() {
        raiseFileDescriptorLimit()
        SystemNotifier.installDelegate()
        // ChainyUITests passes this so a launched-for-testing app reads/
        // writes a throwaway temp directory instead of the developer's own
        // real ~/Library/Application Support/Chainy/AppData.json -- keeps
        // node/subscription/chain library churn from UI tests out of real
        // saved data (see AppStore.init(directoryURL:)'s own doc comment).
        if let testDataDir = ProcessInfo.processInfo.environment["CHAINY_UITEST_DATA_DIR"] {
            _store = StateObject(wrappedValue: AppStore(directoryURL: URL(fileURLWithPath: testDataDir, isDirectory: true)))
        } else {
            _store = StateObject(wrappedValue: AppStore())
        }
    }

    var body: some Scene {
        WindowGroup(id: "main") {
            RootView()
                .environmentObject(store)
                .task {
                    guard autoConnectOnLaunch else { return }
                    await store.connect()
                }
        }
        // The brand already appears in the sidebar; keep the unified
        // toolbar and its sidebar button, but omit the duplicate title.
        .windowToolbarStyle(.unified(showsTitle: false))
        MenuBarExtra(isInserted: $showInMenuBar) {
            MenuBarContentView()
                .environmentObject(store)
        } label: {
            Image(systemName: store.isProxyRunning ? "bolt.fill" : "bolt.slash")
        }
        .menuBarExtraStyle(.menu)
    }
}

/// Apps launched via launchd (i.e. every normal GUI launch, not a shell)
/// inherit launchd's default `RLIMIT_NOFILE` soft limit of 256 -- easy to
/// blow through here since a single relayed session holds two real sockets
/// (the local accept plus one outbound dial, see `ChainCore.open`'s doc
/// comment on why a whole multi-hop chain still shares just one outbound
/// TCP connection) and `NWConnection` itself layers a few more fds on top
/// of the raw socket. Confirmed live: once concurrent sessions climbed past
/// ~100, the local SOCKS5 listener started refusing new connections even
/// though it was still running -- the process had simply run out of fds.
/// Raises the soft limit to the hard ceiling (or 10240, whichever is lower)
/// once at startup, before anything opens a socket.
private func raiseFileDescriptorLimit() {
    var limit = rlimit()
    guard getrlimit(RLIMIT_NOFILE, &limit) == 0 else { return }
    let target = min(limit.rlim_max, 10240)
    guard target > limit.rlim_cur else { return }
    limit.rlim_cur = target
    setrlimit(RLIMIT_NOFILE, &limit)
}
