import SwiftUI
import AppKit
import ChainCore

/// The `.menu`-style `MenuBarExtra` dropdown: connection status, a quick
/// connect/disconnect toggle, one-tap chain switching, and a way back into
/// the full dashboard window. Native `NSMenu` chrome -- SwiftUI ignores
/// color/background modifiers inside a `.menu`-style `MenuBarExtra`, so this
/// stays plain `Text`/`Button`/`Toggle`, no `DashboardPalette`.
struct MenuBarContentView: View {
    @EnvironmentObject var store: AppStore
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        statusLine

        Divider()

        if store.isProxyRunning {
            Button("Disconnect") {
                store.disconnect()
            }
        } else {
            Button("Connect") {
                Task { await store.connect() }
            }
            .disabled(store.settings.activeChain == nil)
        }

        if !store.settings.chains.isEmpty {
            Divider()
            ForEach(store.settings.chains) { chain in
                Toggle(chainLabel(for: chain), isOn: Binding(
                    get: { chain.id == store.settings.activeChainID },
                    set: { isOn in if isOn { store.setActiveChain(chain.id) } }
                ))
            }
        }

        Divider()

        Button("Open Chainy") {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
        Button("Quit Chainy") {
            NSApp.terminate(nil)
        }
        .keyboardShortcut("q")
    }

    @ViewBuilder
    private var statusLine: some View {
        if store.isProxyRunning {
            Text("Connected — \(store.settings.activeChain?.name ?? "Unknown chain")")
        } else {
            Text("Disconnected")
        }
        if let proxyError = store.proxyError {
            Text(proxyError)
        }
    }

    private func chainLabel(for chain: NamedProxyChain) -> String {
        guard let ms = store.chainScores[chain.id]?.latencyMs else { return chain.name }
        return "\(chain.name) — \(ms) ms"
    }
}
