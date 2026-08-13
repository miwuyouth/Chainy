import SwiftUI
import AppKit
import ServiceManagement
import UniformTypeIdentifiers
import ChainCore

enum ThemePreference: String, CaseIterable {
    case light
    case dark

    var colorScheme: ColorScheme {
        switch self {
        case .light: return .light
        case .dark: return .dark
        }
    }
}

/// The "Settings" panel, restyled to the dashboard's dark card language.
/// Keeps exactly the settings that already do something real -- no new
/// toggles matching the mock's dnsLeakProtection/ipv6/tlsVerify/
/// notifyNodeHealth/refreshInterval, none of which are backed by anything
/// today (see the `newgui` plan's adaptation #6). "System Notifications" is
/// the exception: unlike that mock's notifyFailover/notifyNodeHealth
/// toggles, it's wired to a real `SystemNotifier` posting native
/// notifications from `AppStore` on connect/disconnect/auto-optimize.
/// `preferredColorScheme` now lives on `RootView` (applied once, app-wide)
/// instead of here, so the header's theme toggle actually affects every
/// panel, not just this one.
struct SettingsView: View {
    @EnvironmentObject var store: AppStore
    @Environment(\.dashboardPalette) private var palette
    @State private var showingResetConfirm = false
    @State private var isHoveringClearLogs = false
    @State private var isHoveringResetAll = false
    @State private var notificationTestResult: SystemNotifier.TestResult?

    /// Set by `presentImportPicker()` once a file's been chosen and read,
    /// held until the confirmation alert below resolves it -- mirrors
    /// `showingResetConfirm`'s "ask before the destructive step" shape,
    /// just with a file to carry along.
    @State private var pendingImportData: Data?
    @State private var showingImportConfirm = false
    @State private var showingImportResult = false
    @State private var importSucceeded = false

    /// `SMAppService.mainApp.status` is the actual source of truth (the user
    /// can flip this from System Settings > General > Login Items outside
    /// the app entirely), so this mirrors it rather than an `@AppStorage`
    /// bool that could silently drift from what's really registered.
    @State private var launchAtLoginStatus: SMAppService.Status = SMAppService.mainApp.status
    @AppStorage("showInMenuBar") private var showInMenuBar = true
    @AppStorage("autoConnectOnLaunch") private var autoConnectOnLaunch = false
    @AppStorage(SystemNotifier.enabledDefaultsKey) private var systemNotificationsEnabled = false
    @AppStorage("themePreference") private var themePreference = ThemePreference.light
    @AppStorage("localProxyPort") private var localProxyPort = 1080
    @AppStorage("allowLANConnections") private var allowLANConnections = false
    @AppStorage("bandwidthTestSizeMB") private var bandwidthTestSizeMB: Double = 0
    @AppStorage("bandwidthTestConcurrency") private var bandwidthTestConcurrency = 4
    @AppStorage("bandwidthTestTimeoutSeconds") private var bandwidthTestTimeoutSeconds: Double = 8
    @AppStorage("connectionTestTimeoutSeconds") private var connectionTestTimeoutSeconds: Double = 10

    /// While actually running, reflects what the listener is *really* bound
    /// to (`store.isProxyBoundToLAN`, snapshotted at `connect()` time --
    /// flipping the toggle mid-session doesn't rebind it). Otherwise
    /// previews what the next Connect will do, from the toggle's current
    /// value.
    private var proxyHostDescription: String {
        let boundToLAN = store.isProxyRunning ? store.isProxyBoundToLAN : allowLANConnections
        guard boundToLAN else { return "127.0.0.1" }
        return LocalNetworkAddress.primaryIPv4() ?? "0.0.0.0"
    }

    /// Clamps to a bindable TCP port -- 0 would ask the OS to pick an
    /// ephemeral port instead of the one shown in the "Point browser/app..."
    /// hint above, and anything past 65535 doesn't fit a `UInt16` at all.
    private var localProxyPortBinding: Binding<Int> {
        Binding(
            get: { localProxyPort },
            set: { localProxyPort = min(max($0, 1), 65535) }
        )
    }

    /// Negative sizes are meaningless; 0 is kept as the deliberate
    /// "unlimited" sentinel (see the subtitle above).
    private var bandwidthTestSizeMBBinding: Binding<Double> {
        Binding(
            get: { bandwidthTestSizeMB },
            set: { bandwidthTestSizeMB = max(0, $0) }
        )
    }

    /// Mirrors the 1...16 clamp `AppStore.configuredBandwidthTestConcurrency`
    /// already enforces, so the field can't show a value the store would
    /// silently override.
    private var bandwidthTestConcurrencyBinding: Binding<Int> {
        Binding(
            get: { bandwidthTestConcurrency },
            set: { bandwidthTestConcurrency = min(max($0, 1), 16) }
        )
    }

    /// Negative timeouts are meaningless; 0 is kept as the deliberate
    /// "unlimited" sentinel, same convention as `bandwidthTestSizeMBBinding`.
    private var bandwidthTestTimeoutSecondsBinding: Binding<Double> {
        Binding(
            get: { bandwidthTestTimeoutSeconds },
            set: { bandwidthTestTimeoutSeconds = max(0, $0) }
        )
    }

    /// Unlike the bandwidth timeout above, there's no "unlimited" sentinel
    /// here (floors at 1 instead of 0) -- mirrors the floor
    /// `AppStore.configuredConnectionTestTimeoutSeconds` itself enforces, so
    /// the field can't show a value the store would silently override.
    private var connectionTestTimeoutSecondsBinding: Binding<Double> {
        Binding(
            get: { connectionTestTimeoutSeconds },
            set: { connectionTestTimeoutSeconds = max(1, $0) }
        )
    }

    /// Mirrors the floor `AppStore` already enforces when scheduling ticks,
    /// so the field can't show a value the store silently overrides.
    private var autoOptimizeIntervalBinding: Binding<Double> {
        Binding(
            get: { store.autoOptimizeIntervalMinutes },
            set: { store.autoOptimizeIntervalMinutes = max(AppStore.minimumAutoOptimizeIntervalMinutes, $0) }
        )
    }

    /// Registers/unregisters the app as a login item via `SMAppService`
    /// (macOS 13+'s replacement for `SMLoginItemSetEnabled`), then re-reads
    /// the real status rather than trusting `isOn` -- a `.requiresApproval`
    /// result still needs the user to flip it on in System Settings, so the
    /// toggle shouldn't silently claim success.
    private var launchAtLoginBinding: Binding<Bool> {
        Binding(
            get: { launchAtLoginStatus == .enabled },
            set: { isOn in
                do {
                    if isOn {
                        try SMAppService.mainApp.register()
                    } else {
                        try SMAppService.mainApp.unregister()
                    }
                } catch {
                    // Fall through -- re-reading status below reflects
                    // whatever actually happened either way.
                }
                launchAtLoginStatus = SMAppService.mainApp.status
            }
        )
    }

    private var launchAtLoginSubtitle: String? {
        switch launchAtLoginStatus {
        case .requiresApproval:
            return "Approve Chainy in System Settings > General > Login Items to finish enabling"
        default:
            return nil
        }
    }

    /// Swaps in the "Send Test" tap's outcome once there is one, so the
    /// user gets a direct answer to "did that actually work" instead of
    /// having to go check Notification Center themselves.
    private var notificationTestSubtitle: String {
        switch notificationTestResult {
        case nil:
            return "Notify when the proxy connects, disconnects unexpectedly, or auto-optimize switches chains"
        case .sent:
            return "Test notification sent -- check Notification Center."
        case .denied:
            return "Notifications are turned off for Chainy in System Settings > Notifications."
        case .failed:
            return "Couldn't send the test notification -- try again."
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                settingsSection("General") {
                    settingsRow(title: "Launch at Login", subtitle: launchAtLoginSubtitle) {
                        Toggle("", isOn: launchAtLoginBinding).labelsHidden()
                    }
                    rowDivider()
                    settingsRow(title: "Show in Menu Bar") {
                        Toggle("", isOn: $showInMenuBar).labelsHidden()
                    }
                    rowDivider()
                    settingsRow(
                        title: "Auto-Connect on Launch",
                        subtitle: "Reconnect your last active chain automatically"
                    ) {
                        Toggle("", isOn: $autoConnectOnLaunch).labelsHidden()
                    }
                    rowDivider()
                    settingsRow(
                        title: "System Notifications",
                        subtitle: notificationTestSubtitle
                    ) {
                        HStack(spacing: 8) {
                            Button("Send Test") {
                                SystemNotifier.sendTest { notificationTestResult = $0 }
                            }
                            .buttonStyle(.bordered)
                            .disabled(!systemNotificationsEnabled)

                            Toggle("", isOn: $systemNotificationsEnabled).labelsHidden()
                        }
                    }
                }

                settingsSection("Proxy") {
                    settingsRow(
                        title: "Local Proxy Port",
                        subtitle: store.isProxyRunning
                            ? "Currently listening on \(proxyHostDescription):\(store.proxyListenPort.map(Int.init) ?? localProxyPort) (SOCKS5 + HTTP, auto-detected)"
                            : "Point browser/app SOCKS5 or HTTP proxy settings at \(proxyHostDescription):\(localProxyPort)"
                    ) {
                        HStack(spacing: 6) {
                            TextField("", value: localProxyPortBinding, format: .number.grouping(.never))
                                .settingsNumberFieldStyle(palette)
                                .disabled(store.isProxyRunning)
                            Text("1–65535").font(.system(size: 11.5)).foregroundStyle(palette.textDim)
                        }
                    }
                    rowDivider()
                    settingsRow(
                        title: "Allow LAN Connections",
                        subtitle: "Let other devices on your local network use this proxy -- takes effect on next Connect."
                    ) {
                        Toggle("", isOn: $allowLANConnections).labelsHidden()
                    }
                    rowDivider()
                    settingsRow(
                        title: "Connection Test Timeout",
                        subtitle: "Gives up on \"Test Connection\"/node tests -- both the TCP latency probe and the UDP capability probe -- after \(connectionTestTimeoutSeconds.formatted())s per step."
                    ) {
                        HStack(spacing: 6) {
                            TextField("", value: connectionTestTimeoutSecondsBinding, format: .number.grouping(.never))
                                .settingsNumberFieldStyle(palette)
                            Text("s").font(.system(size: 11.5)).foregroundStyle(palette.textDim)
                        }
                    }
                    rowDivider()
                    settingsRow(
                        title: "Speed Test Size",
                        subtitle: bandwidthTestSizeMB > 0
                            ? "Downloads \(bandwidthTestSizeMB.formatted()) MB when testing bandwidth (or until the timeout below, whichever comes first) -- doesn't affect relayed traffic."
                            : "Unlimited -- bounded by the timeout below instead. Doesn't affect relayed traffic."
                    ) {
                        HStack(spacing: 6) {
                            TextField("", value: bandwidthTestSizeMBBinding, format: .number.grouping(.never))
                                .settingsNumberFieldStyle(palette)
                            Text("MB").font(.system(size: 11.5)).foregroundStyle(palette.textDim)
                        }
                    }
                    rowDivider()
                    settingsRow(
                        title: "Speed Test Concurrency",
                        subtitle: "Parallel connections used to measure bandwidth -- a single connection's own window/RTT often caps throughput well below the chain's real capacity."
                    ) {
                        HStack(spacing: 6) {
                            TextField("", value: bandwidthTestConcurrencyBinding, format: .number.grouping(.never))
                                .settingsNumberFieldStyle(palette)
                            Text("1–16").font(.system(size: 11.5)).foregroundStyle(palette.textDim)
                        }
                    }
                    rowDivider()
                    settingsRow(
                        title: "Speed Test Timeout",
                        subtitle: bandwidthTestTimeoutSeconds > 0
                            ? "Stops the bandwidth test after \(bandwidthTestTimeoutSeconds.formatted())s, whatever has downloaded by then."
                            : "Unlimited -- relies only on the Speed Test Size cap (if any) and each connection's own stall timeout."
                    ) {
                        HStack(spacing: 6) {
                            TextField("", value: bandwidthTestTimeoutSecondsBinding, format: .number.grouping(.never))
                                .settingsNumberFieldStyle(palette)
                            Text("s").font(.system(size: 11.5)).foregroundStyle(palette.textDim)
                        }
                    }
                }

                settingsSection("Auto-Optimize") {
                    settingsRow(
                        title: "Test Interval",
                        subtitle: "Minutes between testing the next chain in rotation"
                    ) {
                        HStack(spacing: 6) {
                            TextField("", value: autoOptimizeIntervalBinding, format: .number.grouping(.never))
                                .settingsNumberFieldStyle(palette)
                            Text("≥ \(AppStore.minimumAutoOptimizeIntervalMinutes.formatted())")
                                .font(.system(size: 11.5))
                                .foregroundStyle(palette.textDim)
                        }
                    }
                }

                settingsSection("Appearance") {
                    settingsRow(title: "Theme") {
                        Picker("", selection: $themePreference) {
                            Text("Light").tag(ThemePreference.light)
                            Text("Dark").tag(ThemePreference.dark)
                        }
                        .labelsHidden()
                        .pickerStyle(.segmented)
                        .frame(width: 160)
                    }
                }

                settingsSection("Storage") {
                    settingsRow(title: "Data Folder", subtitle: store.directoryURL.path) {
                        Button("Reveal in Finder") {
                            NSWorkspace.shared.activateFileViewerSelecting([store.directoryURL])
                        }
                        .buttonStyle(.bordered)
                    }
                }

                settingsSection("Backup") {
                    settingsRow(
                        title: "Export Configuration",
                        subtitle: "Save nodes, saved chains, subscriptions, and these settings to a file"
                    ) {
                        Button("Export...") { exportBackup() }
                            .buttonStyle(.bordered)
                    }
                    rowDivider()
                    settingsRow(
                        title: "Import Configuration",
                        subtitle: "Restore from a file exported by Chainy -- replaces everything above"
                    ) {
                        Button("Import...") { presentImportPicker() }
                            .buttonStyle(.bordered)
                    }
                }

                settingsSection("About") {
                    HStack(spacing: 12) {
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .fill(palette.accent)
                            .frame(width: 36, height: 36)
                            .overlay(
                                Text("C").font(.system(size: 15, weight: .bold)).foregroundStyle(.white)
                            )
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Chainy").font(.system(size: 14, weight: .semibold)).foregroundStyle(palette.text)
                            Text("Version \(Self.appVersion)")
                                .font(.system(size: 11.5))
                                .foregroundStyle(palette.textFaint)
                        }
                        Spacer()
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 12)
                    if let commit = Self.gitCommitHash {
                        rowDivider()
                        settingsRow(title: "Commit", subtitle: "Baked in at build time from the checked-out git HEAD") {
                            HStack(spacing: 6) {
                                Text(commit)
                                    .font(.system(size: 12, design: .monospaced))
                                    .foregroundStyle(palette.textDim)
                                Button {
                                    NSPasteboard.general.clearContents()
                                    NSPasteboard.general.setString(commit, forType: .string)
                                } label: {
                                    Image(systemName: "doc.on.doc")
                                }
                                .buttonStyle(.plain)
                                .foregroundStyle(palette.textDim)
                            }
                        }
                    }
                }

                settingsSection("Danger Zone", color: palette.red, cardBorder: palette.red.opacity(0.35)) {
                    HStack(spacing: 10) {
                        Button("Clear Event Log") {
                            store.clearLogs()
                        }
                        .buttonStyle(.plain)
                        .font(.system(size: 12.5, weight: .semibold))
                        .foregroundStyle(palette.textDim)
                        .padding(.horizontal, 15)
                        .padding(.vertical, 8)
                        .contentShape(Rectangle())
                        .background(isHoveringClearLogs ? palette.bgHover : palette.bgElevated, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(palette.border))
                        .hoverCursor($isHoveringClearLogs)

                        Button("Reset All Data") {
                            showingResetConfirm = true
                        }
                        .buttonStyle(.plain)
                        .font(.system(size: 12.5, weight: .semibold))
                        .foregroundStyle(palette.red)
                        .padding(.horizontal, 15)
                        .padding(.vertical, 8)
                        .contentShape(Rectangle())
                        .background(isHoveringResetAll ? palette.red.opacity(0.22) : palette.redDim, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(palette.red.opacity(0.4)))
                        .hoverCursor($isHoveringResetAll)
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 12)
                }
            }
            .padding(20)
        }
        .toggleStyle(.switch)
        .tint(palette.accent)
        .onAppear {
            launchAtLoginStatus = SMAppService.mainApp.status
        }
        .onChange(of: systemNotificationsEnabled) { enabled in
            if enabled { SystemNotifier.requestAuthorizationIfNeeded() }
        }
        .alert("Reset all data?", isPresented: $showingResetConfirm) {
            Button("Cancel", role: .cancel) {}
            Button("Reset", role: .destructive) {
                store.settings = ChainySettings()
                store.library = []
                store.subscriptions = []
            }
        } message: {
            Text("This deletes every saved chain, node, and subscription. This cannot be undone.")
        }
        .alert("Import configuration?", isPresented: $showingImportConfirm) {
            Button("Cancel", role: .cancel) { pendingImportData = nil }
            Button("Import", role: .destructive) {
                importSucceeded = pendingImportData.map(store.importBackup(from:)) ?? false
                pendingImportData = nil
                showingImportResult = true
            }
        } message: {
            Text("This replaces every saved chain, node, subscription, and preference with the file's contents. This cannot be undone.")
        }
        .alert(importSucceeded ? "Import complete" : "Import failed", isPresented: $showingImportResult) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(importSucceeded ? "Your configuration has been restored." : "That file isn't a valid Chainy configuration export.")
        }
    }

    /// Prompts for a save location and writes the current config there --
    /// see `AppStore.exportBackupData()` for what's included. No further
    /// confirmation needed since this only reads state, never mutates it.
    private func exportBackup() {
        guard let data = store.exportBackupData() else { return }
        let panel = NSSavePanel()
        panel.title = "Export Chainy Configuration"
        panel.nameFieldStringValue = "Chainy-Backup-\(Self.exportDateFormatter.string(from: Date())).json"
        panel.allowedContentTypes = [.json]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try? data.write(to: url, options: .atomic)
    }

    /// Reads the chosen file up front, then hands off to the confirmation
    /// alert -- matches `showingResetConfirm`'s pattern of confirming
    /// *before* the destructive step, just with a file already in hand by
    /// the time the user sees that alert.
    private func presentImportPicker() {
        let panel = NSOpenPanel()
        panel.title = "Import Chainy Configuration"
        panel.allowedContentTypes = [.json]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url, let data = try? Data(contentsOf: url) else { return }
        pendingImportData = data
        showingImportConfirm = true
    }

    private static let exportDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter
    }()

    private static var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
    }

    /// Set by the `ChainyApp` target's "Embed Git Commit" build script
    /// (project.yml) via `PlistBuddy` after `GENERATE_INFOPLIST_FILE`
    /// produces the bundle's Info.plist -- absent for builds that skip that
    /// script (e.g. `swift build`/`swift run`, which don't run Xcode build
    /// phases at all).
    private static var gitCommitHash: String? {
        Bundle.main.infoDictionary?["GitCommitHash"] as? String
    }

    private func sectionHeader(_ title: String, color: Color? = nil) -> some View {
        Text(title.uppercased())
            .font(.system(size: 11.5, weight: .semibold))
            .foregroundStyle(color ?? palette.textDim)
            .padding(.horizontal, 4)
    }

    /// A hairline separator between two rows in the same section card --
    /// inset from the leading edge so it doesn't touch the card's own
    /// rounded corners, matching macOS System Settings' grouped-list look
    /// (one card per section, plain dividers between rows, no per-row fill).
    private func rowDivider() -> some View {
        Rectangle().fill(palette.borderSoft).frame(height: 1).padding(.leading, 14)
    }

    /// Pairs a section header tightly with its card (8pt) while the outer
    /// `VStack`'s 22pt spacing keeps sections themselves clearly separated --
    /// otherwise every header sits at the same uniform distance from both
    /// the card above and the card below it, and the page reads as one flat
    /// list instead of grouped sections.
    @ViewBuilder
    private func settingsSection<Content: View>(
        _ title: String,
        color: Color? = nil,
        cardBorder: Color? = nil,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader(title, color: color)
            DashboardCard(padding: 0) {
                VStack(alignment: .leading, spacing: 0) {
                    content()
                }
            }
            .overlay {
                if let cardBorder {
                    RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(cardBorder)
                }
            }
        }
    }

    @ViewBuilder
    private func settingsRow<Accessory: View>(title: String, subtitle: String? = nil, @ViewBuilder accessory: () -> Accessory) -> some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 13, weight: .medium)).foregroundStyle(palette.text)
                if let subtitle {
                    Text(subtitle)
                        .font(.system(size: 11.5))
                        .foregroundStyle(palette.textDim)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            Spacer(minLength: 12)
            accessory()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }
}

/// The numeric settings fields (port, speed-test size, auto-optimize
/// interval) previously used `.textFieldStyle(.roundedBorder)`, whose
/// system-drawn border reads faint against this dashboard's own flat
/// surfaces. Swapping in the same plain-field-plus-explicit-border look the
/// rest of the app already uses (e.g. `ChainBuilderView`'s chain-name field)
/// gives these three a border that's actually visible.
private extension View {
    func settingsNumberFieldStyle(_ palette: DashboardPalette) -> some View {
        self
            .textFieldStyle(.plain)
            .font(.system(size: 12.5))
            .foregroundStyle(palette.text)
            .multilineTextAlignment(.trailing)
            .frame(width: 60)
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .background(palette.bgElevated, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 6, style: .continuous).strokeBorder(palette.border, lineWidth: 1.25))
    }
}
