import SwiftUI
import AppKit

enum AppSection: String, CaseIterable, Identifiable, Hashable {
    case overview = "Overview"
    case connections = "Connections"
    case nodes = "Nodes"
    case chainBuilder = "Chain Builder"
    case logs = "Log"
    case settings = "Settings"

    var id: String { rawValue }

    /// Stable, space-free hook for UI tests (`rawValue` has spaces/differs from case names).
    var testID: String {
        switch self {
        case .overview: return "overview"
        case .connections: return "connections"
        case .nodes: return "nodes"
        case .chainBuilder: return "chainBuilder"
        case .logs: return "logs"
        case .settings: return "settings"
        }
    }

    var systemImage: String {
        switch self {
        case .overview: return "square.grid.2x2.fill"
        case .connections: return "network"
        case .nodes: return "server.rack"
        case .chainBuilder: return "link"
        case .logs: return "doc.text.magnifyingglass"
        case .settings: return "gearshape.fill"
        }
    }
}

/// The dashboard shell: a fixed-width macOS sidebar with a toolbar collapse
/// button and custom rows (rather than `List`, so selected/hover states match
/// the fixed palette exactly) + header chrome, wrapping the real panels.
/// Keeping the sidebar outside NavigationSplitView also prevents a detail
/// table's intrinsic width from changing the navigation width on selection.
/// Owns the palette
/// (derived from the same `themePreference` `@AppStorage` Settings already
/// exposes) and injects it into the environment so every panel reads
/// consistent colors via `@Environment(\.dashboardPalette)`.
struct RootView: View {
    @EnvironmentObject var store: AppStore
    @AppStorage("themePreference") private var themePreference = ThemePreference.light
    @State private var selection: AppSection? = .overview
    @State private var isSidebarVisible = true

    private var palette: DashboardPalette { DashboardTheme.current(for: themePreference.colorScheme) }
    private var activeSection: AppSection { selection ?? .overview }

    var body: some View {
        HStack(spacing: 0) {
            if isSidebarVisible {
                sidebar
                    .frame(width: 190)
                Rectangle().fill(palette.border).frame(width: 1)
            }
            GeometryReader { proxy in
                content
                    .frame(width: proxy.size.width, height: proxy.size.height, alignment: .topLeading)
                    .clipped()
                    .background(palette.bg)
            }
        }
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Button {
                    isSidebarVisible.toggle()
                } label: {
                    Image(systemName: "sidebar.leading")
                }
                .help(isSidebarVisible ? "Hide Sidebar" : "Show Sidebar")
            }
        }
        .frame(minWidth: 960, minHeight: 600)
        .foregroundStyle(palette.text)
        .preferredColorScheme(themePreference.colorScheme)
        .dashboardPalette(for: themePreference.colorScheme)
        .onAppear(perform: hideNativeWindowTitle)
    }

    private func hideNativeWindowTitle() {
        // At this point the toolbar has been installed and the scene window
        // is key, so AppKit can reliably suppress the WindowGroup title.
        DispatchQueue.main.async {
            // An empty title is replaced with the app name by SwiftUI; a
            // zero-width non-empty title avoids that fallback.
            NSApp.keyWindow?.title = "\u{200B}"
            NSApp.keyWindow?.titleVisibility = .hidden
        }
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        VStack(spacing: 2) {
            ForEach(AppSection.allCases) { section in
                SidebarRow(
                    section: section,
                    isSelected: activeSection == section,
                    palette: palette
                ) {
                    selection = section
                }
                .accessibilityIdentifier("sidebar.\(section.testID)")
            }
        }
        .padding(.horizontal, 8)
        .padding(.top, 4)
        .frame(maxHeight: .infinity, alignment: .top)
        .background(palette.bgSidebar)
        .safeAreaInset(edge: .top) {
            HStack(spacing: 9) {
                Text("Chainy")
                    .font(.system(size: 14.5, weight: .semibold))
                    .foregroundStyle(palette.text)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 12)
            .padding(.top, 10)
            .padding(.bottom, 4)
        }
        .safeAreaInset(edge: .bottom) {
            HStack(spacing: 8) {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(palette.bgElevated)
                    .frame(width: 26, height: 26)
                    .overlay(
                        Image(systemName: store.isProxyRunning ? "bolt.fill" : "bolt.slash")
                            .font(.system(size: 11))
                            .foregroundStyle(palette.textDim)
                    )
                VStack(alignment: .leading, spacing: 0) {
                    Text("Chainy").font(.system(size: 12.5, weight: .medium)).foregroundStyle(palette.text)
                    Text("v\(Self.appVersion)")
                        .font(.system(size: 10.5, design: .monospaced))
                        .foregroundStyle(palette.textFaint)
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .background(palette.bgSidebar)
        }
    }

    private static var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
    }

    // MARK: - Content

    @ViewBuilder
    private var content: some View {
        Group {
            switch activeSection {
            case .overview: OverviewView()
            case .connections: ConnectionsView()
            case .chainBuilder: ChainBuilderView()
            case .logs:
                DashboardCard(padding: 0) {
                    LogsView(showTitle: false)
                }
                .padding(20)
            case .nodes: NodesView()
            case .settings: SettingsView()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(palette.bg)
        // `.contain` makes this Group itself one accessibility element
        // carrying the `panel.<id>` identifier -- without it, a plain Group
        // isn't an accessibility element on its own, so `accessibilityIdentifier`
        // cascades down and overwrites every descendant's own identifier
        // instead (only Overview's ScrollView happened to block that, being
        // its own accessibility container already).
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("panel.\(activeSection.testID)")
    }
}

/// One row in the custom sidebar list. A plain `Button` rather than a
/// `List` row, so its selected/hover fills come from the fixed palette
/// (light-blue selection, light-gray hover) instead of the system's own
/// accent-tinted selection material.
private struct SidebarRow: View {
    let section: AppSection
    let isSelected: Bool
    let palette: DashboardPalette
    let action: () -> Void

    @State private var isHovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 9) {
                Image(systemName: section.systemImage)
                    .font(.system(size: 13, weight: .medium))
                    .frame(width: 18)
                Text(section.rawValue)
                    .font(.system(size: 13, weight: .medium))
                Spacer(minLength: 0)
            }
            .foregroundStyle(isSelected ? palette.accent : palette.textDim)
            .padding(.horizontal, 10)
            .frame(height: 40)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                isSelected ? palette.accentDim : (isHovering ? palette.bgHover : .clear),
                in: RoundedRectangle(cornerRadius: 8, style: .continuous)
            )
            .contentShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        }
        .buttonStyle(.plain)
        .onHover { hovering in
            isHovering = hovering
            if hovering {
                NSCursor.pointingHand.push()
            } else {
                NSCursor.pop()
            }
        }
    }
}
