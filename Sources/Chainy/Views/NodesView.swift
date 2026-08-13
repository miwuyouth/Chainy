import SwiftUI
import AppKit
import ChainCore

/// The "Nodes" panel: absorbs the old separate Subscriptions screen (an
/// Import Subscription card + a chip row of saved subscriptions) plus the
/// node library table, matching the mock's single combined panel. The
/// mock's Clash/V2Ray type toggle on Import isn't wired to anything real
/// -- `SubscriptionParser.parse` already auto-detects the format from the
/// fetched text -- so it's dropped rather than kept as a control whose
/// selection is silently discarded (see the `newgui` plan's "no dead
/// toggles" principle). Node latency is real, via `AppStore.testNode`.
struct NodesView: View {
    @EnvironmentObject var store: AppStore
    @Environment(\.dashboardPalette) private var palette

    @State private var isPresentingNew = false
    @State private var editingNode: LibraryNode?
    @State private var isImportingSubscription = false
    @State private var importStatusMessage: String?

    @State private var searchText = ""
    @State private var sortColumn: NodeSortColumn = .name
    @State private var sortAscending = true
    /// Tapping a subscription filter pill (in the Nodes card, not the
    /// Subscriptions card above it) narrows the table down to just that
    /// subscription's nodes; tapping it again -- or the "All" pill --
    /// clears back to `nil`, meaning unfiltered.
    @State private var selectedSubscriptionID: UUID?
    @State private var hoveringNodeID: UUID?
    @State private var hoveringTestButtonNodeID: UUID?
    @State private var hoveringDeleteButtonNodeID: UUID?

    @State private var isHoveringImportSubscription = false
    @State private var isHoveringAddNode = false
    @State private var isHoveringTestAll = false
    @State private var isHoveringSearchClear = false

    // Column widths for the resizable Nodes table. NAME is left out
    // deliberately -- it stays `.frame(maxWidth: .infinity)` and absorbs
    // whatever space the other three don't claim, so dragging a handle
    // never over- or under-fills the row. NAME rather than HOST:PORT gets
    // this treatment on purpose: users navigate by the friendly name they
    // gave a node, not by its raw (often obfuscated, subscription-rotated)
    // host string, so the name is what should get first claim on space and
    // room to avoid truncating, while the host string is capped and
    // truncates instead.
    @AppStorage("nodesTable.protocolColumnWidth") private var protocolColumnWidth: Double = 112
    @AppStorage("nodesTable.hostPortColumnWidth") private var hostPortColumnWidth: Double = 210
    @AppStorage("nodesTable.latencyColumnWidth") private var latencyColumnWidth: Double = 72

    private enum NodeSortColumn {
        case protocolName, name, hostPort, latency
    }

    private struct EffectiveColumnWidths {
        let protocolName: CGFloat
        let hostPort: CGFloat
        let latency: CGFloat
    }

    private var protocolColumnWidthBinding: Binding<CGFloat> {
        Binding(get: { CGFloat(protocolColumnWidth) }, set: { protocolColumnWidth = Double($0) })
    }
    private var hostPortColumnWidthBinding: Binding<CGFloat> {
        Binding(get: { CGFloat(hostPortColumnWidth) }, set: { hostPortColumnWidth = Double($0) })
    }
    private var latencyColumnWidthBinding: Binding<CGFloat> {
        Binding(get: { CGFloat(latencyColumnWidth) }, set: { latencyColumnWidth = Double($0) })
    }

    /// The values in AppStorage are user preferences, not hard minimums for
    /// the window. If several columns have been dragged wide, shrink their
    /// *displayed* widths proportionally (never below their resize-handle
    /// minima) so the flexible NAME column still has useful room and the
    /// detail view never steals width from NavigationSplitView's sidebar.
    private func effectiveColumnWidths(for availableWidth: CGFloat) -> EffectiveColumnWidths {
        let desired = [
            min(max(CGFloat(protocolColumnWidth), 80), 220),
            min(max(CGFloat(hostPortColumnWidth), 120), 420),
            min(max(CGFloat(latencyColumnWidth), 52), 120),
        ]
        let minimums: [CGFloat] = [80, 120, 52]

        // Row chrome outside the three resizable columns: three 9pt
        // handles, 80pt minimum for NAME, 6pt spacer, 68pt actions, and
        // 16pt/18pt horizontal padding.
        let fixedChrome: CGFloat = 27 + 80 + 6 + 68 + 34
        let budget = max(minimums.reduce(0, +), availableWidth - fixedChrome)
        let desiredTotal = desired.reduce(0, +)
        guard desiredTotal > budget else {
            return EffectiveColumnWidths(protocolName: desired[0], hostPort: desired[1], latency: desired[2])
        }

        let capacities = zip(desired, minimums).map(-)
        let totalCapacity = capacities.reduce(0, +)
        let reduction = min(desiredTotal - budget, totalCapacity)
        let displayed = zip(desired, zip(minimums, capacities)).map { desiredWidth, pair in
            let (minimum, capacity) = pair
            guard totalCapacity > 0 else { return minimum }
            return max(minimum, desiredWidth - reduction * capacity / totalCapacity)
        }
        return EffectiveColumnWidths(protocolName: displayed[0], hostPort: displayed[1], latency: displayed[2])
    }

    var body: some View {
        // Plain VStack rather than an outer ScrollView -- the Subscriptions
        // card and the Nodes card's own header/filter/search/column-header
        // chrome stay fixed height, while the Nodes card is given
        // `maxHeight: .infinity` so it stretches to fill whatever room is
        // left in the window (leaving a gap above the window's bottom edge
        // via the outer padding) instead of growing past the window and
        // forcing the whole page to scroll. Only the node *rows* -- the
        // part whose count is unbounded -- get their own inner ScrollView.
        VStack(alignment: .leading, spacing: 16) {
            subscriptionsCard
            nodesTableCard
                .frame(maxHeight: .infinity, alignment: .top)
        }
        .padding(20)
        .sheet(isPresented: $isPresentingNew) {
            NodeEditorSheet(node: nil) { store.addNode($0) }
        }
        .sheet(item: $editingNode) { node in
            NodeEditorSheet(node: node) { store.updateNode($0) }
        }
    }

    // MARK: - Subscriptions

    private var subscriptionsCard: some View {
        DashboardCard(padding: 0) {
            VStack(spacing: 0) {
                HStack {
                    Text("Subscriptions ").font(.system(size: 15, weight: .semibold)).foregroundColor(palette.text)
                        + Text("(\(store.subscriptions.count))").font(.system(size: 13)).foregroundColor(palette.textFaint)
                    Spacer()
                    if let importStatusMessage {
                        Text(importStatusMessage)
                            .font(.system(size: 11.5, design: .monospaced))
                            .foregroundStyle(palette.textFaint)
                            .lineLimit(1)
                            .truncationMode(.tail)
                            .frame(minWidth: 0, maxWidth: .infinity, alignment: .trailing)
                            .layoutPriority(-1)
                    }
                    Button {
                        performClipboardImport()
                    } label: {
                        Label(isImportingSubscription ? "Importing…" : "Import from Clipboard", systemImage: "doc.on.clipboard")
                    }
                        .buttonStyle(.plain)
                        .font(.system(size: 12.5, weight: .semibold))
                        .foregroundStyle(palette.accent.opacity(isHoveringImportSubscription ? 0.7 : 1))
                        .contentShape(Rectangle())
                        .disabled(isImportingSubscription)
                        .hoverCursor($isHoveringImportSubscription)
                        .help("Copy a Clash (YAML) or V2Ray subscription URL, or one or more vmess/vless/trojan/ss:// share links, then click to import from your clipboard.")
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 11)

                if store.subscriptions.isEmpty {
                    EmptyStateView(
                        title: "No subscriptions yet",
                        systemImage: "arrow.down.doc",
                        message: "Copy a Clash/V2Ray subscription URL or share link, then click Import Subscription."
                    )
                    .frame(height: 140)
                } else {
                    Rectangle().fill(palette.border).frame(height: 1)
                    // A row per subscription rather than a wrapping grid of
                    // padded chip cards -- each row only needs a name, one
                    // line of meta, and two icon buttons, so a compact table
                    // row (matching the Nodes table's own row style below)
                    // fits several subscriptions in the space two or three
                    // chip cards used to take.
                    ForEach(Array(store.subscriptions.enumerated()), id: \.element.id) { index, subscription in
                        if index > 0 {
                            Rectangle().fill(palette.borderSoft).frame(height: 1).padding(.leading, 16)
                        }
                        SubscriptionRow(
                            subscription: subscription,
                            isRefreshing: store.refreshingSubscriptionIDs.contains(subscription.id),
                            meta: store.refreshingSubscriptionIDs.contains(subscription.id)
                                ? "Refreshing…"
                                : "\(subscriptionFormatLabel(subscription)) · \(subscription.lastImportedCount.map(String.init) ?? "0") nodes · updated \(lastUpdatedText(subscription))",
                            refreshHelp: store.lastRefreshMessage[subscription.id] ?? "Refresh subscription",
                            palette: palette,
                            onRefresh: { Task { await store.refresh(subscription) } },
                            onDelete: {
                                store.deleteSubscription(subscription)
                                if selectedSubscriptionID == subscription.id {
                                    selectedSubscriptionID = nil
                                }
                            }
                        )
                    }
                }
            }
        }
    }

    /// Cosmetic Clash-vs-v2ray label derived from the URL text alone -- no
    /// parse result format is persisted on `SavedSubscription`.
    private func subscriptionFormatLabel(_ subscription: SavedSubscription) -> String {
        subscription.urlString.localizedCaseInsensitiveContains("clash") ? "Clash" : "V2Ray"
    }

    private static let relativeFormatter: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter
    }()

    private func lastUpdatedText(_ subscription: SavedSubscription) -> String {
        guard let date = subscription.lastImportedAt else { return "never" }
        return Self.relativeFormatter.localizedString(for: date, relativeTo: Date())
    }

    /// Reads whatever's on the pasteboard and figures out what to do with it
    /// -- no separate paste field or sheet, since the common case is always
    /// "copy a link somewhere, come back here, click once." A single-line
    /// http(s) URL is a subscription to fetch; everything else (one or more
    /// vmess/vless/ss/trojan share links, or a Clash YAML blob) is parsed
    /// locally with no network round-trip and merged straight into the
    /// library (see `AppStore.importRawNodes`).
    private func performClipboardImport() {
        guard let clipboard = NSPasteboard.general.string(forType: .string)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !clipboard.isEmpty else {
            showImportStatus("Clipboard is empty or doesn't contain text")
            return
        }

        let isSingleLine = clipboard.split(whereSeparator: { $0.isNewline }).count == 1
        if isSingleLine, let url = URL(string: clipboard), let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https" {
            store.addSubscription(name: url.host ?? "Subscription", urlString: clipboard)
            guard let sub = store.subscriptions.last else { return }
            isImportingSubscription = true
            Task {
                let outcome = await store.refresh(sub)
                isImportingSubscription = false
                switch outcome {
                case .success(let result):
                    showImportStatus("Imported \(result.nodes.count), skipped \(result.skipped.count).")
                case .failure(let error):
                    showImportStatus((error as? LocalizedError)?.errorDescription ?? "\(error)")
                }
            }
            return
        }

        let result = store.importRawNodes(clipboard)
        if result.nodes.isEmpty && result.skipped.isEmpty {
            showImportStatus("Clipboard content isn't a recognized subscription URL or share link")
        } else {
            showImportStatus("Imported \(result.nodes.count), skipped \(result.skipped.count).")
        }
    }

    /// Self-clearing after a few seconds so the header doesn't carry a
    /// stale result message forever; guarded by value so an in-flight timer
    /// from a previous import can't wipe out a newer message.
    private func showImportStatus(_ message: String) {
        importStatusMessage = message
        Task {
            try? await Task.sleep(nanoseconds: 4_000_000_000)
            if importStatusMessage == message {
                importStatusMessage = nil
            }
        }
    }

    // MARK: - Nodes table

    private var filteredNodes: [LibraryNode] {
        var nodes = store.library
        if let selectedSubscriptionID {
            nodes = nodes.filter { $0.subscriptionID == selectedSubscriptionID }
        }
        guard !searchText.trimmingCharacters(in: .whitespaces).isEmpty else { return nodes }
        return nodes.filter { node in
            node.name.localizedCaseInsensitiveContains(searchText)
                || node.hop.host.localizedCaseInsensitiveContains(searchText)
                || node.hop.protocolConfig.displayName.localizedCaseInsensitiveContains(searchText)
        }
    }

    private var sortedNodes: [LibraryNode] {
        filteredNodes.sorted { lhs, rhs in
            if sortColumn == .latency {
                return latencyComparator(lhs, rhs)
            }
            let result: Bool
            switch sortColumn {
            case .protocolName:
                result = lhs.hop.protocolConfig.displayName.localizedCaseInsensitiveCompare(rhs.hop.protocolConfig.displayName) == .orderedAscending
            case .name:
                result = lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
            case .hostPort:
                result = "\(lhs.hop.host):\(lhs.hop.port)".localizedCaseInsensitiveCompare("\(rhs.hop.host):\(rhs.hop.port)") == .orderedAscending
            case .latency:
                result = false // handled above
            }
            return sortAscending ? result : !result
        }
    }

    /// Reachable nodes sort by measured latency; unreachable and untested
    /// nodes always sort to the end regardless of direction, since there's
    /// no meaningful ms value to compare them by.
    private func latencyComparator(_ lhs: LibraryNode, _ rhs: LibraryNode) -> Bool {
        let lhsRank = latencySortRank(for: lhs)
        let rhsRank = latencySortRank(for: rhs)
        let lhsUnmeasured = lhsRank >= Int.max - 1
        let rhsUnmeasured = rhsRank >= Int.max - 1
        if lhsUnmeasured != rhsUnmeasured {
            return !lhsUnmeasured
        }
        let result = lhsRank < rhsRank
        return sortAscending ? result : !result
    }

    private func latencySortRank(for node: LibraryNode) -> Int {
        switch store.nodeLatencyMs[node.id] {
        case .some(.some(let ms)): return ms
        case .some(.none): return Int.max - 1
        case .none: return Int.max
        }
    }

    private func toggleSort(_ column: NodeSortColumn) {
        if sortColumn == column {
            sortAscending.toggle()
        } else {
            sortColumn = column
            sortAscending = true
        }
    }

    private func sortHeaderLabel(_ title: String, column: NodeSortColumn) -> some View {
        SortHeaderButton(
            title: title,
            isActive: sortColumn == column,
            ascending: sortAscending,
            palette: palette,
            action: { toggleSort(column) }
        )
    }

    /// One capsule per saved subscription, plus a leading "All" capsule --
    /// lives in the Nodes card itself (not the Subscriptions card above it),
    /// since this is where the filtered result is actually shown. Tapping a
    /// subscription's capsule again, or tapping "All", clears the filter.
    /// Scrolls horizontally rather than wrapping so it stays a fixed one
    /// line regardless of how many subscriptions are saved.
    private var subscriptionFilterRow: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                SubscriptionFilterPill(
                    title: "All",
                    count: store.library.count,
                    isSelected: selectedSubscriptionID == nil,
                    palette: palette,
                    action: { selectedSubscriptionID = nil }
                )
                ForEach(store.subscriptions) { subscription in
                    SubscriptionFilterPill(
                        title: subscription.name,
                        count: store.library.filter { $0.subscriptionID == subscription.id }.count,
                        isSelected: selectedSubscriptionID == subscription.id,
                        palette: palette,
                        action: {
                            selectedSubscriptionID = selectedSubscriptionID == subscription.id ? nil : subscription.id
                        }
                    )
                }
            }
        }
    }

    private var searchField: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 11))
                .foregroundStyle(palette.textFaint)
            TextField("Search nodes by name, host, or protocol", text: $searchText)
                .textFieldStyle(.plain)
                .font(.system(size: 12, design: .monospaced))
                .accessibilityIdentifier("nodes.searchField")
            if !searchText.isEmpty {
                Button {
                    searchText = ""
                } label: {
                    Image(systemName: "xmark.circle.fill").font(.system(size: 11))
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .foregroundStyle(isHoveringSearchClear ? palette.textDim : palette.textFaint)
                .hoverCursor($isHoveringSearchClear)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(palette.bgElevated, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(palette.border))
    }

    private var nodesTableCard: some View {
        DashboardCard(padding: 0) {
            VStack(spacing: 0) {
                HStack {
                    Text("Nodes ").font(.system(size: 15, weight: .semibold)).foregroundColor(palette.text)
                        + Text("(\(store.library.count))").font(.system(size: 13)).foregroundColor(palette.textFaint)
                    Spacer()
                    HStack(spacing: 2) {
                        Button {
                            isPresentingNew = true
                        } label: {
                            Label("Add Node", systemImage: "plus")
                        }
                            .buttonStyle(.plain)
                            .font(.system(size: 12.5, weight: .semibold))
                            .foregroundStyle(palette.accent)
                            .padding(.horizontal, 9)
                            .padding(.vertical, 5)
                            .background(isHoveringAddNode ? palette.bgHover : .clear, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                            .contentShape(Rectangle())
                            .hoverCursor($isHoveringAddNode)
                            .accessibilityIdentifier("nodes.addButton")

                        Rectangle().fill(palette.border).frame(width: 1, height: 13)

                        Button {
                            store.testAllNodes()
                        } label: {
                            Label("Test All", systemImage: "speedometer")
                        }
                            .buttonStyle(.plain)
                            .font(.system(size: 12.5, weight: .semibold))
                            .foregroundStyle(palette.accent)
                            .padding(.horizontal, 9)
                            .padding(.vertical, 5)
                            .background(isHoveringTestAll ? palette.bgHover : .clear, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                            .opacity(store.library.isEmpty ? 0.4 : 1)
                            .disabled(store.library.isEmpty)
                            .contentShape(Rectangle())
                            .hoverCursor($isHoveringTestAll, enabled: !store.library.isEmpty)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 14)

                if store.library.isEmpty {
                    EmptyStateView(
                        title: "No nodes yet",
                        systemImage: "server.rack",
                        message: "Add a node manually, or import a subscription above."
                    )
                    .frame(height: 220)
                } else {
                    Rectangle().fill(palette.border).frame(height: 1)

                    if !store.subscriptions.isEmpty {
                        subscriptionFilterRow
                            .padding(.horizontal, 16)
                            .padding(.vertical, 10)

                        Rectangle().fill(palette.border).frame(height: 1)
                    }

                    searchField
                        .padding(.horizontal, 16)
                        .padding(.vertical, 10)

                    Rectangle().fill(palette.border).frame(height: 1)

                    GeometryReader { proxy in
                        let widths = effectiveColumnWidths(for: proxy.size.width)
                        VStack(spacing: 0) {
                            nodeColumnHeader(widths)

                            if sortedNodes.isEmpty {
                                EmptyStateView(
                                    title: "No matching nodes",
                                    systemImage: "magnifyingglass",
                                    message: searchText.trimmingCharacters(in: .whitespaces).isEmpty
                                        ? "This subscription has no nodes in the library yet."
                                        : "Try a different search term."
                                )
                                .frame(height: 160)
                            } else {
                            ScrollView {
                                VStack(spacing: 0) {
                                    ForEach(sortedNodes) { node in
                                        Rectangle().fill(palette.borderSoft).frame(height: 1)
                                            nodeRow(node, widths: widths)
                                    }
                                }
                                // A vertical ScrollView otherwise measures its content's
                                // ideal cross-axis width. One long imported node name can
                                // then become the detail column's minimum width and make
                                // NavigationSplitView squeeze the sidebar below its stated
                                // minimum. Keep rows at the viewport width; individual
                                // text columns handle truncation below.
                                .frame(width: proxy.size.width)
                            }
                            }
                        }
                    }
                }
            }
        }
    }

    private func nodeColumnHeader(_ widths: EffectiveColumnWidths) -> some View {
        HStack(spacing: 0) {
            sortHeaderLabel("PROTOCOL", column: .protocolName)
                .frame(width: widths.protocolName, alignment: .leading)
            ColumnResizeHandle(width: protocolColumnWidthBinding, minWidth: 80, maxWidth: 220)
            sortHeaderLabel("NAME", column: .name).frame(minWidth: 0, maxWidth: .infinity, alignment: .leading)
            ColumnResizeHandle(width: hostPortColumnWidthBinding, minWidth: 120, maxWidth: 420, invert: true)
            sortHeaderLabel("HOST:PORT", column: .hostPort)
                .frame(width: widths.hostPort, alignment: .leading)
            ColumnResizeHandle(width: latencyColumnWidthBinding, minWidth: 52, maxWidth: 120, invert: true)
            sortHeaderLabel("LATENCY", column: .latency)
                .frame(width: widths.latency, alignment: .leading)
                .help("Round-trip time: TCP connect + proxy handshake + one HTTP HEAD request/response through the node.")
            Color.clear.frame(width: 6, height: 1)
            Text("").frame(width: 68, alignment: .trailing)
        }
        .font(.system(size: 10.5, weight: .bold))
        .padding(.leading, 16)
        .padding(.trailing, 18)
        .padding(.vertical, 10)
    }

    private func nodeRow(_ node: LibraryNode, widths: EffectiveColumnWidths) -> some View {
        let (latencyText, latencyColor) = latency(for: node)
        return HStack(spacing: 0) {
            DashboardBadge(node.hop.protocolConfig.displayName, foreground: palette.textDim, background: palette.bgElevated)
                .frame(width: widths.protocolName, alignment: .leading)
            Color.clear.frame(width: 9)
            // The friendly name is the primary, most-scanned text in this
            // row -- it gets the flex width above and the stronger weight
            // here -- while the raw host string (often an opaque,
            // subscription-rotated string like
            // "n.b.q.a.k.v.q.d.1.hk02-ae5.entry...") is capped to a fixed
            // column and pushed back with a dimmer/smaller monospace style
            // so it reads as supporting detail, not the headline.
            Text(node.name)
                .font(.system(size: 12.5, weight: .medium))
                .lineLimit(1)
                .truncationMode(.tail)
                .frame(minWidth: 0, maxWidth: .infinity, alignment: .leading)
                .layoutPriority(-1)
                .help(node.name)
            Color.clear.frame(width: 9)
            Text("\(node.hop.host):\(String(node.hop.port))")
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(palette.textDim)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(width: widths.hostPort, alignment: .leading)
                .help("\(node.hop.host):\(String(node.hop.port))")
            Color.clear.frame(width: 9)
            Text(latencyText)
                .font(.system(size: 12, design: .monospaced))
                .foregroundStyle(latencyColor)
                .frame(width: widths.latency, alignment: .leading)
                .help(store.nodeTestFailureReason[node.id] ?? "")
            Color.clear.frame(width: 6)
            // Test/delete stay hidden until the row is hovered -- at rest
            // this is a table of nodes to scan, not a row of controls to
            // press, and two icon buttons on every single row competed with
            // the data for attention. The 68pt trailing frame is reserved
            // either way so rows don't reflow when the icons fade in.
            HStack(spacing: 10) {
                Button("Test") { Task { await store.testNode(node) } }
                    .buttonStyle(.plain)
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundStyle(hoveringTestButtonNodeID == node.id ? palette.text : palette.textDim)
                    .disabled(store.testingNodeIDs.contains(node.id))
                    .opacity(store.testingNodeIDs.contains(node.id) ? 0.5 : 1)
                    .contentShape(Rectangle())
                    .onHover { hoveringTestButtonNodeID = $0 ? node.id : nil }
                Button {
                    store.deleteNode(node)
                } label: {
                    Image(systemName: "xmark").font(.system(size: 12))
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .foregroundStyle(hoveringDeleteButtonNodeID == node.id ? palette.red : palette.textDim)
                .onHover { hoveringDeleteButtonNodeID = $0 ? node.id : nil }
            }
            .frame(width: 68, alignment: .trailing)
            .opacity(hoveringNodeID == node.id ? 1 : 0)
            .allowsHitTesting(hoveringNodeID == node.id)
        }
        .contentShape(Rectangle())
        .onTapGesture { editingNode = node }
        .padding(.leading, 16)
        .padding(.trailing, 18)
        .padding(.vertical, 8)
        // Rows are click-to-edit, but previously had no fill at all -- only
        // the hairline separators between them -- so nothing distinguished
        // a clickable row from plain static text. A hover-only gray wash
        // gives it the same "this row is interactive" cue as the saved
        // chain rows, without the row looking like a permanently-filled
        // card while at rest.
        .background(hoveringNodeID == node.id ? palette.bgHover : .clear, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
        .onHover { hovering in
            hoveringNodeID = hovering ? node.id : nil
            if hovering {
                NSCursor.pointingHand.push()
            } else {
                NSCursor.pop()
            }
        }
    }

    private func latency(for node: LibraryNode) -> (String, Color) {
        if store.testingNodeIDs.contains(node.id) { return ("…", palette.accent) }
        guard let latency = store.nodeLatencyMs[node.id] else { return ("—", palette.textDim) }
        if let ms = latency { return ("\(ms)ms", ms > 150 ? palette.amber : palette.green) }
        return ("Failed", palette.red)
    }
}

/// One capsule in the Nodes card's subscription filter row (`subscriptionFilterRow`
/// above) -- solid-accent when selected, hairline-outlined otherwise, own
/// hover state so only the capsule under the cursor lights up. `count`
/// is shown in a dimmer trailing style so the number reads as metadata,
/// not part of the clickable label.
private struct SubscriptionFilterPill: View {
    let title: String
    let count: Int
    let isSelected: Bool
    let palette: DashboardPalette
    let action: () -> Void

    @State private var isHovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Text(title).lineLimit(1)
                Text("\(count)")
                    .foregroundStyle(isSelected ? .white.opacity(0.8) : palette.textFaint)
            }
            .font(.system(size: 11.5, weight: .semibold))
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundStyle(isSelected ? .white : (isHovering ? palette.text : palette.textDim))
        .background(
            isSelected ? palette.accent : (isHovering ? palette.bgHover : palette.bgElevated),
            in: Capsule()
        )
        .overlay(
            Capsule().strokeBorder(isSelected ? Color.clear : palette.border)
        )
        .hoverCursor($isHovering)
    }
}

/// A sortable Nodes-table column header. Also a standalone `View` rather
/// than a shared function -- four of these render side by side (PROTOCOL/
/// NAME/HOST:PORT/LATENCY), and a single hover flag on `NodesView` would
/// have all four light up together instead of just the one under the
/// cursor.
private struct SortHeaderButton: View {
    let title: String
    let isActive: Bool
    let ascending: Bool
    let palette: DashboardPalette
    let action: () -> Void

    @State private var isHovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 3) {
                Text(title)
                if isActive {
                    Image(systemName: ascending ? "chevron.up" : "chevron.down")
                        .font(.system(size: 8, weight: .bold))
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundStyle(isActive ? palette.textDim : (isHovering ? palette.textDim : palette.textFaint))
        .hoverCursor($isHovering)
    }
}

/// One row in the Subscriptions list. A standalone `View` (rather than a
/// plain function on `NodesView`) so its refresh/delete icon buttons can
/// each own their own hover state -- a function returning a view has
/// nowhere to put `@State` that's scoped to that one row's buttons.
private struct SubscriptionRow: View {
    let subscription: SavedSubscription
    let isRefreshing: Bool
    let meta: String
    let refreshHelp: String
    let palette: DashboardPalette
    let onRefresh: () -> Void
    let onDelete: () -> Void

    @State private var isHoveringRefresh = false
    @State private var isHoveringDelete = false

    var body: some View {
        HStack(spacing: 11) {
            DashboardDot(color: palette.green)
            Text(subscription.name)
                .font(.system(size: 12.5, weight: .medium))
                .foregroundStyle(palette.text)
                .lineLimit(1)
                .truncationMode(.tail)
                .frame(width: 180, alignment: .leading)
            Text(meta)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(palette.textDim)
                .lineLimit(1)
                .truncationMode(.tail)
                .frame(minWidth: 0, maxWidth: .infinity, alignment: .leading)
                .layoutPriority(-1)
            Button(action: onRefresh) {
                Group {
                    if isRefreshing {
                        ProgressView().controlSize(.small)
                    } else {
                        Image(systemName: "arrow.clockwise").font(.system(size: 11.5))
                    }
                }
                .frame(width: 22, height: 22)
                .background(isHoveringRefresh ? palette.bgHover : .clear, in: RoundedRectangle(cornerRadius: 5, style: .continuous))
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .foregroundStyle(isHoveringRefresh ? palette.text : palette.textDim)
            .disabled(isRefreshing)
            .help(refreshHelp)
            .hoverCursor($isHoveringRefresh, enabled: !isRefreshing)

            Button(action: onDelete) {
                Image(systemName: "xmark").font(.system(size: 12))
                    .frame(width: 22, height: 22)
                    .background(isHoveringDelete ? palette.bgHover : .clear, in: RoundedRectangle(cornerRadius: 5, style: .continuous))
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .foregroundStyle(isHoveringDelete ? palette.red : palette.textDim)
            .disabled(isRefreshing)
            .hoverCursor($isHoveringDelete, enabled: !isRefreshing)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 9)
    }
}

/// A draggable divider between two Nodes-table columns. Owns no state of
/// its own beyond the drag-start width -- it just nudges `width` by the
/// gesture's cumulative translation, clamped to the given bounds. `invert`
/// flips the drag direction for handles that sit to the *left* of the
/// column they resize (dragging left should grow that column).
private struct ColumnResizeHandle: View {
    @Binding var width: CGFloat
    let minWidth: CGFloat
    let maxWidth: CGFloat
    var invert: Bool = false

    @State private var dragStartWidth: CGFloat?
    @State private var isHovering = false

    var body: some View {
        ZStack {
            Color.clear
            Rectangle()
                .fill(Color.primary.opacity(isHovering || dragStartWidth != nil ? 0.25 : 0))
                .frame(width: 2)
        }
        .frame(width: 9)
        // `Color.clear` has no intrinsic height, so it greedily fills
        // whatever height its ancestors propose. That was invisible while
        // the whole page sat in one outer ScrollView (which always proposes
        // an unbounded height, so it fell back to a small default) -- but
        // now that the Nodes card is given a real, bounded height to fill
        // the window, this handle would otherwise inflate to fill it and
        // drag the whole column-header row taller with it. Pin it back to
        // its natural size regardless of what height it's offered.
        .fixedSize(horizontal: false, vertical: true)
        .contentShape(Rectangle())
        .gesture(
            DragGesture(minimumDistance: 0, coordinateSpace: .local)
                .onChanged { value in
                    let start = dragStartWidth ?? width
                    if dragStartWidth == nil { dragStartWidth = width }
                    let delta = invert ? -value.translation.width : value.translation.width
                    width = min(max(start + delta, minWidth), maxWidth)
                }
                .onEnded { _ in dragStartWidth = nil }
        )
        .onHover { hovering in
            isHovering = hovering
            if hovering {
                NSCursor.resizeLeftRight.push()
            } else {
                NSCursor.pop()
            }
        }
    }
}
