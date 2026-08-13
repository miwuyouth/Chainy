import SwiftUI

/// Live + recently-closed relayed connections, one row per accepted local
/// socket (see `LocalProxyServer.ConnectionInfo`) -- the per-connection
/// counterpart to Overview's aggregate throughput/active-count stats.
/// Same unbounded-list page shape as `NodesView` (plain `VStack`, no outer
/// `ScrollView`; only the row list scrolls internally) rather than Saved
/// Chains' fixed-height `Table`, since the Closed history can run up to
/// `LocalProxyServer`'s 200-entry cap.
struct ConnectionsView: View {
    @EnvironmentObject var store: AppStore
    @Environment(\.dashboardPalette) private var palette
    @State private var showingClosed = false
    /// Empty until the user clicks a sortable column header, at which point
    /// `Table` drives this itself -- until then `rows` falls back to
    /// newest-first, the natural "what's happening right now" order.
    @State private var sortOrder: [KeyPathComparator<ConnectionInfo>] = []

    private var rows: [ConnectionInfo] {
        let base = showingClosed ? store.closedConnections : store.liveConnections
        guard !sortOrder.isEmpty else {
            return base.sorted { $0.startedAt > $1.startedAt }
        }
        return base.sorted(using: sortOrder)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            connectionsCard
                .frame(maxHeight: .infinity, alignment: .top)
        }
        .padding(20)
    }

    private var connectionsCard: some View {
        DashboardCard(padding: 0) {
            VStack(alignment: .leading, spacing: 0) {
                header

                Rectangle().fill(palette.border).frame(height: 1)

                if rows.isEmpty {
                    EmptyStateView(
                        title: showingClosed ? "No closed connections yet" : "No active connections",
                        systemImage: showingClosed ? "clock.arrow.circlepath" : "network",
                        message: showingClosed
                            ? "Connections show up here once they close, until the next Connect starts a fresh session."
                            : store.isProxyRunning
                                ? "Nothing is relaying through the local proxy right now."
                                : "Connect to a chain to see live connections here."
                    )
                    .frame(maxHeight: .infinity)
                } else {
                    connectionsTable
                }
            }
        }
    }

    private var header: some View {
        HStack {
            Text("Connections")
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(palette.text)
            Spacer()
            Picker("", selection: $showingClosed) {
                Text("Active (\(store.liveConnections.count))").tag(false)
                    .accessibilityIdentifier("connections.tab.active")
                Text("Closed (\(store.closedConnections.count))").tag(true)
                    .accessibilityIdentifier("connections.tab.closed")
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 260)
            .accessibilityIdentifier("connections.tabPicker")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
    }

    // MARK: - Table

    /// Unlike `ChainBuilderView.savedChainsTable`, this deliberately isn't
    /// `.scrollDisabled` -- Saved Chains is a handful of items sized to fit
    /// the page's own outer `ScrollView`, but Closed can run up to 200
    /// entries, so this table gets `maxHeight: .infinity` and scrolls
    /// internally instead (same shape as `NodesView`'s node rows).
    private var connectionsTable: some View {
        Table(rows, sortOrder: $sortOrder) {
            TableColumn("DESTINATION", sortUsing: KeyPathComparator(\.destination)) { row in
                connectionCell {
                    Text(row.destination.isEmpty ? "—" : row.destination)
                        .font(.system(size: 12.5, design: .monospaced))
                        .foregroundStyle(palette.text)
                        .lineLimit(1)
                        .truncationMode(.tail)
                        .help(row.destination)
                }
            }
            .width(min: 160, ideal: 260)

            TableColumn("TYPE") { row in
                connectionCell {
                    DashboardBadge(row.kind == .tcp ? "TCP" : "UDP", foreground: palette.textDim, background: palette.bgElevated)
                }
            }
            .width(min: 56, ideal: 64, max: 90)

            TableColumn("CHAIN", sortUsing: KeyPathComparator(\.chainName)) { row in
                connectionCell {
                    Text(row.chainName)
                        .font(.system(size: 12.5, weight: .medium))
                        .foregroundStyle(palette.textDim)
                        .lineLimit(1)
                        .truncationMode(.tail)
                        .help(row.chainName)
                }
            }
            .width(min: 90, ideal: 140, max: 260)

            TableColumn("UPLOAD", sortUsing: KeyPathComparator(\.uploadBytes)) { row in
                connectionCell(alignment: .trailing) {
                    Text(byteText(row.uploadBytes))
                        .font(.system(size: 11.5, design: .monospaced))
                        .foregroundStyle(palette.textFaint)
                }
            }
            .width(min: 70, ideal: 84, max: 110)

            TableColumn("DOWNLOAD", sortUsing: KeyPathComparator(\.downloadBytes)) { row in
                connectionCell(alignment: .trailing) {
                    Text(byteText(row.downloadBytes))
                        .font(.system(size: 11.5, design: .monospaced))
                        .foregroundStyle(palette.textFaint)
                }
            }
            .width(min: 70, ideal: 84, max: 110)

            TableColumn("DURATION", sortUsing: KeyPathComparator(\.durationSeconds)) { row in
                connectionCell(alignment: .trailing) {
                    Text(durationText(row))
                        .font(.system(size: 11.5, design: .monospaced))
                        .foregroundStyle(palette.textFaint)
                }
            }
            .width(min: 70, ideal: 90, max: 130)
        }
        .tableStyle(.inset(alternatesRowBackgrounds: false))
        .frame(maxHeight: .infinity)
    }

    private func connectionCell<Content: View>(alignment: Alignment = .leading, @ViewBuilder content: () -> Content) -> some View {
        content()
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .frame(maxWidth: .infinity, alignment: alignment)
    }

    private func byteText(_ bytes: UInt64) -> String {
        let scaled = scaledByteUnit(Double(bytes))
        return "\(scaled.value) \(scaled.unit)"
    }

    /// Active rows recompute against `Date()` each time `store.liveConnections`
    /// changes -- driven by `AppStore`'s once-a-second connections poll, so
    /// this refreshes on the same cadence without a timer of its own.
    private func durationText(_ row: ConnectionInfo) -> String {
        let total = Int(row.durationSeconds.rounded())
        if total < 60 { return "\(total)s" }
        let minutes = total / 60
        if minutes < 60 { return "\(minutes)m \(total % 60)s" }
        let hours = minutes / 60
        return "\(hours)h \(minutes % 60)m"
    }
}
