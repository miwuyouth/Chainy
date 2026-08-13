import SwiftUI
import AppKit
import ProxyKit

/// Shows `AppStore.logEntries` -- the in-memory mirror of `ProxyLog.shared`,
/// the process-wide sink every layer (the local SOCKS5/HTTP listener, each
/// relayed connection, chain-hop dialing, subscription refreshes) logs
/// through. The full history also lives on disk (see `AppStore.logFileURL`)
/// for anything that happened before this window was open, or in a past
/// launch.
struct LogsView: View {
    @EnvironmentObject var store: AppStore
    @Environment(\.dashboardPalette) private var palette
    var showTitle: Bool = true
    @State private var minimumLevel: LogLevel = .debug
    @State private var searchText = ""
    @State private var autoScroll = true
    @State private var showingClearConfirm = false

    private var filteredEntries: [LogEntry] {
        store.logEntries.filter { entry in
            guard entry.level >= minimumLevel else { return false }
            guard !searchText.isEmpty else { return true }
            return entry.message.localizedCaseInsensitiveContains(searchText)
                || entry.category.localizedCaseInsensitiveContains(searchText)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            header

            if store.logEntries.isEmpty {
                EmptyStateView(
                    title: "No log activity yet",
                    systemImage: "doc.text.magnifyingglass",
                    message: "Connect, test a chain, or refresh a subscription to see activity here."
                )
            } else if filteredEntries.isEmpty {
                EmptyStateView(
                    title: "No matching log lines",
                    systemImage: "line.3.horizontal.decrease.circle",
                    message: "Try a lower level filter or a different search term."
                )
            } else {
                Rectangle().fill(palette.border).frame(height: 1)
                logList
            }
        }
        .confirmationDialog(
            "Clear all logs?",
            isPresented: $showingClearConfirm,
            titleVisibility: .visible
        ) {
            Button("Clear", role: .destructive) { store.clearLogs() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This clears the in-memory log and the on-disk log file. This cannot be undone.")
        }
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                if showTitle {
                    Text("Logs")
                        .font(.largeTitle.bold())
                }
                Spacer()
                Toggle("Auto-scroll", isOn: $autoScroll)
                    .toggleStyle(.checkbox)
                Button {
                    revealLogFile()
                } label: {
                    Label("Reveal Log File", systemImage: "folder")
                }
                .disabled(store.logFileURL == nil)
                Button(role: .destructive) {
                    showingClearConfirm = true
                } label: {
                    Label("Clear", systemImage: "trash")
                }
                .disabled(store.logEntries.isEmpty)
            }

            HStack(spacing: 12) {
                Picker("Level", selection: $minimumLevel) {
                    Text("All").tag(LogLevel.debug)
                        .accessibilityIdentifier("logs.level.all")
                    Text("Info+").tag(LogLevel.info)
                        .accessibilityIdentifier("logs.level.info")
                    Text("Warnings+").tag(LogLevel.warn)
                        .accessibilityIdentifier("logs.level.warn")
                    Text("Errors").tag(LogLevel.error)
                        .accessibilityIdentifier("logs.level.error")
                }
                .pickerStyle(.segmented)
                .frame(width: 320)
                .labelsHidden()
                .accessibilityIdentifier("logs.levelPicker")

                TextField("Search messages", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("logs.searchField")
            }
        }
        .padding(.horizontal, showTitle ? 28 : 16)
        .padding(.top, showTitle ? 28 : 16)
        .padding(.bottom, 12)
    }

    private func revealLogFile() {
        guard let url = store.logFileURL else { return }
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    // MARK: - Log list

    private var logList: some View {
        ScrollViewReader { proxy in
            List(filteredEntries) { entry in
                LogRow(entry: entry)
                    .id(entry.id)
                    .listRowSeparator(.hidden)
            }
            .listStyle(.plain)
            // Without this, the first row sits flush against the divider
            // above -- easy to mistake for being cropped by it, especially
            // right after the list scrolls to bottom on appear.
            .padding(.top, 6)
            .onChange(of: filteredEntries.last?.id) { newValue in
                guard autoScroll, let newValue else { return }
                withAnimation(.easeOut(duration: 0.15)) {
                    proxy.scrollTo(newValue, anchor: .bottom)
                }
            }
            .onAppear {
                guard autoScroll, let lastID = filteredEntries.last?.id else { return }
                proxy.scrollTo(lastID, anchor: .bottom)
            }
        }
    }
}

private struct LogRow: View {
    let entry: LogEntry
    @Environment(\.dashboardPalette) private var palette

    private static let timeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        return formatter
    }()

    // Debug/info recede (they're the high-volume, routine chatter); warn/error
    // get a saturated badge color plus a tinted row wash + left edge stripe,
    // so the entries the "Warnings+"/"Errors" filter tabs care about are
    // visually distinct in the list, not just in text.
    private var levelColor: Color {
        switch entry.level {
        case .debug: return palette.textFaint
        case .info: return palette.accent
        case .warn: return palette.amber
        case .error: return palette.red
        }
    }

    private var levelBadgeBackground: Color {
        switch entry.level {
        case .debug: return palette.bgElevated
        case .info: return palette.accentDim
        case .warn: return palette.amberDim
        case .error: return palette.redDim
        }
    }

    private var rowWash: Color {
        switch entry.level {
        case .warn: return palette.amberDim.opacity(0.5)
        case .error: return palette.redDim.opacity(0.5)
        case .debug, .info: return .clear
        }
    }

    /// `AppStore`'s log calls consistently single-quote the chain/node/
    /// subscription name a line is about (`"Recorded '\(chain.name)': ..."`,
    /// `"Refreshing '\(subscription.name)'"`, etc.) -- the same accent color
    /// used on the "ACTIVE" badge elsewhere in the app, so the one thing a
    /// log line is *about* stands out from the surrounding chatter instead
    /// of blending into the same monospace gray as everything else. The
    /// quote characters themselves are dropped since the color now does
    /// that delimiting job.
    private var messageText: Text {
        var result = Text("")
        var current = ""
        var isInsideQuote = false

        func flush(accented: Bool) {
            guard !current.isEmpty else { return }
            let segment = Text(current)
            result = result + (accented ? segment.foregroundColor(palette.accent).fontWeight(.semibold) : segment)
            current = ""
        }

        let chars = Array(entry.message)
        for i in chars.indices {
            let char = chars[i]
            guard char == "'" else {
                current.append(char)
                continue
            }
            if isInsideQuote {
                let next = i + 1 < chars.count ? chars[i + 1] : nil
                if let next, next.isLetter {
                    // A contraction apostrophe *inside* the quoted name
                    // itself (e.g. a chain named "User's Chain") rather than
                    // that name's own closing delimiter -- a delimiting
                    // quote is always followed by a space, punctuation, or
                    // the end of the message, never a letter. Symmetric with
                    // the opening-quote rule below, but looking ahead
                    // instead of behind: it's the *next* character that
                    // tells a contraction apart from a delimiter on the
                    // closing side (checking the previous character here
                    // instead, like the opening side does, would wrongly
                    // reject nearly every real closing quote, since almost
                    // every name ends in a letter).
                    current.append(char)
                } else {
                    flush(accented: true)
                    isInsideQuote = false
                }
            } else if i > 0, chars[i - 1].isLetter {
                // A contraction apostrophe (e.g. "wasn't") rather than a
                // name delimiter -- delimiting quotes always follow a space
                // or the start of the message, never a letter.
                current.append(char)
            } else {
                flush(accented: false)
                isInsideQuote = true
            }
        }
        flush(accented: isInsideQuote)
        return result
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 9) {
            Text(Self.timeFormatter.string(from: entry.date))
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(palette.textDim)
                .frame(width: 84, alignment: .leading)
                .padding(.leading, 8)

            DashboardBadge(entry.level.rawValue.uppercased(), foreground: levelColor, background: levelBadgeBackground)
                .frame(width: 56, alignment: .leading)

            Text(entry.category)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(palette.textDim)
                .frame(width: 76, alignment: .leading)
                .lineLimit(1)

            messageText
                .font(.system(size: 11.5, design: .monospaced))
                .foregroundStyle(palette.text)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, 3)
        .padding(.trailing, 8)
        .background(rowWash, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
        .overlay(alignment: .leading) {
            if entry.level >= .warn {
                Rectangle().fill(levelColor).frame(width: 2.5)
            }
        }
    }
}
