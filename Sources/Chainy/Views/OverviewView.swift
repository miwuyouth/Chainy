import SwiftUI
import Charts
import AppKit
import ChainCore
import ProxyKit

/// The "Overview" panel from the Chainy Dashboard design: a single
/// Current Chain card split into a status / metrics / actions section by
/// hairline dividers. Every number here traces back to real `AppStore`
/// state -- no fabricated live numbers (see the `newgui` plan's "no
/// fabricated data" principle): unlike the mock, there's no fake per-hop
/// mini-test animation, since nothing instruments per-hop timing.
struct OverviewView: View {
    @EnvironmentObject var store: AppStore
    @Environment(\.dashboardPalette) private var palette
    @AppStorage("localProxyPort") private var configuredLocalProxyPort = 1080

    private var activeChain: NamedProxyChain? { store.settings.activeChain }

    private var activeChainScore: ChainQualityScore? {
        activeChain.flatMap { store.chainScores[$0.id] }
    }

    private var isRunningDiagnostics: Bool { store.isTesting || store.isTestingBandwidth }

    @State private var isHoveringConnect = false
    @State private var isHoveringRunTest = false
    @State private var copiedProxyLabel: String?
    @State private var isShowingSetupGuide = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                currentChainCard

                localProxyGuideCard

                trafficChartCard

                timeoutRateChartCard

                if let error = store.proxyError {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .font(.system(size: 12.5))
                        .foregroundStyle(palette.red)
                }
            }
            .padding(20)
        }
        .sheet(isPresented: $isShowingSetupGuide) {
            proxySetupGuide
        }
    }

    // MARK: - Local proxy onboarding

    /// Connecting Chainy starts a local listener; it does not automatically
    /// redirect macOS traffic. Keeping this instruction on Overview (rather
    /// than in a one-time welcome dialog) makes the required second step
    /// discoverable both on first use and whenever someone returns later.
    private var localProxyGuideCard: some View {
        DashboardCard(padding: 18) {
            HStack(alignment: .top, spacing: 16) {
                Image(systemName: proxyGuideIcon)
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(proxyGuideColor)
                    .frame(width: 38, height: 38)
                    .background(proxyGuideBackground, in: RoundedRectangle(cornerRadius: 10, style: .continuous))

                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        Text(proxyGuideTitle)
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(palette.text)
                        if store.hasDetectedProxyClient && store.isProxyRunning {
                            DashboardBadge("PROXY CLIENT DETECTED", foreground: palette.green, background: palette.greenDim)
                        }
                    }

                    Text(proxyGuideMessage)
                        .font(.system(size: 12.5))
                        .foregroundStyle(palette.textDim)
                        .fixedSize(horizontal: false, vertical: true)

                    if store.isProxyRunning {
                        proxyAddressRow(label: "SOCKS5 + HTTP")
                    }
                }

                Spacer(minLength: 12)

                Button("Setup Guide") {
                    isShowingSetupGuide = true
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }
        }
        .accessibilityIdentifier("overview.localProxyGuide")
    }

    private var proxyGuideTitle: String {
        if !store.isProxyRunning { return "Connect a chain to start the local proxy" }
        if store.hasDetectedProxyClient { return "Proxy client detected" }
        return "Chainy is ready — connect your apps"
    }

    private var proxyGuideMessage: String {
        if !store.isProxyRunning {
            return "Chainy creates a local SOCKS5/HTTP proxy. Select a chain and connect, then point your browser or macOS proxy settings to the address shown here."
        }
        if store.hasDetectedProxyClient {
            return "A local proxy client has reached Chainy. Its supported proxy requests will be relayed through the active chain."
        }
        return "Chainy is listening locally, but no proxy client has connected yet. Traffic will not use Chainy until your browser or macOS proxy is configured."
    }

    private var proxyGuideIcon: String {
        guard store.isProxyRunning else { return "1.circle.fill" }
        return store.hasDetectedProxyClient ? "checkmark.circle.fill" : "2.circle.fill"
    }

    private var proxyGuideColor: Color {
        store.hasDetectedProxyClient && store.isProxyRunning ? palette.green : palette.accent
    }

    private var proxyGuideBackground: Color {
        store.hasDetectedProxyClient && store.isProxyRunning ? palette.greenDim : palette.accentDim
    }

    private var localProxyAddress: String {
        "127.0.0.1:\(store.proxyListenPort.map(Int.init) ?? configuredLocalProxyPort)"
    }

    private func proxyAddressRow(label: String) -> some View {
        HStack(spacing: 7) {
            Text(label)
                .font(.system(size: 10.5, weight: .semibold))
                .foregroundStyle(palette.textFaint)
            Text(localProxyAddress)
                .font(.system(size: 11.5, design: .monospaced))
                .foregroundStyle(palette.text)
            Button {
                copyProxyAddress(label: label)
            } label: {
                Image(systemName: copiedProxyLabel == label ? "checkmark" : "doc.on.doc")
                    .font(.system(size: 10.5, weight: .medium))
            }
            .buttonStyle(.plain)
            .foregroundStyle(copiedProxyLabel == label ? palette.green : palette.accent)
            .help("Copy \(label) proxy address")
            .accessibilityLabel("Copy \(label) proxy address")
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(palette.bgElevated, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    }

    private func copyProxyAddress(label: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(localProxyAddress, forType: .string)
        copiedProxyLabel = label
        Task {
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            guard !Task.isCancelled, copiedProxyLabel == label else { return }
            copiedProxyLabel = nil
        }
    }

    private var proxySetupGuide: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Connect an app to Chainy")
                        .font(.system(size: 20, weight: .bold))
                    Text("Chainy supports SOCKS5 and HTTP on the same local address.")
                        .font(.system(size: 12.5))
                        .foregroundStyle(palette.textDim)
                }
                Spacer()
                Button("Done") { isShowingSetupGuide = false }
                    .keyboardShortcut(.defaultAction)
            }

            setupStep(number: "1", title: "Connect a chain", detail: "Choose a saved chain on Overview and click Connect.")
            setupStep(number: "2", title: "Configure your browser or macOS", detail: "Set its SOCKS5 or HTTP proxy server to \(localProxyAddress). Leave username and password empty.")
            setupStep(number: "3", title: "Confirm traffic", detail: "Return to Overview. The card turns green after Chainy detects the first client connection.")

            Text("To configure all macOS traffic: System Settings → Network → your active connection → Details → Proxies. Remember to turn those proxy settings off before disconnecting Chainy.")
                .font(.system(size: 12))
                .foregroundStyle(palette.textDim)
                .padding(12)
                .background(palette.amberDim, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        }
        .padding(24)
        .frame(width: 560)
        .background(palette.bgPanel)
    }

    private func setupStep(number: String, title: String, detail: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text(number)
                .font(.system(size: 12, weight: .bold))
                .foregroundStyle(palette.accent)
                .frame(width: 26, height: 26)
                .background(palette.accentDim, in: Circle())
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.system(size: 13.5, weight: .semibold))
                Text(detail).font(.system(size: 12.5)).foregroundStyle(palette.textDim)
            }
        }
    }

    // MARK: - Current chain (hero)

    /// The one card on this screen: what chain is active and whether it's
    /// connected (status), its live vitals (metrics), and the actions that
    /// operate on it (Run Test, Auto-Optimize) -- three sections separated
    /// by hairline dividers instead of three competing card surfaces. Only
    /// one accent-colored element is ever on screen at once: the outlined
    /// Connect/Disconnect button, blue when offering to connect and red
    /// when offering to disconnect -- so the card itself uses the plain
    /// `DashboardCard` border rather than a permanent accent tint.
    private var currentChainCard: some View {
        DashboardCard(padding: 20) {
            VStack(alignment: .leading, spacing: 16) {
                statusSection

                Rectangle().fill(palette.borderSoft).frame(height: 1)

                metricsRow

                Rectangle().fill(palette.borderSoft).frame(height: 1)

                actionsRow
            }
        }
    }

    // MARK: - Traffic chart

    /// Total upload/download throughput over the last ~10 minutes, summed
    /// across every chain and connection rather than broken out per-chain
    /// or per-node -- `AppStore.trafficHistory` deliberately keeps one
    /// combined session view instead of a per-source breakdown.
    private var trafficChartCard: some View {
        DashboardCard(padding: 20) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 10) {
                    Text("TRAFFIC")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(palette.textFaint)
                    Spacer()
                    trafficLegendSwatch(color: palette.accent, label: "Download")
                    trafficLegendSwatch(color: palette.accentSecondary, label: "Upload")
                }
                if store.trafficHistory.isEmpty {
                    Text("No traffic yet -- connect and relay some data to see it here.")
                        .font(.system(size: 12.5))
                        .foregroundStyle(palette.textFaint)
                        .frame(maxWidth: .infinity, minHeight: 140, alignment: .center)
                } else {
                    trafficChart
                }
            }
        }
    }

    /// Zero-based with a little headroom above the peak sample, rather than
    /// Swift Charts' default tight-fit domain -- a traffic graph that
    /// doesn't start at zero visually exaggerates small fluctuations into
    /// looking like major swings.
    private var trafficChartYDomain: ClosedRange<Double> {
        let peak = store.trafficHistory.reduce(0.0) { max($0, $1.uploadBytesPerSec, $1.downloadBytesPerSec) }
        return 0...max(peak * 1.15, 1024)
    }

    private func trafficLegendSwatch(color: Color, label: String) -> some View {
        HStack(spacing: 5) {
            Circle().fill(color).frame(width: 6, height: 6)
            Text(label).font(.system(size: 10.5)).foregroundStyle(palette.textFaint)
        }
    }

    /// "Long" form of `trafficHistory` -- one row per direction per tick,
    /// tagged rather than kept as two parallel arrays -- because a single
    /// `ForEach` with `.foregroundStyle(by:)` + `.chartForegroundStyleScale`
    /// is the pattern Swift Charts actually resolves reliably for a
    /// two-series line chart; two separate `ForEach`s each hardcoding a
    /// constant `.foregroundStyle(Color)` (the first version of this chart)
    /// rendered both series in whichever color happened to apply last.
    private struct TrafficPoint: Identifiable {
        let id = UUID()
        let date: Date
        let bytesPerSec: Double
        let direction: String
    }

    private var trafficPoints: [TrafficPoint] {
        store.trafficHistory.flatMap { sample in
            [
                TrafficPoint(date: sample.date, bytesPerSec: sample.downloadBytesPerSec, direction: "Download"),
                TrafficPoint(date: sample.date, bytesPerSec: sample.uploadBytesPerSec, direction: "Upload")
            ]
        }
    }

    private var trafficChart: some View {
        Chart(trafficPoints) { point in
            LineMark(
                x: .value("Time", point.date),
                y: .value("Bytes/s", point.bytesPerSec)
            )
            .foregroundStyle(by: .value("Direction", point.direction))
            // Dash on Upload only -- redundant encoding alongside color so
            // the two series are still distinguishable even where their
            // values sit close together.
            .lineStyle(StrokeStyle(lineWidth: 1.5, dash: point.direction == "Upload" ? [5, 3] : []))
            .interpolationMethod(.monotone)
        }
        .chartForegroundStyleScale(["Download": palette.accent, "Upload": palette.accentSecondary])
        .chartLegend(.hidden)
        .chartYScale(domain: trafficChartYDomain)
        .chartYAxis {
            AxisMarks { value in
                AxisGridLine().foregroundStyle(palette.borderSoft)
                AxisValueLabel {
                    if let bytes = value.as(Double.self) {
                        let scaled = scaledByteUnit(bytes)
                        Text("\(scaled.value)\(scaled.unit)/s")
                            .font(.system(size: 9.5))
                            .foregroundStyle(palette.textFaint)
                    }
                }
            }
        }
        .chartXAxis {
            AxisMarks(values: .stride(by: .minute, count: 2)) { _ in
                AxisGridLine().foregroundStyle(palette.borderSoft)
                AxisValueLabel(format: .dateTime.hour().minute())
            }
        }
        .frame(height: 140)
    }

    // MARK: - Timeout rate chart

    /// Companion to `trafficChartCard`, but a 1-minute rolling window per
    /// point rather than one instantaneous sample -- unlike bytes/sec, a
    /// single second rarely has more than one or two connection attempts,
    /// so an unsmoothed per-tick rate would just swing between 0% and 100%
    /// on tiny sample sizes. A minute-wide rolling window trades some
    /// responsiveness to a single isolated timeout for a line that actually
    /// reads as a trend.
    private var timeoutRateChartCard: some View {
        DashboardCard(padding: 20) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 10) {
                    Text("TIMEOUT RATE")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(palette.textFaint)
                    Spacer()
                    Text("1-min rolling window")
                        .font(.system(size: 10.5))
                        .foregroundStyle(palette.textFaint)
                }
                if store.timeoutRateHistory.isEmpty {
                    Text("No connection attempts yet -- connect and relay some traffic to see it here.")
                        .font(.system(size: 12.5))
                        .foregroundStyle(palette.textFaint)
                        .frame(maxWidth: .infinity, minHeight: 140, alignment: .center)
                } else {
                    timeoutRateChart
                }
            }
        }
    }

    /// Headroom above the peak sample like `trafficChartYDomain`, but with a
    /// 5%-of-scale floor instead of a byte-count floor -- so a mostly-healthy
    /// session (peak well under 5%) doesn't zoom in so far that ordinary
    /// jitter looks like a crisis, while a genuinely bad stretch still gets
    /// real headroom above its own peak. Capped at 100% since the rate can
    /// never exceed that.
    private var timeoutRateChartYDomain: ClosedRange<Double> {
        let peak = store.timeoutRateHistory.reduce(0.0) { max($0, $1.rate) }
        return 0...min(max(peak * 1.15, 0.05), 1.0)
    }

    private var timeoutRateChart: some View {
        Chart(store.timeoutRateHistory) { point in
            LineMark(
                x: .value("Time", point.date),
                y: .value("Timeout Rate", point.rate)
            )
            .foregroundStyle(palette.red)
            .interpolationMethod(.monotone)
        }
        .chartYScale(domain: timeoutRateChartYDomain)
        .chartYAxis {
            AxisMarks { value in
                AxisGridLine().foregroundStyle(palette.borderSoft)
                AxisValueLabel {
                    if let rate = value.as(Double.self) {
                        Text("\(Int((rate * 100).rounded()))%")
                            .font(.system(size: 9.5))
                            .foregroundStyle(palette.textFaint)
                    }
                }
            }
        }
        .chartXAxis {
            AxisMarks(values: .stride(by: .minute, count: 2)) { _ in
                AxisGridLine().foregroundStyle(palette.borderSoft)
                AxisValueLabel(format: .dateTime.hour().minute())
            }
        }
        .frame(height: 140)
    }

    private var statusSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 5) {
                Text("CURRENT CHAIN")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(palette.textFaint)
                HStack(spacing: 8) {
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text(activeChain?.name ?? "No active chain")
                            .font(.system(size: 22, weight: .bold))
                            .foregroundStyle(palette.text)
                        HStack(spacing: 5) {
                            DashboardDot(color: connectionStatusColor, size: 7)
                            Text(connectionStatusLabel)
                                .font(.system(size: 12.5, weight: .medium))
                                .foregroundStyle(palette.textDim)
                        }
                    }
                    Spacer(minLength: 12)
                    connectButton
                }
            }

            if let chain = activeChain, !chain.hops.isEmpty {
                hopStrip(chain)
            } else {
                Text("Build a chain in Chain Builder and activate it to see it here.")
                    .font(.system(size: 12.5))
                    .foregroundStyle(palette.textFaint)
            }
        }
    }

    /// Outlined rather than filled -- transparent background, colored
    /// stroke + text -- so it reads as the page's single accent element
    /// without competing with the solid surfaces around it. Red when it
    /// offers to disconnect, blue when it offers to connect.
    private var connectButton: some View {
        let isDisabled = !store.isProxyRunning && activeChain == nil
        let tint = store.isProxyRunning ? palette.red : palette.accent
        return Button {
            if store.isProxyRunning {
                store.disconnect()
            } else {
                Task { await store.connect() }
            }
        } label: {
            HStack(spacing: 6) {
                Image(systemName: store.isProxyRunning ? "bolt.slash.fill" : "bolt.fill")
                    .font(.system(size: 10.5, weight: .semibold))
                Text(store.isProxyRunning ? "Disconnect" : "Connect")
                    .font(.system(size: 12.5, weight: .semibold))
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 7)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundStyle(tint.opacity(isHoveringConnect ? 0.7 : 1))
        .overlay(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .strokeBorder(tint.opacity(isHoveringConnect ? 0.7 : 1), lineWidth: 1.25)
        )
        .disabled(isDisabled)
        .opacity(isDisabled ? 0.45 : 1)
        .hoverCursor($isHoveringConnect, enabled: !isDisabled)
    }

    private var connectionStatusColor: Color {
        guard store.isProxyRunning else { return palette.textFaint }
        return store.proxyError == nil ? palette.green : palette.red
    }

    private var connectionStatusLabel: String {
        guard store.isProxyRunning else { return "disconnected" }
        return store.proxyError == nil ? "connected" : "error"
    }

    // MARK: - Metrics row

    /// The four numbers that used to sit in their own bordered/shadowed
    /// tiles now share one row inside the chain card, separated by hairline
    /// dividers instead of four full card surfaces -- same data, way less
    /// chrome.
    private var metricsRow: some View {
        HStack(alignment: .top, spacing: 20) {
            metricItem(label: "Active Connections", value: "\(store.activeConnectionCount)", unit: "sessions")
            metricDivider
            latencyMetricItem
            metricDivider
            metricItem(label: "Bandwidth", value: bandwidthText, unit: bandwidthUnit, color: bandwidthColor)
            metricDivider
            throughputMetric
            metricDivider
            totalDataMetric
        }
    }

    private var metricDivider: some View {
        Rectangle().fill(palette.borderSoft).frame(width: 1)
    }

    private func metricItem(label: String, value: String, unit: String?, color: Color? = nil) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label.uppercased())
                .font(.system(size: 10.5, weight: .semibold))
                .foregroundStyle(palette.textFaint)
                .lineLimit(1)
                .minimumScaleFactor(0.6)
            HStack(alignment: .firstTextBaseline, spacing: 5) {
                Text(value)
                    .font(.system(size: 19, weight: .semibold, design: .monospaced))
                    .foregroundStyle(color ?? palette.text)
                    .lineLimit(1)
                    .minimumScaleFactor(0.5)
                if let unit {
                    Text(unit).font(.system(size: 11.5)).foregroundStyle(palette.textFaint)
                        .lineLimit(1)
                        .minimumScaleFactor(0.5)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var latencyMetricItem: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text("LATENCY")
                .font(.system(size: 10.5, weight: .semibold))
                .foregroundStyle(palette.textFaint)
                .lineLimit(1)
                .minimumScaleFactor(0.6)
            HStack(alignment: .firstTextBaseline, spacing: 5) {
                Text(latencyText)
                    .font(.system(size: 19, weight: .semibold, design: .monospaced))
                    .foregroundStyle(latencyColorForScore ?? palette.text)
                    .lineLimit(1)
                    .minimumScaleFactor(0.5)
                if let latencyUnit {
                    Text(latencyUnit).font(.system(size: 11.5)).foregroundStyle(palette.textFaint)
                        .lineLimit(1)
                        .minimumScaleFactor(0.5)
                }
            }
            if let udp = udpBadge {
                MetricBadge(text: udp.text, color: udp.color)
                    .help(udp.help)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// What to show for the active chain's last-known UDP capability, `nil`
    /// when it's never been tested (see
    /// `ChainQualityScore.udpSupported`/`udpLatencyMs`).
    private var udpBadge: (text: String, color: Color, help: String)? {
        guard let supported = activeChainScore?.udpSupported else { return nil }
        guard supported else {
            return ("NO UDP", palette.textFaint, "This chain's protocols don't support UDP forwarding.")
        }
        if let ms = activeChainScore?.udpLatencyMs {
            return ("UDP \(ms)ms", palette.accent, "Supports UDP forwarding -- last probe round-tripped in \(ms)ms.")
        }
        return ("UDP timeout", palette.amber, "Supports UDP forwarding, but the last probe got no reply.")
    }

    private var throughputMetric: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text("DOWN / UP")
                .font(.system(size: 10.5, weight: .semibold))
                .foregroundStyle(palette.textFaint)
                .lineLimit(1)
                .minimumScaleFactor(0.6)
            VStack(alignment: .leading, spacing: 3) {
                throughputValue(arrow: "arrow.down", value: downloadRateDisplay.value, unit: downloadRateDisplay.unit)
                throughputValue(arrow: "arrow.up", value: uploadRateDisplay.value, unit: uploadRateDisplay.unit)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// Cumulative total since the app launched (`AppStore.totalUploadBytes`/
    /// `totalDownloadBytes`), summed across every chain rather than tracked
    /// per-chain -- unlike `throughputMetric`'s live rate, this keeps
    /// counting across disconnects and across switching to a different
    /// chain, only resetting when the app quits.
    private var totalDataMetric: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text("TOTAL DOWN / UP")
                .font(.system(size: 10.5, weight: .semibold))
                .foregroundStyle(palette.textFaint)
                .lineLimit(1)
                .minimumScaleFactor(0.6)
            VStack(alignment: .leading, spacing: 3) {
                throughputValue(arrow: "arrow.down", value: totalDownloadDisplay.value, unit: totalDownloadDisplay.unit)
                throughputValue(arrow: "arrow.up", value: totalUploadDisplay.value, unit: totalUploadDisplay.unit)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func rateDisplay(_ bytesPerSecond: Double) -> (value: String, unit: String?) {
        guard store.isProxyRunning else { return ("—", nil) }
        let scaled = scaledByteUnit(bytesPerSecond)
        return (scaled.value, "\(scaled.unit)/s")
    }

    private var downloadRateDisplay: (value: String, unit: String?) { rateDisplay(store.downloadRateBytesPerSec) }
    private var uploadRateDisplay: (value: String, unit: String?) { rateDisplay(store.uploadRateBytesPerSec) }

    private func totalDisplay(_ bytes: UInt64) -> (value: String, unit: String?) {
        guard bytes > 0 else { return ("—", nil) }
        let scaled = scaledByteUnit(Double(bytes))
        return (scaled.value, scaled.unit)
    }

    private var totalDownloadDisplay: (value: String, unit: String?) { totalDisplay(store.totalDownloadBytes) }
    private var totalUploadDisplay: (value: String, unit: String?) { totalDisplay(store.totalUploadBytes) }

    private func throughputValue(arrow: String, value: String, unit: String? = nil) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 4) {
            Image(systemName: arrow)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(palette.textFaint)
            Text(value)
                .font(.system(size: 15, weight: .semibold, design: .monospaced))
                .foregroundStyle(palette.text)
                .lineLimit(1)
                .minimumScaleFactor(0.5)
            if let unit {
                Text(unit)
                    .font(.system(size: 11))
                    .foregroundStyle(palette.textFaint)
                    .lineLimit(1)
                    .minimumScaleFactor(0.5)
            }
        }
    }

    /// The probe measures round-trip time (send -> first response byte);
    /// halving it approximates one-way latency.
    private var latencyText: String {
        guard let ms = activeChainScore?.latencyMs else { return "—" }
        return "\(ms / 2)"
    }

    private var latencyUnit: String? { activeChainScore?.latencyMs != nil ? "ms" : nil }

    private var latencyColorForScore: Color? {
        guard let ms = activeChainScore?.latencyMs else { return nil }
        let oneWayMs = ms / 2
        return oneWayMs < 100 ? palette.green : oneWayMs < 200 ? palette.amber : palette.red
    }

    private var bandwidthText: String {
        guard let mbps = activeChainScore?.mbps else { return "—" }
        return String(format: "%.1f", mbps)
    }

    private var bandwidthUnit: String? { activeChainScore?.mbps != nil ? "Mb/s" : nil }

    /// `nil` (falls back to the card's default text color) when there's no
    /// reading yet, so the "—" placeholder never gets colored like real
    /// data -- same reasoning as `latencyColorForScore`.
    private var bandwidthColor: Color? {
        activeChainScore?.mbps != nil ? palette.green : nil
    }

    // MARK: - Actions row

    /// Replaces the old standalone Chain Diagnostics card: one line, two
    /// ends. Left is Run Test (outlined, not filled) with its last-run
    /// status trailing it in small gray text; right is Auto-Optimize as a
    /// short caption directly beside its switch, with no wrapping
    /// container around the pair.
    private var actionsRow: some View {
        HStack(spacing: 20) {
            HStack(spacing: 10) {
                runTestButton
                Text(diagnosticsSubtitle)
                    .font(.system(size: 12))
                    .foregroundStyle(diagnosticsSubtitleColor)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .help(diagnosticsFailureMessage ?? "")
            }

            Spacer(minLength: 12)

            HStack(spacing: 10) {
                Text("Auto-optimize · switches to fastest chain")
                    .font(.system(size: 12))
                    .foregroundStyle(palette.textFaint)
                Toggle("", isOn: $store.isAutoOptimizeEnabled)
                    .labelsHidden()
                    .toggleStyle(.switch)
                    .tint(palette.accent)
            }
        }
    }

    /// Neutral gray outline, not accent blue -- the Connect/Disconnect
    /// button is the page's one accent-colored element, so this secondary
    /// action stays quiet even though it's also outlined.
    private var runTestButton: some View {
        Button {
            runDiagnostics()
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "play.fill")
                    .font(.system(size: 9.5, weight: .semibold))
                Text(isRunningDiagnostics ? "Testing…" : "Run Test")
                    .font(.system(size: 12.5, weight: .semibold))
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 7)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundStyle(isHoveringRunTest ? palette.text : palette.textDim)
        .overlay(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .strokeBorder(isHoveringRunTest ? palette.textDim : palette.border, lineWidth: 1.25)
        )
        .disabled(activeChain == nil || isRunningDiagnostics)
        .opacity(activeChain == nil ? 0.45 : 1)
        .hoverCursor($isHoveringRunTest, enabled: activeChain != nil && !isRunningDiagnostics)
    }

    private var diagnosticsSubtitle: String {
        if let message = diagnosticsFailureMessage { return "Failed: \(message)" }
        guard let date = activeChainScore?.date else { return "Not tested yet" }
        return "Last run \(Self.timeFormatter.string(from: date))"
    }

    private var diagnosticsSubtitleColor: Color {
        diagnosticsFailureMessage == nil ? palette.textFaint : palette.red
    }

    /// The error message from whichever of `lastTestResult`/
    /// `lastBandwidthResult` most recently ran against the active chain, if
    /// that attempt failed -- `chainScores` (behind `activeChainScore`)
    /// only ever records successes, so without this a failed "Run Test"
    /// would leave the "Last run HH:mm:ss" caption pointing at whatever
    /// earlier attempt actually succeeded, with nothing on screen showing
    /// the most recent one just failed.
    private var diagnosticsFailureMessage: String? {
        guard let chain = activeChain else { return nil }
        let attempts: [(date: Date, success: Bool, message: String)] = [
            store.lastTestResult.flatMap { $0.chainName == chain.name ? (date: $0.date, success: $0.success, message: $0.message) : nil },
            store.lastBandwidthResult.flatMap { $0.chainName == chain.name ? (date: $0.date, success: $0.success, message: $0.message) : nil }
        ].compactMap { $0 }
        guard let latest = attempts.max(by: { $0.date < $1.date }), !latest.success else { return nil }
        return latest.message
    }

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    /// This strip is a static topology diagram -- it never responds to
    /// taps -- so its resting style previously looked indistinguishable
    /// from a disabled control. Tying its color to `isProxyRunning` gives
    /// the greyed-out look an actual meaning (idle path vs. live path)
    /// instead of leaving it as ambiguous default styling.
    private func hopStrip(_ chain: NamedProxyChain) -> some View {
        let isLive = store.isProxyRunning
        let lineColor = isLive ? palette.accent.opacity(0.5) : palette.border
        let labelColor = isLive ? palette.textDim : palette.textFaint
        let chipTextColor = isLive ? palette.accent : palette.textFaint
        let chipBorderColor = isLive ? palette.accent.opacity(0.4) : palette.borderSoft
        return ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                Text("CLIENT").font(.system(size: 10.5, weight: .semibold)).foregroundStyle(labelColor)
                ForEach(Array(chain.hops.enumerated()), id: \.offset) { _, hop in
                    Rectangle().fill(lineColor).frame(width: 16, height: 1.5)
                    VStack(spacing: 4) {
                        Text(hop.protocolConfig.displayName)
                            .font(.system(size: 9.5, weight: .bold))
                            .foregroundStyle(chipTextColor)
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 8)
                    .background(palette.bgElevated, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(chipBorderColor))
                }
                Rectangle().fill(lineColor).frame(width: 16, height: 1.5)
                Text("DESTINATION").font(.system(size: 10.5, weight: .semibold)).foregroundStyle(labelColor)
            }
        }
    }

    private func runDiagnostics() {
        guard let chain = activeChain, !isRunningDiagnostics else { return }
        Task {
            await store.testConnection(chain)
            await store.testBandwidth(chain)
        }
    }

}
