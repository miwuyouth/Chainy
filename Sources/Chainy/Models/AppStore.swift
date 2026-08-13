// AppStore.swift
//
// The GUI's single source of truth: wraps ChainCore's `ChainySettings`
// (saved chains) plus this target's own node library and subscription list,
// all persisted together to one JSON file under Application Support/
// Chainy. Every screen reads/mutates one shared instance handed down via
// `.environmentObject`.

import Foundation
import ChainCore
import SubscriptionCore
import ProxyKit

/// Everything AppStore persists, combined into the single JSON file on disk.
private struct AppData: Codable {
    var settings: ChainySettings
    var library: [LibraryNode]
    var subscriptions: [SavedSubscription]
    /// Optional (rather than defaulted) so `AppData.json` written before
    /// this field existed still decodes -- Swift's synthesized `Decodable`
    /// only tolerates a missing key for an `Optional` property, a default
    /// value alone isn't applied on decode (same reasoning as
    /// `LibraryNode.subscriptionID` below).
    var chainHopLinks: [ChainHopLinks]?
}

/// One saved chain's hop-to-library-node links, aligned index-for-index
/// with that chain's `NamedProxyChain.hops`. `NamedProxyChain` itself has
/// no room for this -- it's raw connection data ChainCore knows how to
/// dial, same reason `LibraryNode` lives here instead of in ChainCore.
/// Captured once in `ChainBuilderView.saveChain()` from each staged hop's
/// `libraryNodeID`, so `AppStore.resolvedLibraryNode` can look a hop's
/// node straight up instead of re-matching by `host`/`port` -- which
/// breaks the moment a subscription rotates its nodes' hosts on refresh.
private struct ChainHopLinks: Codable {
    var id: UUID
    var libraryNodeIDs: [UUID?]
}

/// A snapshot of the `UserDefaults`-backed preferences `SettingsView` binds
/// via `@AppStorage` (proxy port, LAN access, bandwidth/timeout tuning,
/// theme, etc.) plus `AppStore`'s own Auto-Optimize toggle/interval --
/// bundled into `AppBackup` alongside `AppData` so "Export Configuration"
/// carries over everything a fresh install would otherwise ask the user to
/// redo by hand, not just nodes/chains/subscriptions. Every field is
/// optional so a backup taken before a given preference existed -- or
/// written by a future version that dropped one -- still decodes and
/// imports whatever it does have.
private struct AppPreferences: Codable, Equatable {
    var showInMenuBar: Bool?
    var autoConnectOnLaunch: Bool?
    var systemNotificationsEnabled: Bool?
    var themePreference: String?
    var localProxyPort: Int?
    var allowLANConnections: Bool?
    var bandwidthTestSizeMB: Double?
    var bandwidthTestConcurrency: Int?
    var bandwidthTestTimeoutSeconds: Double?
    var connectionTestTimeoutSeconds: Double?
    var autoOptimizeEnabled: Bool?
    var autoOptimizeIntervalMinutes: Double?
}

/// The "Export Configuration" file format: everything `AppData` already
/// persists to disk (settings/library/subscriptions/chainHopLinks) plus
/// `AppPreferences`, so restoring one file on a fresh install reproduces
/// both the proxy config and the app's tuning. `formatVersion` is decoded
/// leniently (see `AppStore.importBackup`) rather than gating the whole
/// import on an exact match, so a future version can still read an older
/// export.
private struct AppBackup: Codable {
    var formatVersion: Int
    var settings: ChainySettings
    var library: [LibraryNode]
    var subscriptions: [SavedSubscription]
    var chainHopLinks: [ChainHopLinks]?
    var preferences: AppPreferences

    static let currentFormatVersion = 1
}

/// One reusable single-hop proxy server, kept in the library independent of
/// any chain that uses it. GUI-layer storage on top of ChainCore's
/// `ProxyHop` -- the Chains screen picks from this flat list (hand-typed or
/// imported from a subscription) when building an ordered chain. Not part
/// of `ChainySettings`' saved-chain schema, so it's kept as its own type
/// here rather than changing that already-tested format.
public struct LibraryNode: Codable, Equatable, Identifiable {
    public let id: UUID
    public var name: String
    public var hop: ProxyHop
    /// The subscription this node was imported from, if any -- `nil` for a
    /// hand-added node. Lets the Nodes screen filter its table down to one
    /// subscription's nodes. Optional so existing persisted library entries
    /// (saved before this field existed) decode with no migration needed.
    public var subscriptionID: UUID?

    public init(id: UUID = UUID(), name: String, hop: ProxyHop, subscriptionID: UUID? = nil) {
        self.id = id
        self.name = name
        self.hop = hop
        self.subscriptionID = subscriptionID
    }
}

/// A subscription URL the user has saved, plus bookkeeping from its most
/// recent refresh, refreshed by the Subscriptions screen.
public struct SavedSubscription: Codable, Equatable, Identifiable {
    public let id: UUID
    public var name: String
    public var urlString: String
    public var lastImportedAt: Date?
    public var lastImportedCount: Int?
    public var lastSkippedCount: Int?

    public init(
        id: UUID = UUID(),
        name: String,
        urlString: String,
        lastImportedAt: Date? = nil,
        lastImportedCount: Int? = nil,
        lastSkippedCount: Int? = nil
    ) {
        self.id = id
        self.name = name
        self.urlString = urlString
        self.lastImportedAt = lastImportedAt
        self.lastImportedCount = lastImportedCount
        self.lastSkippedCount = lastSkippedCount
    }
}

/// Small helpers for describing a `ProxyHopProtocol` in the UI.
extension ProxyHopProtocol {
    public var displayName: String {
        switch self {
        case .socks5: return "SOCKS5"
        case .shadowsocks: return "Shadowsocks"
        case .vmess: return "VMess"
        case .trojan: return "Trojan"
        case .vless: return "VLESS"
        case .http: return "HTTP"
        }
    }
}

/// The outcome of the last "test connection" run from the Dashboard.
public struct ConnectionTestResult: Equatable {
    public let chainName: String
    public let success: Bool
    public let message: String
    public let milliseconds: Int
    public let date: Date
}

/// The outcome of the last "test bandwidth" run from the Dashboard.
public struct BandwidthTestResult: Equatable {
    public let chainName: String
    public let success: Bool
    public let message: String
    public let mbps: Double
    public let bytesTransferred: Int
    public let date: Date
}

/// One throughput-sampling tick's upload/download rate, summed across
/// every chain and connection rather than attributed to any one of them --
/// this feeds Overview's traffic-over-time chart, which shows total
/// session traffic rather than a per-chain/per-node breakdown (see
/// `AppStore.trafficHistory`).
public struct TrafficSample: Identifiable, Equatable {
    public let id = UUID()
    public let date: Date
    public let uploadBytesPerSec: Double
    public let downloadBytesPerSec: Double
}

/// One tick's timeout rate over a short trailing window (see
/// `AppStore.timeoutRateChartWindow`) -- deliberately a much shorter lookback
/// than `timeoutRateSummary`'s ~10 minutes, so this chart reacts to a fresh
/// burst of timeouts within roughly a minute instead of that burst being
/// diluted across a long session's worth of healthy connections. `rate` is
/// the fraction (0...1) of relayed-connection attempts in that window that
/// failed with `ProxyError.timedOut`.
public struct TimeoutRateSample: Identifiable, Equatable {
    public let id = UUID()
    public let date: Date
    public let rate: Double
}

/// The current ~10-minute-window timeout rate for Overview's metric tile --
/// a longer, steadier lookback than `TimeoutRateSample`'s chart window, since
/// the tile is meant to answer "how healthy has this connection been lately"
/// rather than react to a single short burst. Carries the raw counts
/// alongside the rate so the tile can show both -- a lone percentage hides
/// whether it's 1/2 or 60/120.
public struct TimeoutRateSummary: Equatable {
    public let rate: Double
    public let timedOut: Int
    public let total: Int
}

/// A chain's most recently known latency/bandwidth reading and the combined
/// score derived from them, keyed by chain id (not name, unlike
/// `ConnectionTestResult`/`BandwidthTestResult` -- this persists per chain
/// rather than just remembering the single most recent test, so Auto-Optimize
/// can compare every saved chain against each other, and every saved chain's
/// row can show its own last-known numbers instead of just whichever one was
/// tested most recently). Filled in by a manual "Test Connection"/"Test
/// Bandwidth" tap just as much as by the background Auto-Optimize rotation --
/// either source updates the same record for a given chain.
public struct ChainQualityScore: Equatable {
    public let chainID: UUID
    public let latencyMs: Int?
    /// Time to establish the raw TCP connection to the first hop, `nil` when
    /// that instant isn't separately observable (see `ProxyChain.open`'s
    /// `onTCPConnected` doc comment -- a fresh Trojan first hop negotiates
    /// TCP+TLS as one atomic step).
    public let tcpMs: Int?
    /// Time until every hop's handshake has completed and the tunnel is
    /// ready to relay -- always `>= tcpMs` and `<= latencyMs`, the latter
    /// also counting the probe request/response round trip on top.
    public let handshakeMs: Int?
    public let mbps: Double?
    /// Whether this chain's hop protocols can carry UDP at all, per
    /// `ProxyChain.openUDPRelay`'s dispatch (Shadowsocks-all/VMess/VLESS/
    /// Trojan last hop) -- `nil` means never tested, `false` means the
    /// chain shape itself refuses UDP (e.g. HTTP or SOCKS5 as the last hop),
    /// `true` means the protocol allows it, independent of whether
    /// `udpLatencyMs` below actually got a reply.
    public let udpSupported: Bool?
    /// Round-trip time for a UDP probe through the chain (a DNS query to a
    /// public resolver, see `performUDPProbe`), `nil` whenever `udpSupported`
    /// is `false`/`nil` or the probe didn't get a reply in time (a blocked
    /// path still leaves `udpSupported == true`, since the protocol itself
    /// supports UDP -- only the reply failed).
    public let udpLatencyMs: Int?
    public let date: Date
}

enum RefreshError: LocalizedError {
    case invalidURL, badResponse(Int), notText

    var errorDescription: String? {
        switch self {
        case .invalidURL: return "That's not a valid URL."
        case .badResponse(let code): return "Server returned HTTP \(code)."
        case .notText: return "Response wasn't readable text."
        }
    }
}

@MainActor
public final class AppStore: ObservableObject {
    @Published public var settings: ChainySettings {
        didSet { save() }
    }
    @Published public var library: [LibraryNode] {
        didSet { save() }
    }
    @Published public var subscriptions: [SavedSubscription] {
        didSet { save() }
    }

    /// Backing store for `hopLibraryNodeIDs`/`resolvedLibraryNode`, keyed by
    /// chain id. Not `@Published` -- nothing reads it directly off the
    /// object graph, only through those two accessors -- so `addChain`/
    /// `updateChain`/`deleteChain` set it explicitly before touching
    /// `settings`, whose own `didSet` above triggers the actual `save()`.
    private var chainHopLinks: [UUID: [UUID?]] = [:]

    @Published public var isTesting = false
    @Published public var lastTestResult: ConnectionTestResult?
    @Published public var isTestingBandwidth = false
    @Published public var lastBandwidthResult: BandwidthTestResult?

    /// Every saved chain's most recent latency/bandwidth/score, keyed by
    /// chain id. Populated by manual tests and by the Auto-Optimize
    /// background rotation alike (see `recordChainScore`).
    @Published public private(set) var chainScores: [UUID: ChainQualityScore] = [:]

    /// Persisted (via `UserDefaults`, like the other user-facing toggles in
    /// SettingsView) rather than in `AppData`/`ChainySettings`, since it's
    /// a GUI-only preference, not something ChainCore's saved-chain format
    /// needs to know about. Turning this on/off drives the background
    /// rotation directly (see the `didSet` below) rather than requiring a
    /// separate "start" action.
    @Published public var isAutoOptimizeEnabled: Bool {
        didSet {
            UserDefaults.standard.set(isAutoOptimizeEnabled, forKey: Self.autoOptimizeEnabledDefaultsKey)
            if isAutoOptimizeEnabled {
                startAutoOptimizeLoop()
            } else {
                stopAutoOptimizeLoop()
            }
        }
    }

    /// How often Auto-Optimize tests the next chain in its rotation, in
    /// minutes. One chain per tick, not all of them at once -- see
    /// `runAutoOptimizeCycle`.
    @Published public var autoOptimizeIntervalMinutes: Double {
        didSet {
            UserDefaults.standard.set(autoOptimizeIntervalMinutes, forKey: Self.autoOptimizeIntervalDefaultsKey)
        }
    }

    @Published public var refreshingSubscriptionIDs: Set<UUID> = []
    @Published public var lastRefreshMessage: [UUID: String] = [:]

    /// Each library node's most recent reachability probe, keyed by node id
    /// -- `nil` means the probe ran and failed (unreachable); an absent key
    /// means it's never been tested. Populated by `testNode`/`testAllNodes`,
    /// the source for the Nodes table's latency column and Chain Builder's
    /// per-hop latency hints.
    @Published public private(set) var nodeLatencyMs: [UUID: Int?] = [:]
    /// Why the most recent probe in `nodeLatencyMs` came back unreachable,
    /// keyed by node id -- the raw thrown error's description (timeout,
    /// connection refused, TLS failure, etc.), not a hand-rolled category,
    /// so nothing gets lost translating it for display. Absent whenever the
    /// node hasn't been tested or its last test succeeded.
    @Published public private(set) var nodeTestFailureReason: [UUID: String] = [:]
    @Published public private(set) var testingNodeIDs: Set<UUID> = []

    @Published public private(set) var isProxyRunning = false
    @Published public private(set) var proxyListenPort: UInt16?
    /// Live count of currently-relaying connections through the local
    /// SOCKS5 proxy -- mirrors `LocalProxyServer`'s own count via a
    /// callback (same shape as `onUnexpectedStop` below), so Overview's
    /// "Active Connections" stat is real instead of a placeholder.
    @Published public private(set) var activeConnectionCount = 0
    /// Currently-relaying connections, one entry per accepted local socket --
    /// polled from `LocalProxyServer.snapshotConnections()` on the same
    /// once-a-second cadence as the throughput/timeout samples below. Feeds
    /// the Connections panel's "Active" toggle.
    @Published public private(set) var liveConnections: [ConnectionInfo] = []
    /// Bounded history of finished connections (see
    /// `LocalProxyServer.closedConnections`) -- feeds the Connections
    /// panel's "Closed" toggle. Reset when a new `connect()` starts a fresh
    /// session; left alone across a plain `disconnect()` so the history of
    /// what just happened is still visible.
    @Published public private(set) var closedConnections: [ConnectionInfo] = []
    /// Whether the *currently running* listener is bound to every interface
    /// (LAN-reachable) or just loopback -- snapshotted from the
    /// `allowLANConnections` setting at `connect()` time, since flipping the
    /// setting mid-session doesn't retroactively rebind an already-running
    /// listener (same as `localProxyPort`).
    @Published public private(set) var isProxyBoundToLAN = false
    @Published public var proxyError: String?

    /// Real-time download/upload throughput (bytes/sec) for whatever's
    /// actually relaying through the local proxy right now, derived by
    /// `throughputSamplingTask` polling `LocalProxyServer.snapshotByteCounts()`
    /// roughly once a second and dividing the delta by elapsed time --
    /// the source for Overview's "Live Throughput" stat. Zeroed by
    /// `stopThroughputSampling()` whenever the proxy isn't running.
    @Published public private(set) var downloadRateBytesPerSec: Double = 0
    @Published public private(set) var uploadRateBytesPerSec: Double = 0
    private var throughputSamplingTask: Task<Void, Never>?

    /// Cumulative upload/download totals across every chain, kept in memory
    /// only (never persisted to `AppData.json`) so they naturally start
    /// over at zero on every app launch, but otherwise just keep growing --
    /// across disconnect/reconnect and across switching the active chain
    /// (see `recordDataUsage`, called from `startThroughputSampling`'s
    /// polling loop). One running total rather than kept per-chain: this is
    /// meant to read as "how much has this session relayed", not a
    /// per-chain breakdown.
    @Published public private(set) var totalUploadBytes: UInt64 = 0
    @Published public private(set) var totalDownloadBytes: UInt64 = 0

    /// Rolling window of recent throughput ticks (~10 minutes at the
    /// sampling loop's 1/sec cadence, see `Self.trafficHistoryLimit`)
    /// powering Overview's traffic-over-time chart. In memory only, like
    /// `totalUploadBytes`/`totalDownloadBytes` above -- restarts empty each
    /// launch, and keeps accumulating across disconnect/reconnect since a
    /// gap in the chart during a disconnect is itself real information.
    @Published public private(set) var trafficHistory: [TrafficSample] = []
    private static let trafficHistoryLimit = 600

    /// Rolling ~10-minute-window timeout rate for Overview's metric tile --
    /// `nil` whenever that window has seen zero relayed-connection attempts
    /// (nothing to divide by), same "nil means no data yet, not a real
    /// zero" convention as `bandwidthColor`. Cleared on disconnect, unlike
    /// `timeoutRateHistory` below, since -- like the live throughput rate --
    /// it answers "right now", not "show a gap for the disconnected span".
    @Published public private(set) var timeoutRateSummary: TimeoutRateSummary?
    /// Rolling ~10-minute chart history of the *short*-window (~1 minute,
    /// see `Self.timeoutRateChartWindow`) timeout rate, one point per
    /// sampling tick that had at least one connection attempt in that short
    /// window. In memory only, like `trafficHistory` -- keeps accumulating
    /// across disconnect/reconnect rather than resetting, so a gap in the
    /// chart during a disconnect is itself real information.
    @Published public private(set) var timeoutRateHistory: [TimeoutRateSample] = []
    private static let timeoutRateChartWindow: TimeInterval = 60

    /// Mirrors `ProxyLog.shared` (the process-wide sink every layer --
    /// `TCPListener`'s caller, `LocalProxyServer`, `ChainCore`'s
    /// `ProxyChain`, and this store itself -- logs through) into a
    /// `@Published` array so the Logs screen can just observe `AppStore`
    /// like every other screen does, instead of polling the log store
    /// directly.
    @Published public private(set) var logEntries: [LogEntry] = []
    private var logListenerID: UUID?
    private static let maxMirroredLogEntries = 2000

    public var logFileURL: URL? { ProxyLog.shared.fileURL }

    public let directoryURL: URL
    private let dataURL: URL
    private let localProxyServer = LocalProxyServer()

    private var autoOptimizeTask: Task<Void, Never>?
    private var autoOptimizeCursor = 0

    public convenience init() {
        self.init(directoryURL: Self.appSupportDirectory())
    }

    /// Test-only entry point: points persistence at an arbitrary directory
    /// (a temp dir, say) instead of the real per-user Application Support
    /// location `init()` uses -- so exercising `AppStore` in tests never
    /// reads or overwrites the developer's own real saved chains/library.
    init(directoryURL dir: URL) {
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        directoryURL = dir
        dataURL = dir.appendingPathComponent("AppData.json")

        let data = Self.loadJSON(AppData.self, from: dataURL)
        settings = data?.settings ?? ChainySettings()
        library = Self.deduplicatedByName(data?.library ?? [])
        subscriptions = data?.subscriptions ?? []
        chainHopLinks = Dictionary(uniqueKeysWithValues: (data?.chainHopLinks ?? []).map { ($0.id, $0.libraryNodeIDs) })

        // Assigning here -- as part of `init` -- does not itself trigger the
        // `didSet` above (Swift only calls property observers for *later*
        // assignments), so this can't accidentally kick off the background
        // loop before `self` is fully initialized. Resuming it if it was left
        // on from a previous launch is handled explicitly just below instead.
        isAutoOptimizeEnabled = UserDefaults.standard.object(forKey: Self.autoOptimizeEnabledDefaultsKey) as? Bool ?? false
        autoOptimizeIntervalMinutes = UserDefaults.standard.object(forKey: Self.autoOptimizeIntervalDefaultsKey) as? Double ?? Self.defaultAutoOptimizeIntervalMinutes

        logEntries = ProxyLog.shared.snapshot()
        logListenerID = ProxyLog.shared.addListener { [weak self] entry in
            Task { @MainActor in
                self?.appendLogEntry(entry)
            }
        }

        if isAutoOptimizeEnabled {
            startAutoOptimizeLoop()
        }
    }

    deinit {
        if let logListenerID {
            ProxyLog.shared.removeListener(logListenerID)
        }
        autoOptimizeTask?.cancel()
    }

    private func appendLogEntry(_ entry: LogEntry) {
        logEntries.append(entry)
        if logEntries.count > Self.maxMirroredLogEntries {
            logEntries.removeFirst(logEntries.count - Self.maxMirroredLogEntries)
        }
    }

    public func clearLogs() {
        ProxyLog.shared.clear()
        logEntries.removeAll()
    }

    // MARK: - Persistence helpers

    private static func appSupportDirectory() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        let dir = base.appendingPathComponent("Chainy", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func save() {
        let links = chainHopLinks
            .map { ChainHopLinks(id: $0.key, libraryNodeIDs: $0.value) }
            .sorted { $0.id.uuidString < $1.id.uuidString }
        Self.saveJSON(AppData(settings: settings, library: library, subscriptions: subscriptions, chainHopLinks: links), to: dataURL)
    }

    private static func loadJSON<T: Decodable>(_ type: T.Type, from url: URL) -> T? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(T.self, from: data)
    }

    private static func saveJSON<T: Encodable>(_ value: T, to url: URL) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(value) else { return }
        try? data.write(to: url, options: .atomic)
    }

    /// One-time cleanup for library data saved before `mergeIntoLibrary`
    /// matched by name: installs that refreshed a host-rotating subscription
    /// many times could have accumulated dozens of duplicate entries per
    /// node (same name, different host). Collapsing to one entry per name
    /// on load heals that without needing a manual reset.
    private static func deduplicatedByName(_ nodes: [LibraryNode]) -> [LibraryNode] {
        var seenNames = Set<String>()
        return nodes.filter { seenNames.insert($0.name).inserted }
    }

    // MARK: - Nodes

    public func addNode(_ node: LibraryNode) {
        library.append(node)
    }

    public func updateNode(_ node: LibraryNode) {
        guard let index = library.firstIndex(where: { $0.id == node.id }) else { return }
        library[index] = node
    }

    public func deleteNodes(at offsets: IndexSet) {
        library.remove(atOffsets: offsets)
    }

    public func deleteNode(_ node: LibraryNode) {
        library.removeAll { $0.id == node.id }
        nodeLatencyMs.removeValue(forKey: node.id)
        nodeTestFailureReason.removeValue(forKey: node.id)
    }

    /// Resolves a saved chain's hop back to the library node it came from,
    /// for display (the Saved Chains route summary, and re-linking a hop
    /// when a chain is loaded back into the builder). `linkedID` is the
    /// hop's persisted `chainHopLinks` entry -- captured once in
    /// `ChainBuilderView.saveChain()` from `StagedHop.libraryNodeID`, the
    /// same field the builder already uses to track a staged hop's origin
    /// while editing -- so this is a direct, unambiguous lookup for any
    /// chain saved after that linking existed, immune to a subscription
    /// rotating every node's `host` on refresh.
    ///
    /// For a chain saved *before* that linking existed (no persisted
    /// `linkedID`), falls back to an exact host+port match, then to a
    /// port-only match if the port uniquely identifies one library node --
    /// mirrors `deduplicatedByName`'s self-heal-on-load approach for the
    /// library itself. An ambiguous port match is skipped rather than
    /// risking the wrong node's name.
    public func resolvedLibraryNode(for hop: ProxyHop, linkedID: UUID?) -> LibraryNode? {
        if let linkedID, let linked = library.first(where: { $0.id == linkedID }) {
            return linked
        }
        if let exact = library.first(where: { $0.hop.host == hop.host && $0.hop.port == hop.port }) {
            return exact
        }
        let portMatches = library.filter { $0.hop.port == hop.port }
        return portMatches.count == 1 ? portMatches[0] : nil
    }

    /// The per-hop library-node links captured for `chainID` at save time
    /// (see `resolvedLibraryNode`), aligned index-for-index with that
    /// chain's `hops`. Empty for a chain saved before this linking existed.
    public func hopLibraryNodeIDs(forChainID chainID: UUID) -> [UUID?] {
        chainHopLinks[chainID] ?? []
    }

    /// `resolvedLibraryNode(for:linkedID:)` applied across every hop in
    /// `chain`, one result per hop in order -- the actual per-call site
    /// need (a route summary, or re-linking staged hops) is always "the
    /// whole chain's hops resolved," so this is what callers use instead
    /// of each re-deriving `linkedID` by bounds-checking
    /// `hopLibraryNodeIDs` against `chain.hops` themselves.
    public func resolvedLibraryNodes(for chain: NamedProxyChain) -> [LibraryNode?] {
        let links = hopLibraryNodeIDs(forChainID: chain.id)
        return chain.hops.enumerated().map { index, hop in
            let linkedID = links.indices.contains(index) ? links[index] : nil
            return resolvedLibraryNode(for: hop, linkedID: linkedID)
        }
    }

    /// Probes one library node's own reachability by dialing straight
    /// through it -- a one-hop chain -- to the same real, known-reachable
    /// target `performLatencyProbe` uses for whole-chain tests. Real
    /// latency in, real latency (or `nil` on failure) out; no fabricated
    /// numbers. Source for the Nodes table's latency column and Overview's
    /// "Healthy Nodes" count.
    public func testNode(_ node: LibraryNode) async {
        guard !testingNodeIDs.contains(node.id) else { return }
        testingNodeIDs.insert(node.id)
        defer { testingNodeIDs.remove(node.id) }

        do {
            let start = Date()
            let timeout = Self.configuredConnectionTestTimeoutSeconds()
            let transport = try await ProxyChain.open(
                hops: [node.hop],
                finalTargetHost: Self.testTargetHost,
                finalTargetPort: Self.testTargetPort,
                connectTimeout: timeout
            )
            try await transport.send(Self.testProbeRequest, timeout: timeout)
            _ = try await transport.readAvailable(timeout: timeout)
            transport.close()
            nodeLatencyMs[node.id] = Int(Date().timeIntervalSince(start) * 1000)
            nodeTestFailureReason[node.id] = nil
        } catch {
            nodeLatencyMs[node.id] = .some(nil)
            nodeTestFailureReason[node.id] = "\(error)"
            proxyLog(.warn, "Store", "Node test failed for '\(node.name)': \(error)")
        }
    }

    public func testAllNodes() {
        for node in library {
            Task { await testNode(node) }
        }
    }

    // MARK: - Chains

    public func addChain(_ chain: NamedProxyChain, hopLibraryNodeIDs: [UUID?] = []) {
        chainHopLinks[chain.id] = hopLibraryNodeIDs
        settings.chains.append(chain)
        if settings.activeChainID == nil {
            settings.activeChainID = chain.id
        }
    }

    public func updateChain(_ chain: NamedProxyChain, hopLibraryNodeIDs: [UUID?] = []) {
        guard let index = settings.chains.firstIndex(where: { $0.id == chain.id }) else { return }
        chainHopLinks[chain.id] = hopLibraryNodeIDs
        settings.chains[index] = chain
        if isProxyRunning, settings.activeChainID == chain.id {
            localProxyServer.updateHops(chain.hops, chainName: chain.name)
        }
    }

    public func deleteChain(_ chain: NamedProxyChain) {
        chainHopLinks.removeValue(forKey: chain.id)
        settings.chains.removeAll { $0.id == chain.id }
        if settings.activeChainID == chain.id {
            settings.activeChainID = settings.chains.first?.id
        }
        syncRunningProxyToActiveChain()
    }

    /// Switching (or clearing) the active chain while the local proxy is
    /// running never drops what's already relaying -- it just retargets
    /// *new* connections to the newly-active chain's hops (see
    /// `LocalProxyServer.updateHops`). Only disconnects outright if there's
    /// no chain left to relay through at all.
    public func setActiveChain(_ id: UUID?) {
        settings.activeChainID = id
        syncRunningProxyToActiveChain()
    }

    private func syncRunningProxyToActiveChain() {
        guard isProxyRunning else { return }
        if let chain = settings.activeChain {
            localProxyServer.updateHops(chain.hops, chainName: chain.name)
        } else {
            disconnect()
        }
    }

    // MARK: - Subscriptions

    public func addSubscription(name: String, urlString: String) {
        subscriptions.append(SavedSubscription(name: name, urlString: urlString))
    }

    /// Parses one-or-more raw `vmess://`/`vless://`/`ss://`/`trojan://`/
    /// `http://` share links (as opposed to a subscription URL to fetch) and
    /// merges them straight into the library. Unlike `refresh`, this never
    /// touches the network and doesn't create a `SavedSubscription` -- a
    /// pasted share link has no server to re-fetch from later, so there's
    /// nothing to attach the imported nodes to.
    @discardableResult
    public func importRawNodes(_ text: String) -> SubscriptionParseResult {
        let result = SubscriptionParser.parse(text)
        mergeIntoLibrary(result.nodes, subscriptionID: nil)
        return result
    }

    public func deleteSubscription(_ subscription: SavedSubscription) {
        subscriptions.removeAll { $0.id == subscription.id }
        let orphanedNodeIDs = library.filter { $0.subscriptionID == subscription.id }.map(\.id)
        library.removeAll { $0.subscriptionID == subscription.id }
        for id in orphanedNodeIDs {
            nodeLatencyMs.removeValue(forKey: id)
            nodeTestFailureReason.removeValue(forKey: id)
        }
    }

    @discardableResult
    public func refresh(_ subscription: SavedSubscription) async -> Result<SubscriptionParseResult, Error> {
        refreshingSubscriptionIDs.insert(subscription.id)
        defer { refreshingSubscriptionIDs.remove(subscription.id) }

        proxyLog(.info, "Subscription", "Refreshing '\(subscription.name)'")
        do {
            guard let url = URL(string: subscription.urlString), url.scheme != nil else {
                throw RefreshError.invalidURL
            }
            let (data, response) = try await URLSession.shared.data(from: url)
            if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
                throw RefreshError.badResponse(http.statusCode)
            }
            guard let text = String(data: data, encoding: .utf8) else {
                throw RefreshError.notText
            }

            let result = SubscriptionParser.parse(text)
            mergeIntoLibrary(result.nodes, subscriptionID: subscription.id)

            if let index = subscriptions.firstIndex(where: { $0.id == subscription.id }) {
                subscriptions[index].lastImportedAt = Date()
                subscriptions[index].lastImportedCount = result.nodes.count
                subscriptions[index].lastSkippedCount = result.skipped.count
            }
            lastRefreshMessage[subscription.id] = "Imported \(result.nodes.count), skipped \(result.skipped.count)."
            proxyLog(.info, "Subscription", "Refreshed '\(subscription.name)': imported \(result.nodes.count), skipped \(result.skipped.count)")
            return .success(result)
        } catch {
            let message = (error as? LocalizedError)?.errorDescription ?? "\(error)"
            lastRefreshMessage[subscription.id] = message
            proxyLog(.warn, "Subscription", "Refresh failed for '\(subscription.name)': \(message)")
            return .failure(error)
        }
    }

    /// Matches by name, not host/port: some providers rotate a node's
    /// host to a freshly randomized subdomain on every subscription fetch
    /// (anti-DPI obfuscation) while keeping the same password/port and
    /// display name, so host+port equality would treat every refresh as a
    /// brand new node and pile up duplicates instead of updating in place.
    private func mergeIntoLibrary(_ nodes: [SubscriptionNode], subscriptionID: UUID?) {
        for node in nodes {
            if let index = library.firstIndex(where: { $0.name == node.name }) {
                library[index].name = node.name
                library[index].hop = node.hop
                library[index].subscriptionID = subscriptionID
            } else {
                library.append(LibraryNode(name: node.name, hop: node.hop, subscriptionID: subscriptionID))
            }
        }
    }

    // MARK: - Backup / Import & Export

    /// Bundles everything `AppData.json` already persists (settings/library/
    /// subscriptions/chainHopLinks) plus the `UserDefaults`-backed
    /// preferences from `SettingsView` into one JSON blob a user can save on
    /// this machine and restore on a new one via "Import Configuration" --
    /// see `SettingsView`'s Backup section. Reuses `saveJSON`'s encoder
    /// settings (pretty-printed, sorted keys, ISO8601 dates) so the exported
    /// file reads the same as `AppData.json` itself.
    public func exportBackupData() -> Data? {
        let links = chainHopLinks
            .map { ChainHopLinks(id: $0.key, libraryNodeIDs: $0.value) }
            .sorted { $0.id.uuidString < $1.id.uuidString }
        let backup = AppBackup(
            formatVersion: AppBackup.currentFormatVersion,
            settings: settings,
            library: library,
            subscriptions: subscriptions,
            chainHopLinks: links,
            preferences: currentPreferences()
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try? encoder.encode(backup)
    }

    /// Replaces every saved chain, node, subscription, and preference with
    /// what's in `data` -- the inverse of `exportBackupData()`. Returns
    /// `false` (leaving the current data untouched) if `data` isn't a
    /// decodable backup, so `SettingsView` can tell the user the file was
    /// invalid rather than silently wiping their config. Callers are
    /// expected to confirm with the user first, same as "Reset All Data" --
    /// this itself performs no confirmation.
    @discardableResult
    public func importBackup(from data: Data) -> Bool {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let backup = try? decoder.decode(AppBackup.self, from: data) else { return false }
        // Set before `settings`/`library`/`subscriptions` below so their
        // `didSet` (see `save()`) writes the freshly-imported links, not the
        // stale ones from before the import.
        chainHopLinks = Dictionary(uniqueKeysWithValues: (backup.chainHopLinks ?? []).map { ($0.id, $0.libraryNodeIDs) })
        settings = backup.settings
        library = Self.deduplicatedByName(backup.library)
        subscriptions = backup.subscriptions
        applyPreferences(backup.preferences)
        return true
    }

    private func currentPreferences() -> AppPreferences {
        let d = UserDefaults.standard
        return AppPreferences(
            showInMenuBar: d.object(forKey: "showInMenuBar") as? Bool,
            autoConnectOnLaunch: d.object(forKey: "autoConnectOnLaunch") as? Bool,
            systemNotificationsEnabled: d.object(forKey: SystemNotifier.enabledDefaultsKey) as? Bool,
            themePreference: d.string(forKey: "themePreference"),
            localProxyPort: d.object(forKey: "localProxyPort") as? Int,
            allowLANConnections: d.object(forKey: "allowLANConnections") as? Bool,
            bandwidthTestSizeMB: d.object(forKey: "bandwidthTestSizeMB") as? Double,
            bandwidthTestConcurrency: d.object(forKey: "bandwidthTestConcurrency") as? Int,
            bandwidthTestTimeoutSeconds: d.object(forKey: "bandwidthTestTimeoutSeconds") as? Double,
            connectionTestTimeoutSeconds: d.object(forKey: "connectionTestTimeoutSeconds") as? Double,
            autoOptimizeEnabled: d.object(forKey: Self.autoOptimizeEnabledDefaultsKey) as? Bool,
            autoOptimizeIntervalMinutes: d.object(forKey: Self.autoOptimizeIntervalDefaultsKey) as? Double
        )
    }

    /// Writes preferences straight to `UserDefaults` (picked up automatically
    /// by every `@AppStorage`-bound control in `SettingsView`) except for the
    /// two Auto-Optimize fields, which go through `self.isAutoOptimizeEnabled`/
    /// `self.autoOptimizeIntervalMinutes` instead so their own `didSet`
    /// (persisting *and* starting/stopping the background loop) fires the
    /// same as any other change to them would.
    private func applyPreferences(_ prefs: AppPreferences) {
        let d = UserDefaults.standard
        if let v = prefs.showInMenuBar { d.set(v, forKey: "showInMenuBar") }
        if let v = prefs.autoConnectOnLaunch { d.set(v, forKey: "autoConnectOnLaunch") }
        if let v = prefs.systemNotificationsEnabled { d.set(v, forKey: SystemNotifier.enabledDefaultsKey) }
        if let v = prefs.themePreference { d.set(v, forKey: "themePreference") }
        if let v = prefs.localProxyPort { d.set(v, forKey: "localProxyPort") }
        if let v = prefs.allowLANConnections { d.set(v, forKey: "allowLANConnections") }
        if let v = prefs.bandwidthTestSizeMB { d.set(v, forKey: "bandwidthTestSizeMB") }
        if let v = prefs.bandwidthTestConcurrency { d.set(v, forKey: "bandwidthTestConcurrency") }
        if let v = prefs.bandwidthTestTimeoutSeconds { d.set(v, forKey: "bandwidthTestTimeoutSeconds") }
        if let v = prefs.connectionTestTimeoutSeconds { d.set(v, forKey: "connectionTestTimeoutSeconds") }
        if let v = prefs.autoOptimizeEnabled { isAutoOptimizeEnabled = v }
        if let v = prefs.autoOptimizeIntervalMinutes { autoOptimizeIntervalMinutes = v }
    }

    // MARK: - Local SOCKS5/HTTP proxy

    /// Starts the local mixed SOCKS5/HTTP listener (see `LocalProxyServer`),
    /// relaying through the currently-active chain. No-ops if already running
    /// or if there's no active chain to relay through.
    public func connect() async {
        guard !isProxyRunning, let chain = settings.activeChain else { return }
        proxyError = nil
        let allowLAN = Self.configuredAllowLAN()
        proxyLog(.info, "Store", "Connect requested using chain '\(chain.name)'\(allowLAN ? " (LAN connections allowed)" : "")")
        do {
            let port = try await localProxyServer.start(
                port: Self.configuredLocalProxyPort(),
                hops: chain.hops,
                chainName: chain.name,
                allowLAN: allowLAN,
                onUnexpectedStop: { [weak self] error in
                    Task { @MainActor in
                        self?.isProxyRunning = false
                        self?.proxyListenPort = nil
                        self?.activeConnectionCount = 0
                        self?.proxyError = "\(error)"
                        self?.stopThroughputSampling()
                        SystemNotifier.post(title: "Chainy Disconnected", body: "The proxy stopped unexpectedly: \(error)")
                    }
                },
                onConnectionCountChanged: { [weak self] count in
                    Task { @MainActor in
                        self?.activeConnectionCount = count
                    }
                }
            )
            isProxyRunning = true
            proxyListenPort = port
            isProxyBoundToLAN = allowLAN
            startThroughputSampling()
            SystemNotifier.post(title: "Chainy Connected", body: "Relaying through '\(chain.name)' on \(proxyHostDescription(allowLAN: allowLAN)):\(port) (SOCKS5 + HTTP)")
        } catch TCPListenerError.portInUse {
            proxyError = "Port \(Self.configuredLocalProxyPort()) is already in use."
            proxyLog(.error, "Store", proxyError!)
            SystemNotifier.post(title: "Chainy Connection Failed", body: proxyError!)
        } catch {
            proxyError = "\(error)"
            proxyLog(.error, "Store", "Connect failed: \(error)")
            SystemNotifier.post(title: "Chainy Connection Failed", body: "\(error)")
        }
    }

    private func proxyHostDescription(allowLAN: Bool) -> String {
        guard allowLAN else { return "127.0.0.1" }
        return LocalNetworkAddress.primaryIPv4() ?? "0.0.0.0"
    }

    public func disconnect() {
        guard isProxyRunning else { return }
        proxyLog(.info, "Store", "Disconnect requested")
        localProxyServer.stop()
        isProxyRunning = false
        proxyListenPort = nil
        isProxyBoundToLAN = false
        activeConnectionCount = 0
        liveConnections = []
        stopThroughputSampling()
    }

    /// Polls `LocalProxyServer.snapshotByteCounts()` roughly once a second
    /// and turns the delta since the previous sample into a bytes/sec rate
    /// -- a poll rather than a per-chunk push so the hot relay path never
    /// touches the MainActor (see `LocalProxyServer.pumpBothDirections`'s
    /// doc comment on why that matters). Mirrors `startAutoOptimizeLoop`'s
    /// shape below.
    private func startThroughputSampling() {
        throughputSamplingTask?.cancel()
        throughputSamplingTask = Task { [weak self] in
            var lastCounts: (upload: UInt64, download: UInt64) = (0, 0)
            var lastSample = Date()
            // Raw cumulative (total, timedOut) connection-outcome snapshots,
            // oldest first, capped at the same ~10-minute span as
            // `trafficHistory` -- both `timeoutRateSummary`'s 10-minute
            // window and `timeoutRateHistory`'s per-tick 1-minute window are
            // deltas looked up against this one buffer, so they never
            // disagree about what actually happened in the overlapping part
            // of their windows.
            var outcomeSamples: [(date: Date, total: UInt64, timedOut: UInt64)] = []
            while let self, !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                guard !Task.isCancelled else { break }
                let now = Date()
                let elapsed = now.timeIntervalSince(lastSample)
                let counts = self.localProxyServer.snapshotByteCounts()
                let uploadDelta = counts.upload &- lastCounts.upload
                let downloadDelta = counts.download &- lastCounts.download
                if elapsed > 0 {
                    self.uploadRateBytesPerSec = Double(uploadDelta) / elapsed
                    self.downloadRateBytesPerSec = Double(downloadDelta) / elapsed
                }
                self.recordDataUsage(uploadDelta: uploadDelta, downloadDelta: downloadDelta)
                self.recordTrafficSample(date: now, uploadBps: self.uploadRateBytesPerSec, downloadBps: self.downloadRateBytesPerSec)
                lastCounts = counts
                lastSample = now

                let connections = self.localProxyServer.snapshotConnections()
                self.liveConnections = connections.active
                self.closedConnections = connections.closed

                let outcomeCounts = self.localProxyServer.snapshotConnectionOutcomeCounts()
                outcomeSamples.append((date: now, total: outcomeCounts.total, timedOut: outcomeCounts.timedOut))
                if outcomeSamples.count > Self.trafficHistoryLimit {
                    outcomeSamples.removeFirst(outcomeSamples.count - Self.trafficHistoryLimit)
                }
                self.recordTimeoutRateSummary(now: now, current: outcomeCounts, oldest: outcomeSamples.first!)
                // The freshest sample that's still at least a full window
                // old -- on an ascending-by-date array, `last(where:)` finds
                // that without scanning past it into fresher samples that'd
                // undershoot the window.
                let chartBase = outcomeSamples.last(where: { now.timeIntervalSince($0.date) >= Self.timeoutRateChartWindow }) ?? outcomeSamples.first!
                self.recordTimeoutRateSample(now: now, current: outcomeCounts, base: chartBase)
            }
        }
    }

    private func stopThroughputSampling() {
        throughputSamplingTask?.cancel()
        throughputSamplingTask = nil
        uploadRateBytesPerSec = 0
        downloadRateBytesPerSec = 0
        timeoutRateSummary = nil
    }

    /// Adds a sampling tick's byte delta to the session-wide running total
    /// -- not attributed to any particular chain, so switching the active
    /// chain mid-session or disconnecting/reconnecting never resets it.
    private func recordDataUsage(uploadDelta: UInt64, downloadDelta: UInt64) {
        totalUploadBytes += uploadDelta
        totalDownloadBytes += downloadDelta
    }

    /// Appends one tick to `trafficHistory`, trimming from the front once
    /// it's past `trafficHistoryLimit` -- a ring buffer via array slicing
    /// rather than a dedicated type, since a once-a-second append is cheap
    /// enough not to need one.
    private func recordTrafficSample(date: Date, uploadBps: Double, downloadBps: Double) {
        trafficHistory.append(TrafficSample(date: date, uploadBytesPerSec: uploadBps, downloadBytesPerSec: downloadBps))
        if trafficHistory.count > Self.trafficHistoryLimit {
            trafficHistory.removeFirst(trafficHistory.count - Self.trafficHistoryLimit)
        }
    }

    /// Updates the tile's ~10-minute-window summary from the delta between
    /// `current` and `oldest` (the earliest sample still in the ~10-minute
    /// buffer) -- an expanding window for the first ~10 minutes after
    /// connecting, same bootstrap behavior `trafficHistory` already has.
    private func recordTimeoutRateSummary(now: Date, current: (total: UInt64, timedOut: UInt64), oldest: (date: Date, total: UInt64, timedOut: UInt64)) {
        let totalDelta = current.total &- oldest.total
        let timedOutDelta = current.timedOut &- oldest.timedOut
        guard totalDelta > 0 else {
            timeoutRateSummary = nil
            return
        }
        timeoutRateSummary = TimeoutRateSummary(
            rate: Double(timedOutDelta) / Double(totalDelta),
            timedOut: Int(timedOutDelta),
            total: Int(totalDelta)
        )
    }

    /// Appends one chart tick's short-window rate, computed against `base`
    /// (see `startThroughputSampling`'s `chartBase` lookup) -- skipped
    /// entirely, rather than plotting a fake 0%, whenever that window saw no
    /// connection attempts at all (e.g. the proxy is running but idle).
    private func recordTimeoutRateSample(now: Date, current: (total: UInt64, timedOut: UInt64), base: (date: Date, total: UInt64, timedOut: UInt64)) {
        let totalDelta = current.total &- base.total
        guard totalDelta > 0 else { return }
        let timedOutDelta = current.timedOut &- base.timedOut
        timeoutRateHistory.append(TimeoutRateSample(date: now, rate: Double(timedOutDelta) / Double(totalDelta)))
        if timeoutRateHistory.count > Self.trafficHistoryLimit {
            timeoutRateHistory.removeFirst(timeoutRateHistory.count - Self.trafficHistoryLimit)
        }
    }

    /// `UserDefaults.integer(forKey:)` returns 0 for a key that was never
    /// set, indistinguishable from an explicit 0 -- `object(forKey:)` is
    /// checked instead so "Settings was never opened" correctly falls back
    /// to 1080 instead of silently trying to bind port 0.
    private static func configuredLocalProxyPort() -> UInt16 {
        if let stored = UserDefaults.standard.object(forKey: "localProxyPort") as? Int, let port = UInt16(exactly: stored) {
            return port
        }
        return 1080
    }

    private static func configuredAllowLAN() -> Bool {
        UserDefaults.standard.bool(forKey: "allowLANConnections")
    }

    /// `<= 0` (including "never set") means unlimited -- same
    /// never-set-vs-explicit-0 rationale as `configuredLocalProxyPort`,
    /// though here 0 unlimited is also the desired fallback rather than
    /// something to special-case around. Read by `performBandwidthProbe`,
    /// *not* by `connect()` -- this setting caps how much data the Test
    /// Bandwidth probe downloads, not live relayed traffic. `nonisolated`
    /// (unlike its sibling `configured*` helpers) because it's read from
    /// `performBandwidthProbe`'s own `nonisolated` context, not from
    /// MainActor -- it only touches `UserDefaults`, which is thread-safe.
    private nonisolated static func configuredBandwidthTestSizeMB() -> Double {
        UserDefaults.standard.object(forKey: "bandwidthTestSizeMB") as? Double ?? 0
    }

    /// A single TCP tunnel's own window/RTT often caps its throughput well
    /// below what the chain can actually carry, so the probe opens this many
    /// tunnels in parallel and sums what they move -- same idea most public
    /// speed tests use. Clamped to 1...16: below 1 there's nothing to
    /// parallelize, and past 16 the extra tunnels mostly just compete for the
    /// same last-mile link rather than revealing more real throughput.
    /// `nonisolated` for the same reason as `configuredBandwidthTestSizeMB`.
    private nonisolated static func configuredBandwidthTestConcurrency() -> Int {
        let configured = UserDefaults.standard.object(forKey: "bandwidthTestConcurrency") as? Int ?? 4
        return min(max(configured, 1), 16)
    }

    /// `<= 0` (including "never set") means unlimited -- the probe then
    /// relies only on the "Speed Test Size" cap (if any) and each read's own
    /// `bandwidthTestReadTimeout` stall guard. Read by `performBandwidthProbe`,
    /// `nonisolated` for the same reason as `configuredBandwidthTestSizeMB`.
    private nonisolated static func configuredBandwidthTestTimeoutSeconds() -> TimeInterval {
        UserDefaults.standard.object(forKey: "bandwidthTestTimeoutSeconds") as? Double ?? 8
    }

    // MARK: - Connection test

    // A saved chain has no target of its own (see ChainCore's
    // `NamedProxyChain` doc comment) -- real traffic always relays each
    // client's own requested destination. "Test Connection" instead just
    // needs *some* known-reachable address to dial through the chain to
    // confirm every hop works. Deliberately port 80, not 443: a plaintext
    // HTTP HEAD request gets a real, human-readable response back over the
    // raw chain without needing a TLS client here, so a successful test
    // proves bytes actually round-trip through every hop, not just that the
    // first hop accepted a TCP connection. (Confirmed against the real
    // server with `nc`: a raw connect, or even this same plaintext request,
    // gets nothing at all back on port 443 -- a TLS server won't speak
    // before a real ClientHello.)
    // `nonisolated`: read by `performLatencyProbe`, itself `nonisolated` so
    // it doesn't run its awaits on the MainActor (see that function's doc
    // comment) -- these are immutable Sendable constants, so it's safe for
    // a nonisolated caller to read them without hopping back to MainActor.
    private nonisolated static let testTargetHost = "www.google.com"
    private nonisolated static let testTargetPort: UInt16 = 80
    private nonisolated static let testProbeRequest = Array("HEAD / HTTP/1.0\r\nHost: \(testTargetHost)\r\nConnection: close\r\n\r\n".utf8)

    /// Shared connect/read deadline for both the TCP latency probe and the
    /// UDP capability probe below -- unlike the bandwidth test's timeout,
    /// there's no "unlimited" sentinel here: a connectivity check that never
    /// gives up isn't useful, so this floors at 1s rather than accepting
    /// `<= 0`. `nonisolated` for the same reason as `configuredBandwidthTestTimeoutSeconds`
    /// -- read from both probes, which themselves run off the MainActor.
    private nonisolated static func configuredConnectionTestTimeoutSeconds() -> TimeInterval {
        let configured = UserDefaults.standard.object(forKey: "connectionTestTimeoutSeconds") as? Double ?? 10
        return max(configured, 1)
    }

    private static let testLogTimeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        return formatter
    }()

    /// The result of dialing `testTargetHost` through a chain and timing the
    /// round trip -- shared by the manual `testConnection` button and the
    /// Auto-Optimize background rotation (`runAutoOptimizeCycle`), so both
    /// paths measure latency identically. `tcpMs`/`handshakeMs` are earlier
    /// checkpoints on the same clock as `elapsedMs`, not separate timers --
    /// see `ProxyChain.open`'s `onTCPConnected`/`onHandshakeComplete` hooks.
    private struct LatencyProbe {
        let tcpMs: Int?
        let handshakeMs: Int?
        let elapsedMs: Int
        let firstResponseBytes: [UInt8]
    }

    /// Mutable holder for `performLatencyProbe`'s two timing callbacks --
    /// a class (rather than captured locals) so the compiler doesn't flag
    /// the cross-closure mutation as a Swift 6 concurrency error. Safe as
    /// `@unchecked Sendable`: `onTCPConnected`/`onHandshakeComplete` run
    /// synchronously inside `TCPConn.connect`/`ProxyChain.open`, which are
    /// always awaited before anything reads these fields back, so there's
    /// no actual concurrent access -- just a happens-before edge the
    /// compiler can't see through the closures.
    private final class LatencyMilestones: @unchecked Sendable {
        var tcpConnectedAt: Date?
        var handshakeCompleteAt: Date?
    }

    /// `nonisolated`: without this, being a method of `@MainActor` `AppStore`
    /// would pull this whole probe (including every `await` resumption
    /// inside it) onto the MainActor -- fine for one round trip, but see
    /// `performBandwidthProbe`'s doc comment for why that's a real problem
    /// for its sibling probe, and this is kept `nonisolated` to match rather
    /// than leave an inconsistent trap for the next probe added here.
    private nonisolated func performLatencyProbe(_ chain: NamedProxyChain) async throws -> LatencyProbe {
        let start = Date()
        let milestones = LatencyMilestones()
        let timeout = Self.configuredConnectionTestTimeoutSeconds()
        let transport = try await ProxyChain.open(
            hops: chain.hops,
            finalTargetHost: Self.testTargetHost,
            finalTargetPort: Self.testTargetPort,
            connectTimeout: timeout,
            onTCPConnected: { milestones.tcpConnectedAt = Date() },
            onHandshakeComplete: { milestones.handshakeCompleteAt = Date() }
        )
        try await transport.send(Self.testProbeRequest, timeout: timeout)
        let firstData = try await transport.readAvailable(timeout: timeout)
        transport.close()
        return LatencyProbe(
            tcpMs: milestones.tcpConnectedAt.map { Int($0.timeIntervalSince(start) * 1000) },
            handshakeMs: milestones.handshakeCompleteAt.map { Int($0.timeIntervalSince(start) * 1000) },
            elapsedMs: Int(Date().timeIntervalSince(start) * 1000),
            firstResponseBytes: firstData
        )
    }

    // MARK: - UDP capability probe

    // Same reasoning as `testTargetHost`/`testTargetPort` above -- a saved
    // chain has no destination of its own, so this needs a known-reachable
    // target that actually round-trips real UDP payload rather than just
    // accepting a packet. A DNS query to a public resolver is the standard
    // way to get a real, verifiable UDP round trip without needing an echo
    // service (those are rare and unreliable on the open internet) -- same
    // choice of well-known Google infrastructure as the TCP probe's HEAD
    // request to `testTargetHost`.
    private nonisolated static let udpTestTargetHost = "8.8.8.8"
    private nonisolated static let udpTestTargetPort: UInt16 = 53
    private nonisolated static let udpTestQueryName = "www.google.com"
    private nonisolated static let udpTestRequest = AppStore.makeDNSQuery(name: udpTestQueryName)

    private struct UDPProbe {
        let elapsedMs: Int
        let responseBytes: [UInt8]
    }

    /// A minimal, well-formed DNS query for `name`'s A record -- just enough
    /// bytes to get a real resolver to answer, since this only needs *some*
    /// reply to come back through the chain, not a parsed result.
    private nonisolated static func makeDNSQuery(name: String, id: UInt16 = 0x2a2a) -> [UInt8] {
        var bytes: [UInt8] = [
            UInt8(id >> 8), UInt8(id & 0xff),  // ID
            0x01, 0x00,                        // flags: standard query, recursion desired
            0x00, 0x01,                        // QDCOUNT = 1
            0x00, 0x00,                        // ANCOUNT = 0
            0x00, 0x00,                        // NSCOUNT = 0
            0x00, 0x00,                        // ARCOUNT = 0
        ]
        for label in name.split(separator: ".") {
            bytes.append(UInt8(label.utf8.count))
            bytes.append(contentsOf: label.utf8)
        }
        bytes.append(0)                        // root label
        bytes.append(contentsOf: [0x00, 0x01]) // QTYPE = A
        bytes.append(contentsOf: [0x00, 0x01]) // QCLASS = IN
        return bytes
    }

    /// Dials this chain's UDP relay (`ProxyChain.openUDPRelay`'s existing
    /// Shadowsocks-all/VMess/VLESS/Trojan-last-hop dispatch) and times a DNS
    /// round trip through it, same shared-by-manual-test-and-Auto-Optimize
    /// role as `performLatencyProbe`. Throws `ProxyChainError.udpUnsupportedHop`/
    /// `udpUnsupportedLastHop` before dialing anything if the chain's own hop
    /// protocols can't carry UDP at all -- callers use that to tell "this
    /// chain shape doesn't support UDP" apart from "it does, but this probe
    /// didn't get a reply" (see `attemptUDPProbe`).
    private nonisolated func performUDPProbe(_ chain: NamedProxyChain) async throws -> UDPProbe {
        let start = Date()
        let timeout = Self.configuredConnectionTestTimeoutSeconds()
        let relay = try await ProxyChain.openUDPRelay(hops: chain.hops, connectTimeout: timeout)
        do {
            try await relay.send(targetHost: Self.udpTestTargetHost, targetPort: Self.udpTestTargetPort, payload: Self.udpTestRequest, timeout: timeout)
            let (_, _, payload) = try await relay.receive(timeout: timeout)
            relay.close()
            return UDPProbe(elapsedMs: Int(Date().timeIntervalSince(start) * 1000), responseBytes: payload)
        } catch {
            relay.close()
            throw error
        }
    }

    /// Wraps `performUDPProbe` into the two-part (supported, latency) result
    /// `recordChainScore`/`ChainQualityScore` store -- never throws, so
    /// callers can run it unconditionally alongside the TCP latency probe.
    private nonisolated func attemptUDPProbe(_ chain: NamedProxyChain) async -> (supported: Bool, latencyMs: Int?, logDescription: String) {
        do {
            let probe = try await performUDPProbe(chain)
            return (true, probe.elapsedMs, "\(probe.elapsedMs)ms")
        } catch let error as ProxyChainError {
            switch error {
            case .udpUnsupportedHop, .udpUnsupportedLastHop, .udpUnsupported2022Cipher:
                return (false, nil, "unsupported (\(error))")
            case .emptyChain:
                return (true, nil, "no reply (\(error))")
            }
        } catch {
            return (true, nil, "no reply (\(error))")
        }
    }

    public func testConnection(_ chain: NamedProxyChain) async {
        isTesting = true
        defer { isTesting = false }

        let start = Date()
        proxyLog(.info, "Store", "Testing chain '\(chain.name)' (\(chain.hops.count) hop(s)) -- started \(Self.testLogTimeFormatter.string(from: start))")
        do {
            let probe = try await performLatencyProbe(chain)
            let end = Date()
            lastTestResult = ConnectionTestResult(
                chainName: chain.name,
                success: true,
                message: "Connected to \(Self.testTargetHost):\(Self.testTargetPort) through \(chain.hops.count) hop(s).",
                milliseconds: probe.elapsedMs,
                date: end
            )
            let udp = await attemptUDPProbe(chain)
            recordChainScore(chainID: chain.id, latencyMs: probe.elapsedMs, tcpMs: probe.tcpMs, handshakeMs: probe.handshakeMs, udpSupported: udp.supported, udpLatencyMs: udp.latencyMs, mbps: nil)
            proxyLog(.info, "Store", "Test succeeded for '\(chain.name)' -- ended \(Self.testLogTimeFormatter.string(from: end)) (\(probe.elapsedMs)ms). First data from \(Self.testTargetHost): \(probe.firstResponseBytes.count) byte(s): \(Self.preview(of: probe.firstResponseBytes)). UDP: \(udp.logDescription)")
        } catch {
            let end = Date()
            let elapsedMs = Int(end.timeIntervalSince(start) * 1000)
            lastTestResult = ConnectionTestResult(
                chainName: chain.name,
                success: false,
                message: "\(error)",
                milliseconds: elapsedMs,
                date: end
            )
            proxyLog(.warn, "Store", "Test failed for '\(chain.name)' -- ended \(Self.testLogTimeFormatter.string(from: end)) after \(elapsedMs)ms: \(error)")
        }
    }

    /// Renders the first bytes of the test probe's response for a log line.
    /// The response is plaintext HTTP (see `testProbeRequest`), so this only
    /// needs to handle text, not arbitrary binary payloads.
    private static func preview(of bytes: [UInt8], maxBytes: Int = 200) -> String {
        guard !bytes.isEmpty else { return "(empty)" }
        let text = String(decoding: bytes.prefix(maxBytes), as: UTF8.self)
            .replacingOccurrences(of: "\r\n", with: "\\r\\n")
        return bytes.count > maxBytes ? "\(text)…" : text
    }

    // MARK: - Bandwidth test

    // Same rationale as the latency probe above -- a saved chain has no
    // target of its own, so this needs its own known-reachable endpoint. It
    // has to actually serve a large file over plain HTTP rather than
    // redirecting to HTTPS, since it's the chain's raw bytes that get timed,
    // not a redirect response and a TLS handshake this app has no client
    // for. speedtest.tele2.net's public speed-test files are a long-standing
    // convention for exactly this (plenty of curl/wget-based speed tests
    // use them -- confirmed by hand here that it serves the plain HTTP/1.0
    // request below with real file bytes and no redirect; thinkbroadband's
    // equivalent files, tried first, didn't respond at all on this network
    // path), and unlike testConnection's HEAD probe, this issues a GET for a
    // file large enough that the transfer, not the handshake, is what
    // dominates the timing.
    // `nonisolated`: read by `performBandwidthProbe`, itself `nonisolated`
    // so its hot read loop doesn't run on the MainActor (see that function's
    // doc comment) -- these are immutable Sendable constants, so it's safe
    // for a nonisolated caller to read them without hopping back to
    // MainActor.
    private nonisolated static let bandwidthTestHost = "speedtest.tele2.net"
    private nonisolated static let bandwidthTestPort: UInt16 = 80
    private nonisolated static let bandwidthTestPath = "/10MB.zip"
    private nonisolated static let bandwidthTestRequest = Array(
        "GET \(bandwidthTestPath) HTTP/1.0\r\nHost: \(bandwidthTestHost)\r\nConnection: close\r\n\r\n".utf8
    )
    // The configured timeout (see `configuredBandwidthTestTimeoutSeconds`)
    // bounds total wall-clock time regardless of whether a "Speed Test Size"
    // is also set: a slow chain shouldn't have to finish downloading the
    // whole configured size to get a reading, it'll just read whatever
    // arrived before the clock runs out. A fast chain that finishes early is
    // still capped by the size (or the server closing the connection at EOF)
    // as before.
    private nonisolated static let bandwidthTestConnectTimeout: TimeInterval = 10
    private nonisolated static let bandwidthTestReadTimeout: TimeInterval = 10

    /// Shared by the manual `testBandwidth` button and the Auto-Optimize
    /// background rotation, same as `performLatencyProbe` above.
    private struct BandwidthProbe {
        let mbps: Double
        let bytesTransferred: Int
        let elapsed: TimeInterval
    }

    /// `nonisolated`: this method is a plain member of `@MainActor`
    /// `AppStore`, which by default would pull its *entire* body -- including
    /// the read loop below -- onto the MainActor, since every `await`
    /// resumption inside a MainActor-isolated method hops back to it. That's
    /// exactly what was happening here: a tight ~10s loop calling
    /// `transport.readAvailable` as fast as the network delivers data (tens
    /// of thousands of resumptions for a real bandwidth test) was
    /// monopolizing the *same* single-threaded MainActor that
    /// `LocalProxyServer`'s live relay loop also needs a turn on for every
    /// one of its own reads/sends -- confirmed live: a real user connection
    /// relayed through `LocalProxyServer` stalled and got reset by the peer
    /// for the exact ~11s duration of an Auto-Optimize rotation cycle
    /// running concurrently, with matching timestamps in the log. Marking
    /// this `nonisolated` moves the whole probe (it touches no `@MainActor`
    /// instance state, only `Self`-static constants and its own locals) onto
    /// the general concurrent executor, so a bandwidth test no longer starves
    /// real traffic -- or the UI -- of MainActor time.
    private nonisolated func performBandwidthProbe(_ chain: NamedProxyChain) async throws -> BandwidthProbe {
        func openAndRequest() async throws -> any ProxyTransport {
            let transport = try await ProxyChain.open(
                hops: chain.hops,
                finalTargetHost: Self.bandwidthTestHost,
                finalTargetPort: Self.bandwidthTestPort,
                connectTimeout: Self.bandwidthTestConnectTimeout
            )
            try await transport.send(Self.bandwidthTestRequest, timeout: Self.bandwidthTestReadTimeout)
            return transport
        }

        // The user-configured "Speed Test Size" sets how much data this
        // probe downloads in total, in MB -- it never touches live relayed
        // traffic (see `LocalProxyServer`'s doc comment). `<= 0` (unlimited)
        // means no cap: the probe stays bounded only by the timeout below.
        let configuredSizeMB = Self.configuredBandwidthTestSizeMB()
        let sizeCapBytes = configuredSizeMB > 0 ? Int(configuredSizeMB * 1_000_000) : nil

        // Split the total size cap evenly across the parallel tunnels
        // (remainder to the first few) so their sum still adds up to the
        // configured size instead of overshooting it. Unlimited stays
        // unlimited per-tunnel too -- each is bounded only by the shared
        // deadline below.
        let concurrency = Self.configuredBandwidthTestConcurrency()
        let perTunnelCaps: [Int?]
        if let sizeCapBytes {
            let share = sizeCapBytes / concurrency
            let remainder = sizeCapBytes % concurrency
            perTunnelCaps = (0..<concurrency).map { $0 < remainder ? share + 1 : share }
        } else {
            perTunnelCaps = Array(repeating: nil, count: concurrency)
        }

        // Every tunnel is opened -- and its request sent -- before the clock
        // starts, all in parallel, same rationale as the old single-tunnel
        // probe: multi-hop handshake latency shouldn't count against
        // throughput, only the transfer itself should.
        let transports = try await withThrowingTaskGroup(of: (any ProxyTransport).self) { group in
            for _ in 0..<concurrency {
                group.addTask { try await openAndRequest() }
            }
            var opened: [any ProxyTransport] = []
            var firstError: Error?
            // Deliberately not `for try await transport in group`: that
            // sugar exits the loop the moment any child throws, leaving
            // whichever siblings hadn't finished dialing *yet* to complete
            // later, unobserved -- their transport would never reach
            // `opened` and so never get closed below, leaking a live socket.
            // Looping on `group.next()` directly and swallowing (not
            // rethrowing) each error keeps polling until every child has
            // reported in, so every tunnel that *did* open successfully --
            // no matter when -- ends up in `opened` and gets closed here.
            while true {
                do {
                    guard let transport = try await group.next() else { break }
                    opened.append(transport)
                } catch {
                    if firstError == nil { firstError = error }
                }
            }
            if let firstError {
                // A sibling tunnel's dial failing here would otherwise leak
                // every tunnel that *did* finish opening -- this `opened`
                // array is the only reference to those live sockets, and
                // it's about to be discarded by the rethrow below (nothing
                // else ever closes them).
                for transport in opened { transport.close() }
                throw firstError
            }
            return opened
        }

        let downloadStart = Date()
        // The configured timeout (`<= 0` means unlimited) bounds the whole
        // probe regardless of whether a size cap is set, so a chain that's
        // merely slow -- not stalled -- can't run indefinitely trying to
        // fill a large configured size. Each read's own
        // `bandwidthTestReadTimeout` stall guard still separately catches a
        // tunnel that's actually stuck rather than just slow.
        let timeoutSeconds = Self.configuredBandwidthTestTimeoutSeconds()
        let deadline = timeoutSeconds > 0 ? downloadStart.addingTimeInterval(timeoutSeconds) : Date.distantFuture

        let totalBytes = try await withThrowingTaskGroup(of: Int.self) { group in
            for (transport, cap) in zip(transports, perTunnelCaps) {
                group.addTask {
                    var transport = transport
                    // Covers every exit from the loop below, including a
                    // thrown error (e.g. `readAvailable` timing out on a
                    // stalled tunnel) -- that path used to skip the explicit
                    // `close()` this loop only reached on a normal `break`,
                    // leaking that tunnel's socket.
                    defer { transport.close() }
                    var bytes = 0
                    while Date() < deadline {
                        if let cap, bytes >= cap { break }
                        let chunk = try await transport.readAvailable(timeout: Self.bandwidthTestReadTimeout)
                        if !chunk.isEmpty {
                            bytes += chunk.count
                            continue
                        }
                        // EOF: `bandwidthTestPath` is a single fixed-size file, so a
                        // per-tunnel share bigger than it needs more than one download
                        // to fill -- reopen a fresh connection to the same
                        // (already verified-working) file and keep going, as long as
                        // there's still budget left to fill. Unlimited (`cap == nil`)
                        // stops here instead, same as before this setting existed.
                        guard let cap, bytes < cap else { break }
                        transport.close()
                        transport = try await openAndRequest()
                    }
                    return bytes
                }
            }
            var sum = 0
            for try await bytes in group {
                sum += bytes
            }
            return sum
        }

        let elapsed = Date().timeIntervalSince(downloadStart)
        let mbps = elapsed > 0 ? (Double(totalBytes) * 8 / 1_000_000) / elapsed : 0
        return BandwidthProbe(mbps: mbps, bytesTransferred: totalBytes, elapsed: elapsed)
    }

    public func testBandwidth(_ chain: NamedProxyChain) async {
        isTestingBandwidth = true
        defer { isTestingBandwidth = false }

        let start = Date()
        proxyLog(.info, "Store", "Bandwidth-testing chain '\(chain.name)' (\(chain.hops.count) hop(s)) -- started \(Self.testLogTimeFormatter.string(from: start))")
        do {
            let probe = try await performBandwidthProbe(chain)
            let end = Date()
            lastBandwidthResult = BandwidthTestResult(
                chainName: chain.name,
                success: true,
                message: "Downloaded \(Self.formatByteCount(probe.bytesTransferred)) from \(Self.bandwidthTestHost) through \(chain.hops.count) hop(s) in \(String(format: "%.1f", probe.elapsed))s.",
                mbps: probe.mbps,
                bytesTransferred: probe.bytesTransferred,
                date: end
            )
            recordChainScore(chainID: chain.id, latencyMs: nil, mbps: probe.mbps)
            proxyLog(.info, "Store", "Bandwidth test succeeded for '\(chain.name)' -- \(Self.formatByteCount(probe.bytesTransferred)) in \(String(format: "%.2f", probe.elapsed))s (\(String(format: "%.1f", probe.mbps)) Mbps)")
        } catch {
            let end = Date()
            lastBandwidthResult = BandwidthTestResult(
                chainName: chain.name,
                success: false,
                message: "\(error)",
                mbps: 0,
                bytesTransferred: 0,
                date: end
            )
            proxyLog(.warn, "Store", "Bandwidth test failed for '\(chain.name)': \(error)")
        }
    }

    private static func formatByteCount(_ bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .binary)
    }

    // MARK: - Auto-Optimize

    private static let autoOptimizeEnabledDefaultsKey = "autoOptimizeEnabled"
    private static let autoOptimizeIntervalDefaultsKey = "autoOptimizeIntervalMinutes"
    private static let defaultAutoOptimizeIntervalMinutes: Double = 5
    /// Guards against a stray 0-or-negative interval (e.g. a blank Settings
    /// field decoding to 0) turning the rotation into a tight loop that
    /// hammers the latency/bandwidth test targets. Not `private` -- `SettingsView`
    /// clamps its Test Interval field to this same floor instead of duplicating it.
    static let minimumAutoOptimizeIntervalMinutes: Double = 0.5

    // Two independently-normalized 0...1 sub-scores blended 50/50, so neither
    // metric dominates just because its raw units are numerically larger
    // (Mbps in the tens vs. milliseconds in the hundreds). Latency gets a
    // fixed "anything under half a second is fine" cutoff, but bandwidth has
    // no realistic fixed ceiling -- a good Mbps number depends entirely on
    // the user's own network and chosen nodes -- so it's normalized against
    // the best Mbps currently observed among the chains being compared
    // instead: the fastest saved chain always scores 1.0 on bandwidth, the
    // rest scale relative to it. That keeps the comparison meaningful
    // whether real-world speeds run in the tens or the hundreds of Mbps.
    private static let latencyNormalizationCeilingMs: Double = 500
    private static let latencyScoreWeight = 0.5
    private static let bandwidthScoreWeight = 0.5

    static func combinedScore(latencyMs: Int?, mbps: Double?, maxObservedMbps: Double?) -> Double {
        let latencyScore = latencyMs.map { max(0, 1 - Double($0) / latencyNormalizationCeilingMs) }
        let bandwidthScore: Double? = {
            guard let mbps, let maxObservedMbps, maxObservedMbps > 0 else { return nil }
            return min(1, mbps / maxObservedMbps)
        }()
        switch (latencyScore, bandwidthScore) {
        case let (l?, b?): return l * latencyScoreWeight + b * bandwidthScoreWeight
        case let (l?, nil): return l * latencyScoreWeight
        case let (nil, b?): return b * bandwidthScoreWeight
        case (nil, nil): return 0
        }
    }

    /// Merges a freshly-measured latency and/or bandwidth reading into the
    /// chain's running record -- either one alone (as from a single manual
    /// "Test Connection" or "Test Bandwidth" tap) carries over whichever
    /// other metric was already known, rather than blanking it out. Same
    /// carry-over for `tcpMs`/`handshakeMs`: a bandwidth-only run passes
    /// `nil` for both and keeps whatever the chain's last latency probe
    /// found. `udpSupported`/`udpLatencyMs` follow the same rule -- a caller
    /// that didn't run the UDP probe (passing `nil`) keeps whatever the
    /// chain's last UDP probe found, and a fresh probe that determined
    /// `udpSupported` but got no reply this time (`udpLatencyMs: nil`) keeps
    /// the last *successful* reading rather than blanking it, so one
    /// transient no-reply doesn't flicker the UDP badge off.
    func recordChainScore(chainID: UUID, latencyMs: Int?, tcpMs: Int? = nil, handshakeMs: Int? = nil, udpSupported: Bool? = nil, udpLatencyMs: Int? = nil, mbps: Double?) {
        let existing = chainScores[chainID]
        let mergedLatency = latencyMs ?? existing?.latencyMs
        let mergedTCP = tcpMs ?? existing?.tcpMs
        let mergedHandshake = handshakeMs ?? existing?.handshakeMs
        let mergedUDPSupported = udpSupported ?? existing?.udpSupported
        let mergedUDPLatency = udpLatencyMs ?? existing?.udpLatencyMs
        let mergedMbps = mbps ?? existing?.mbps
        chainScores[chainID] = ChainQualityScore(
            chainID: chainID,
            latencyMs: mergedLatency,
            tcpMs: mergedTCP,
            handshakeMs: mergedHandshake,
            mbps: mergedMbps,
            udpSupported: mergedUDPSupported,
            udpLatencyMs: mergedUDPLatency,
            date: Date()
        )
    }

    /// The saved chain with the best known combined score, or `nil` if fewer
    /// than two chains have been tested. Drives the auto-switch in
    /// `runAutoOptimizeCycle` --
    /// "optimal" implies a comparison, so a single tested chain (which would
    /// otherwise trivially "win" against an empty field, however bad its own
    /// latency/bandwidth) doesn't qualify.
    ///
    /// Scores are computed here rather than cached on `ChainQualityScore`
    /// because the bandwidth sub-score is normalized against the best Mbps
    /// currently observed across this same comparison -- caching it at
    /// measurement time would leave every chain's score stale the moment a
    /// new fastest chain gets tested.
    public var autoOptimizeBestChainID: UUID? {
        let scored = settings.chains.compactMap { chain in chainScores[chain.id] }
        guard scored.count >= 2 else { return nil }
        let maxObservedMbps = scored.compactMap(\.mbps).max()
        return scored.max { lhs, rhs in
            Self.combinedScore(latencyMs: lhs.latencyMs, mbps: lhs.mbps, maxObservedMbps: maxObservedMbps)
                < Self.combinedScore(latencyMs: rhs.latencyMs, mbps: rhs.mbps, maxObservedMbps: maxObservedMbps)
        }?.chainID
    }

    private func startAutoOptimizeLoop() {
        guard autoOptimizeTask == nil else { return }
        autoOptimizeTask = Task { [weak self] in
            while let self, !Task.isCancelled {
                await self.runAutoOptimizeCycle()
                guard !Task.isCancelled else { break }
                let minutes = max(self.autoOptimizeIntervalMinutes, Self.minimumAutoOptimizeIntervalMinutes)
                try? await Task.sleep(nanoseconds: UInt64(minutes * 60 * 1_000_000_000))
            }
        }
    }

    private func stopAutoOptimizeLoop() {
        autoOptimizeTask?.cancel()
        autoOptimizeTask = nil
    }

    /// Round-robins through `settings.chains` -- one chain per call, wrapping
    /// back to the start -- so a fixed test interval spreads out across every
    /// saved chain over time instead of testing them all in one burst.
    private func nextChainToTest() -> NamedProxyChain? {
        let chains = settings.chains
        guard !chains.isEmpty else { return nil }
        autoOptimizeCursor = autoOptimizeCursor % chains.count
        let chain = chains[autoOptimizeCursor]
        autoOptimizeCursor = (autoOptimizeCursor + 1) % chains.count
        return chain
    }

    /// One rotation tick: tests the next chain's latency and bandwidth
    /// (without touching `isTesting`/`lastTestResult` -- those report the
    /// manual test buttons' own in-flight state, which a background chain
    /// the user didn't tap shouldn't hijack), records its score, and
    /// switches the active chain if a different one now scores best.
    private func runAutoOptimizeCycle() async {
        guard let chain = nextChainToTest() else { return }
        proxyLog(.info, "AutoOptimize", "Rotation testing '\(chain.name)' (\(chain.hops.count) hop(s))")

        let latencyProbe = try? await performLatencyProbe(chain)
        let udp = await attemptUDPProbe(chain)
        let mbps = try? await performBandwidthProbe(chain).mbps
        recordChainScore(chainID: chain.id, latencyMs: latencyProbe?.elapsedMs, tcpMs: latencyProbe?.tcpMs, handshakeMs: latencyProbe?.handshakeMs, udpSupported: udp.supported, udpLatencyMs: udp.latencyMs, mbps: mbps)

        let latencyDescription = latencyProbe.map { "\($0.elapsedMs)ms" } ?? "no response"
        let mbpsDescription = mbps.map { String(format: "%.1f Mbps", $0) } ?? "no response"
        proxyLog(.info, "AutoOptimize", "Recorded '\(chain.name)': \(latencyDescription), \(mbpsDescription), UDP: \(udp.logDescription)")

        guard let bestID = autoOptimizeBestChainID, bestID != settings.activeChainID else { return }
        let bestName = settings.chains.first { $0.id == bestID }?.name ?? "?"
        proxyLog(.info, "AutoOptimize", "Switching active chain to '\(bestName)' -- best combined score so far")
        setActiveChain(bestID)
        SystemNotifier.post(title: "Chainy Auto-Optimize", body: "Switched to '\(bestName)' -- best combined score so far")
    }
}
