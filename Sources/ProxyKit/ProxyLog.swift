// ProxyLog.swift
//
// A tiny cross-target log sink: every layer (TCPListener's caller,
// LocalProxyServer, ChainCore's ProxyChain, AppStore) calls
// `proxyLog(...)` to record what it's doing. Entries are kept in a bounded
// in-memory buffer (for the app's Logs panel) and appended to a rolling
// file on disk, so a user who hits a connection problem can inspect what
// happened without attaching a debugger. Lives in ProxyKit -- the one
// target every other target already depends on -- rather than ChainCore or
// Chainy, so the demo CLIs and every protocol module can log through
// the same sink.

import Foundation

public enum LogLevel: String, Codable, CaseIterable, Comparable, Sendable {
    case debug, info, warn, error

    private var sortOrder: Int {
        switch self {
        case .debug: return 0
        case .info: return 1
        case .warn: return 2
        case .error: return 3
        }
    }

    public static func < (lhs: LogLevel, rhs: LogLevel) -> Bool { lhs.sortOrder < rhs.sortOrder }
}

public struct LogEntry: Identifiable, Equatable, Sendable {
    public let id: UUID
    public let date: Date
    public let level: LogLevel
    public let category: String
    public let message: String

    public init(id: UUID = UUID(), date: Date = Date(), level: LogLevel, category: String, message: String) {
        self.id = id
        self.date = date
        self.level = level
        self.category = category
        self.message = message
    }
}

/// Thread-safe: `log`/`snapshot`/`addListener` all take `lock`, since log
/// entries are produced from whatever thread each relay/listener callback
/// happens to run on, not just the main actor.
public final class ProxyLog: @unchecked Sendable {
    /// The log every `proxyLog(...)` call writes through, pointed at the
    /// real per-user Application Support location.
    public static let shared = ProxyLog()

    private let lock = NSLock()
    private var entries: [LogEntry] = []
    private var listeners: [UUID: (LogEntry) -> Void] = [:]
    private let maxEntries: Int

    private let fileHandle: FileHandle?
    public let fileURL: URL?
    private let fileDateFormatter: DateFormatter

    /// `directoryURL: nil` disables file writing (still keeps the in-memory
    /// buffer) -- used by tests so exercising logging never touches the
    /// developer's own real log file.
    public init(maxEntries: Int = 2000, directoryURL: URL? = ProxyLog.defaultLogDirectory()) {
        self.maxEntries = maxEntries
        fileDateFormatter = DateFormatter()
        fileDateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        fileDateFormatter.locale = Locale(identifier: "en_US_POSIX")

        if let dir = directoryURL {
            let url = dir.appendingPathComponent("Chainy.log")
            if !FileManager.default.fileExists(atPath: url.path) {
                FileManager.default.createFile(atPath: url.path, contents: nil)
            }
            fileURL = url
            fileHandle = try? FileHandle(forWritingTo: url)
            fileHandle?.seekToEndOfFile()
        } else {
            fileURL = nil
            fileHandle = nil
        }
    }

    deinit { try? fileHandle?.close() }

    public static func defaultLogDirectory() -> URL? {
        guard let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        let dir = base.appendingPathComponent("Chainy", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    public func log(_ level: LogLevel, _ category: String, _ message: String) {
        let entry = LogEntry(level: level, category: category, message: message)

        lock.lock()
        entries.append(entry)
        if entries.count > maxEntries {
            entries.removeFirst(entries.count - maxEntries)
        }
        let currentListeners = Array(listeners.values)
        lock.unlock()

        appendToFile(entry)
        for listener in currentListeners {
            listener(entry)
        }
    }

    public func snapshot() -> [LogEntry] {
        lock.lock(); defer { lock.unlock() }
        return entries
    }

    /// `listener` fires once per new entry, on whatever thread `log(...)`
    /// was called from -- callers that need main-actor delivery (e.g.
    /// `AppStore` updating a `@Published` array) must hop themselves.
    @discardableResult
    public func addListener(_ listener: @escaping (LogEntry) -> Void) -> UUID {
        let id = UUID()
        lock.lock()
        listeners[id] = listener
        lock.unlock()
        return id
    }

    public func removeListener(_ id: UUID) {
        lock.lock()
        listeners.removeValue(forKey: id)
        lock.unlock()
    }

    public func clear() {
        lock.lock()
        entries.removeAll()
        lock.unlock()
    }

    private func appendToFile(_ entry: LogEntry) {
        guard let fileHandle else { return }
        let line = "\(fileDateFormatter.string(from: entry.date)) [\(entry.level.rawValue.uppercased())] [\(entry.category)] \(entry.message)\n"
        guard let data = line.data(using: .utf8) else { return }
        fileHandle.write(data)
    }
}

/// Shorthand so call sites read `proxyLog(.info, "Proxy", "started")`
/// instead of the fully-qualified singleton call.
public func proxyLog(_ level: LogLevel, _ category: String, _ message: String) {
    ProxyLog.shared.log(level, category, message)
}
