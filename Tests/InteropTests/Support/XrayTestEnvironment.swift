// XrayTestEnvironment.swift
//
// Launches one real `xray-core` process (installed locally via
// `brew install xray` -- confirmed the right tool during planning: Clash/
// mihomo has no inbound VMess/VLESS/Trojan *server* capability, it's a
// client-only kernel, so the actual protocol servers this suite dials into
// have to come from xray-core, the maintained v2ray-core fork) exposing all
// 6 protocols Chainy speaks as independent inbound listeners on fixed
// loopback ports, each with a `freedom` (direct-dial) outbound.
//
// Because `freedom` just dials whatever destination address a client's own
// protocol handshake names, chaining needs no server-side awareness at all:
// asking hop *i* to CONNECT to hop *i+1*'s 127.0.0.1:port loops back into
// this same process on a different (or the same, for a repeated protocol)
// port, handled exactly like a fresh client. One process therefore serves
// every chain of any length/shape this suite builds -- see
// `Tests/InteropTests/ChainExhaustiveTCPTests.swift`.
//
// Started once for the whole `InteropTests` binary (`XrayTestEnvironment.shared`,
// a lazily-initialized `static let`) and never torn down mid-run -- individual
// tests only ever open/close their own chain's connections through it.

import Foundation
import Darwin
import ChainCore
import ShadowsocksCore

// MARK: - Locating the external binaries this suite depends on

/// Resolves `xray`/`mihomo`/`openssl` on this machine. Checks common
/// Homebrew install locations first (works even if `PATH` was stripped by
/// whatever launched the test runner), falling back to a `PATH`-based
/// `which` lookup.
enum ExternalTool {
    static let xray = resolve("xray")
    static let mihomo = resolve("mihomo")
    static let openssl = resolve("openssl")

    private static func resolve(_ name: String) -> String? {
        for dir in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
            let path = "\(dir)/\(name)"
            if FileManager.default.isExecutableFile(atPath: path) { return path }
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["which", name]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { return nil }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let path = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            return path.isEmpty ? nil : path
        } catch {
            return nil
        }
    }
}

// MARK: - The 6 canonical single-protocol nodes this suite builds chains from

/// One canonical, fixed configuration per protocol -- used both for the
/// exhaustive chain matrix (`ChainExhaustiveTCPTests`/`ChainExhaustiveUDPTests`)
/// and Part A's subscription round-trip. Auxiliary parameter variants
/// (VLESS without TLS, SOCKS5/HTTP with auth, the other Shadowsocks ciphers)
/// are deliberately *not* folded in here -- see `ProtocolVariantSpotChecks.swift`.
enum CanonicalProtocol: String, CaseIterable {
    case socks5, http, vmess, vless, trojan, shadowsocks

    var port: UInt16 {
        switch self {
        case .socks5: return XrayTestEnvironment.Ports.socks5
        case .http: return XrayTestEnvironment.Ports.http
        case .vmess: return XrayTestEnvironment.Ports.vmess
        case .vless: return XrayTestEnvironment.Ports.vless
        case .trojan: return XrayTestEnvironment.Ports.trojan
        case .shadowsocks: return XrayTestEnvironment.Ports.shadowsocks
        }
    }

    var protocolConfig: ProxyHopProtocol {
        switch self {
        case .socks5: return .socks5(auth: .none)
        case .http: return .http(auth: .none)
        case .vmess: return .vmess(uuid: XrayTestEnvironment.vmessUUID)
        case .vless: return .vless(uuid: XrayTestEnvironment.vlessUUID, tls: true, sni: "localhost", allowInsecure: true)
        case .trojan: return .trojan(password: XrayTestEnvironment.trojanPassword, sni: "localhost", allowInsecure: true)
        case .shadowsocks: return .shadowsocks(password: XrayTestEnvironment.shadowsocksPassword, cipher: XrayTestEnvironment.shadowsocksCipher)
        }
    }

    func hop(host: String = "127.0.0.1") -> ProxyHop {
        ProxyHop(host: host, port: port, protocolConfig: protocolConfig)
    }

    /// Mirrors `ProxyHopProtocol.logName` (internal to `ChainCore`, so not
    /// reachable from this test target) -- used only to check
    /// `ProxyChainError.udpUnsupportedLastHop`'s associated protocol name.
    var chainCoreLogName: String {
        switch self {
        case .socks5: return "SOCKS5"
        case .shadowsocks: return "Shadowsocks"
        case .vmess: return "VMess"
        case .trojan: return "Trojan"
        case .vless: return "VLESS"
        case .http: return "HTTP"
        }
    }

    /// Every ordered `length`-long sequence of the 6 canonical protocols
    /// (6^length total) -- a plain cartesian power, built recursively since
    /// `CaseIterable` only gives us the base case. Shared by
    /// `ChainExhaustiveTCPTests` and `ChainExhaustiveUDPTests` so both walk
    /// exactly the same 9,330-combination matrix.
    static func combinations(length: Int) -> [[CanonicalProtocol]] {
        guard length > 0 else { return [[]] }
        let shorter = combinations(length: length - 1)
        return CanonicalProtocol.allCases.flatMap { proto in shorter.map { [proto] + $0 } }
    }
}

// MARK: - The xray-core process itself

enum XrayTestEnvironmentError: Error, CustomStringConvertible {
    case toolMissing(String)
    case processFailed(String)
    case portNeverOpened(UInt16)

    var description: String {
        switch self {
        case .toolMissing(let name): return "\(name) not found on this machine"
        case .processFailed(let detail): return "external process failed: \(detail)"
        case .portNeverOpened(let port): return "xray never opened port \(port) in time"
        }
    }
}

final class XrayTestEnvironment: @unchecked Sendable {
    enum Ports {
        static let socks5: UInt16 = 18100
        static let http: UInt16 = 18101
        static let vmess: UInt16 = 18102
        static let vless: UInt16 = 18103
        static let trojan: UInt16 = 18104
        static let shadowsocks: UInt16 = 18105

        // Auxiliary variants deliberately excluded from the canonical
        // 6-protocol exhaustive matrix (see `ProtocolVariantSpotChecks.swift`).
        static let socks5WithAuth: UInt16 = 18106
        static let httpWithAuth: UInt16 = 18107
        static let vlessNoTLS: UInt16 = 18108
        static let shadowsocksAes128Gcm: UInt16 = 18109
        static let shadowsocksChacha20: UInt16 = 18110
        // WS transport spot-checks (see `ProtocolVariantSpotChecks.swift`) --
        // the real-world-common "+ WS + TLS" deployment for vmess/vless,
        // and "+ WS" for trojan (always-TLS already).
        static let vmessWSTLS: UInt16 = 18111
        static let vlessWSTLS: UInt16 = 18112
        static let trojanWS: UInt16 = 18113
        // Shadowsocks 2022 edition spot-checks (see `ProtocolVariantSpotChecks.swift`).
        static let shadowsocks2022Aes128Gcm: UInt16 = 18114
        static let shadowsocks2022Aes256Gcm: UInt16 = 18115
        static let shadowsocks2022Chacha20: UInt16 = 18116

        // Remaining corners of the WS x TLS matrix for vmess/vless -- `tls`
        // and `wsPath` are independent toggles client-side (see
        // `VMessCore.dial`'s doc comment: "tls/wsPath optionally wrap
        // transport first, in that order"), so all 4 combinations are
        // real, dialable configurations, not just 2 (see
        // `RepresentativeMatrixReportTests.swift`).
        static let vmessTLSOnly: UInt16 = 18117
        static let vmessWSOnly: UInt16 = 18118
        static let vlessWSOnly: UInt16 = 18119

        // A trojan node with TLS turned off entirely (`security=none` in a
        // subscription link) -- the rarer real-world deployment confirmed
        // live against an actual node before `TrojanServerConfig.tls`
        // existed. Unlike `vlessNoTLS` (VLESS's spec-correct default),
        // this is the *non-default* case for Trojan.
        static let trojanNoTLS: UInt16 = 18120

        static let all: [UInt16] = [
            socks5, http, vmess, vless, trojan, shadowsocks,
            socks5WithAuth, httpWithAuth, vlessNoTLS, shadowsocksAes128Gcm, shadowsocksChacha20,
            vmessWSTLS, vlessWSTLS, trojanWS,
            shadowsocks2022Aes128Gcm, shadowsocks2022Aes256Gcm, shadowsocks2022Chacha20,
            vmessTLSOnly, vmessWSOnly, vlessWSOnly,
            trojanNoTLS,
        ]
    }

    static let vmessWSPath = "/vmess-ws-tls"
    static let vlessWSPath = "/vless-ws-tls"
    static let trojanWSPath = "/trojan-ws"
    static let vmessWSOnlyPath = "/vmess-ws-only"
    static let vlessWSOnlyPath = "/vless-ws-only"

    static let vmessUUID = "0398d470-bc09-4cd5-889d-3ae4c569b6da"
    static let vlessUUID = "1398d470-bc09-4cd5-889d-3ae4c569b6db"
    static let trojanPassword = "chain-test-trojan-password"
    static let shadowsocksPassword = "chain-test-shadowsocks-password"
    static let shadowsocksCipher = ShadowsocksCipher.aes256Gcm

    /// Fixed, known-in-advance base64 PSKs for the 2022-edition spot-checks
    /// -- exact length matters (16 bytes for aes-128-gcm, 32 for the other
    /// two), unlike 2017's arbitrary-passphrase `shadowsocksPassword`.
    static let shadowsocks2022PSK128 = Data((0..<16).map { UInt8($0) }).base64EncodedString()
    static let shadowsocks2022PSK256 = Data((0..<32).map { UInt8($0) }).base64EncodedString()

    static let spotCheckUsername = "chain-test-user"
    static let spotCheckPassword = "chain-test-pass"

    static let host = "127.0.0.1"

    /// `true` once `xray`/`openssl` are confirmed present -- every test
    /// method should check this (via `XCTSkipUnless`) *before* touching
    /// `.shared`, so a machine without these tools installed skips cleanly
    /// instead of the `fatalError` below firing (which is reserved for a
    /// real setup failure once we already know the tools exist).
    static var isAvailable: Bool { ExternalTool.xray != nil && ExternalTool.openssl != nil }

    static let shared: XrayTestEnvironment = {
        do {
            return try XrayTestEnvironment()
        } catch {
            fatalError("XrayTestEnvironment failed to start even though xray/openssl were detected -- this is a genuine setup failure, not a missing-tool case: \(error)")
        }
    }()

    private let process: Process
    private let tempDir: URL

    private init() throws {
        guard let xrayPath = ExternalTool.xray else { throw XrayTestEnvironmentError.toolMissing("xray") }
        guard let opensslPath = ExternalTool.openssl else { throw XrayTestEnvironmentError.toolMissing("openssl") }

        // A previous `swift test` invocation's xray-core process is never
        // reaped automatically: `Process.terminate()` in `deinit` only runs
        // if this singleton is ever deallocated, but a `static let` normally
        // just gets dropped along with the whole process at exit, without
        // Swift running its deinit -- so an interrupted or simply repeated
        // test run leaves its own xray-core child orphaned, still bound to
        // these exact fixed ports. Left alone, every subsequent run's own
        // freshly-launched xray-core process then fails to bind some of
        // those ports (already held by the orphan), while this init's own
        // `waitUntilPortOpens` below can't tell "my process opened this
        // port" from "some *other* still-running process already had it
        // open" -- silently talking to a stale, possibly long-gone-on-disk
        // orphan instead of this run's own server. Confirmed empirically:
        // 13 orphaned `xray` processes had accumulated from this file's own
        // earlier test runs, and cleaning them up was necessary to get
        // consistent (non-flaky) results from the exhaustive UDP suite.
        Self.killAnyProcessHoldingOurPorts()

        tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("chainy-interop-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)

        let certPath = tempDir.appendingPathComponent("cert.pem").path
        let keyPath = tempDir.appendingPathComponent("key.pem").path
        try Self.generateSelfSignedCert(opensslPath: opensslPath, certPath: certPath, keyPath: keyPath)

        let configPath = tempDir.appendingPathComponent("config.json").path
        try Self.writeConfig(to: configPath, certPath: certPath, keyPath: keyPath)

        process = Process()
        process.executableURL = URL(fileURLWithPath: xrayPath)
        process.arguments = ["run", "-config", configPath]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()

        for port in Ports.all {
            try Self.waitUntilPortOpens(port: port, timeout: 10)
        }

        // Make the external-server provenance visible in XCTest output.
        // A green test alone only proves that *something* answered on the
        // fixture ports; this banner records the exact executable/version,
        // live child PID, generated config, and ports used by this run.
        let version = Self.toolVersion(executablePath: xrayPath)
        print("SERVER_EVIDENCE|||engine=xray-core|||path=\(xrayPath)|||version=\(version)|||pid=\(process.processIdentifier)|||config=\(configPath)|||ports=\(Ports.all.map(String.init).joined(separator: ","))")
    }

    deinit {
        process.terminate()
        try? FileManager.default.removeItem(at: tempDir)
    }

    // MARK: - Stale-process cleanup

    /// Finds and kills whatever process (almost certainly a previous run's
    /// orphaned xray-core, per this init's own doc comment above) currently
    /// holds any of `Ports.all`, via `lsof`. Best-effort: a failure here
    /// just means a stale process might still be squatting on a port, which
    /// `waitUntilPortOpens` will at least still confirm is *open* -- this
    /// only exists to make that "open" mean "opened by the process we're
    /// about to launch", not silently paper over one that never got killed.
    private static func killAnyProcessHoldingOurPorts() {
        for port in Ports.all {
            let lsof = Process()
            lsof.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
            lsof.arguments = ["-ti", "tcp:\(port)"]
            let pipe = Pipe()
            lsof.standardOutput = pipe
            lsof.standardError = FileHandle.nullDevice
            guard (try? lsof.run()) != nil else { continue }
            lsof.waitUntilExit()
            let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            for pidString in output.split(whereSeparator: \.isNewline) {
                guard let pid = pid_t(pidString) else { continue }
                kill(pid, SIGKILL)
            }
        }
        if !Ports.all.isEmpty { usleep(100_000) } // let the kernel release the ports
    }

    // MARK: - Self-signed cert (Trojan/VLESS-TLS)

    private static func generateSelfSignedCert(opensslPath: String, certPath: String, keyPath: String) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: opensslPath)
        process.arguments = [
            "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-keyout", keyPath, "-out", certPath, "-days", "3", "-nodes", "-subj", "/CN=localhost",
        ]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw XrayTestEnvironmentError.processFailed("openssl exited \(process.terminationStatus)")
        }
    }

    private static func toolVersion(executablePath: String) -> String {
        let versionProcess = Process()
        versionProcess.executableURL = URL(fileURLWithPath: executablePath)
        versionProcess.arguments = ["version"]
        let pipe = Pipe()
        versionProcess.standardOutput = pipe
        versionProcess.standardError = pipe
        guard (try? versionProcess.run()) != nil else { return "unknown" }
        versionProcess.waitUntilExit()
        return String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            .split(whereSeparator: \.isNewline).first.map(String.init) ?? "unknown"
    }

    // MARK: - xray JSON config

    private static func writeConfig(to path: String, certPath: String, keyPath: String) throws {
        let tlsSettings: [String: Any] = [
            "certificates": [["certificateFile": certPath, "keyFile": keyPath]],
        ]

        let inbounds: [[String: Any]] = [
            [
                "tag": "socks-in", "listen": host, "port": Ports.socks5, "protocol": "socks",
                "settings": ["auth": "noauth", "udp": true],
            ],
            [
                "tag": "http-in", "listen": host, "port": Ports.http, "protocol": "http",
                "settings": [String: Any](),
            ],
            [
                "tag": "vmess-in", "listen": host, "port": Ports.vmess, "protocol": "vmess",
                "settings": ["clients": [["id": vmessUUID, "alterId": 0]]],
            ],
            [
                "tag": "vless-in", "listen": host, "port": Ports.vless, "protocol": "vless",
                "settings": ["clients": [["id": vlessUUID, "flow": ""]], "decryption": "none"],
                "streamSettings": ["network": "tcp", "security": "tls", "tlsSettings": tlsSettings],
            ],
            [
                "tag": "trojan-in", "listen": host, "port": Ports.trojan, "protocol": "trojan",
                "settings": ["clients": [["password": trojanPassword]]],
                "streamSettings": ["network": "tcp", "security": "tls", "tlsSettings": tlsSettings],
            ],
            [
                "tag": "ss-in", "listen": host, "port": Ports.shadowsocks, "protocol": "shadowsocks",
                "settings": ["method": shadowsocksCipher.rawValue, "password": shadowsocksPassword, "network": "tcp,udp"],
            ],

            // Auxiliary spot-check variants (see `ProtocolVariantSpotChecks.swift`).
            [
                "tag": "socks-auth-in", "listen": host, "port": Ports.socks5WithAuth, "protocol": "socks",
                "settings": ["auth": "password", "accounts": [["user": spotCheckUsername, "pass": spotCheckPassword]], "udp": true],
            ],
            [
                "tag": "http-auth-in", "listen": host, "port": Ports.httpWithAuth, "protocol": "http",
                "settings": ["accounts": [["user": spotCheckUsername, "pass": spotCheckPassword]]],
            ],
            [
                "tag": "vless-notls-in", "listen": host, "port": Ports.vlessNoTLS, "protocol": "vless",
                "settings": ["clients": [["id": vlessUUID, "flow": ""]], "decryption": "none"],
            ],
            [
                "tag": "trojan-notls-in", "listen": host, "port": Ports.trojanNoTLS, "protocol": "trojan",
                "settings": ["clients": [["password": trojanPassword]]],
            ],
            [
                "tag": "ss-128-in", "listen": host, "port": Ports.shadowsocksAes128Gcm, "protocol": "shadowsocks",
                "settings": ["method": "aes-128-gcm", "password": shadowsocksPassword, "network": "tcp,udp"],
            ],
            [
                "tag": "ss-chacha-in", "listen": host, "port": Ports.shadowsocksChacha20, "protocol": "shadowsocks",
                "settings": ["method": "chacha20-ietf-poly1305", "password": shadowsocksPassword, "network": "tcp,udp"],
            ],
            [
                "tag": "vmess-ws-tls-in", "listen": host, "port": Ports.vmessWSTLS, "protocol": "vmess",
                "settings": ["clients": [["id": vmessUUID, "alterId": 0]]],
                "streamSettings": [
                    "network": "ws", "security": "tls",
                    "wsSettings": ["path": vmessWSPath],
                    "tlsSettings": tlsSettings,
                ],
            ],
            [
                "tag": "vless-ws-tls-in", "listen": host, "port": Ports.vlessWSTLS, "protocol": "vless",
                "settings": ["clients": [["id": vlessUUID, "flow": ""]], "decryption": "none"],
                "streamSettings": [
                    "network": "ws", "security": "tls",
                    "wsSettings": ["path": vlessWSPath],
                    "tlsSettings": tlsSettings,
                ],
            ],
            [
                "tag": "trojan-ws-in", "listen": host, "port": Ports.trojanWS, "protocol": "trojan",
                "settings": ["clients": [["password": trojanPassword]]],
                "streamSettings": [
                    "network": "ws", "security": "tls",
                    "wsSettings": ["path": trojanWSPath],
                    "tlsSettings": tlsSettings,
                ],
            ],
            [
                "tag": "ss2022-128-in", "listen": host, "port": Ports.shadowsocks2022Aes128Gcm, "protocol": "shadowsocks",
                "settings": ["method": "2022-blake3-aes-128-gcm", "password": shadowsocks2022PSK128, "network": "tcp"],
            ],
            [
                "tag": "ss2022-256-in", "listen": host, "port": Ports.shadowsocks2022Aes256Gcm, "protocol": "shadowsocks",
                "settings": ["method": "2022-blake3-aes-256-gcm", "password": shadowsocks2022PSK256, "network": "tcp"],
            ],
            [
                "tag": "ss2022-chacha-in", "listen": host, "port": Ports.shadowsocks2022Chacha20, "protocol": "shadowsocks",
                "settings": ["method": "2022-blake3-chacha20-poly1305", "password": shadowsocks2022PSK256, "network": "tcp"],
            ],

            // Remaining WS x TLS matrix corners (see `Ports.vmessTLSOnly` doc comment).
            [
                "tag": "vmess-tls-only-in", "listen": host, "port": Ports.vmessTLSOnly, "protocol": "vmess",
                "settings": ["clients": [["id": vmessUUID, "alterId": 0]]],
                "streamSettings": ["network": "tcp", "security": "tls", "tlsSettings": tlsSettings],
            ],
            [
                "tag": "vmess-ws-only-in", "listen": host, "port": Ports.vmessWSOnly, "protocol": "vmess",
                "settings": ["clients": [["id": vmessUUID, "alterId": 0]]],
                "streamSettings": ["network": "ws", "wsSettings": ["path": vmessWSOnlyPath]],
            ],
            [
                "tag": "vless-ws-only-in", "listen": host, "port": Ports.vlessWSOnly, "protocol": "vless",
                "settings": ["clients": [["id": vlessUUID, "flow": ""]], "decryption": "none"],
                "streamSettings": ["network": "ws", "wsSettings": ["path": vlessWSOnlyPath]],
            ],
        ]

        let config: [String: Any] = [
            "log": ["loglevel": "warning"],
            "inbounds": inbounds,
            "outbounds": [["protocol": "freedom", "tag": "direct"]],
        ]

        let data = try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted])
        try data.write(to: URL(fileURLWithPath: path))
    }

    // MARK: - Readiness polling

    /// Busy-polls a raw `connect()` against `port` until it succeeds or
    /// `timeout` elapses -- plain BSD sockets rather than `TCPConn`/Network.framework
    /// since this runs synchronously inside `init()`, before any async
    /// context exists.
    private static func waitUntilPortOpens(port: UInt16, timeout: TimeInterval) throws {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            let fd = socket(AF_INET, SOCK_STREAM, 0)
            guard fd >= 0 else { throw XrayTestEnvironmentError.processFailed("socket() failed") }
            defer { close(fd) }

            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            addr.sin_addr.s_addr = inet_addr(host)

            let result = withUnsafePointer(to: &addr) { pointer -> Int32 in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                    connect(fd, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            if result == 0 { return }
            usleep(50_000)
        } while Date() < deadline
        throw XrayTestEnvironmentError.portNeverOpened(port)
    }
}
