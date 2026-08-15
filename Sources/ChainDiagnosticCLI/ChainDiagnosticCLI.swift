import Foundation
import ChainCore
import ProxyKit
import SOCKS5Core

private struct AppDataEnvelope: Decodable {
    let settings: ChainySettings
}

private struct Options {
    var config = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/Chainy/AppData.json")
    var chainName: String?
    var sites = [
        "https://www.google.com/generate_204",
        "https://www.cloudflare.com/cdn-cgi/trace",
        "https://www.apple.com/library/test/success.html",
        "https://www.microsoft.com/",
        "https://github.com/"
    ]
    var customSites = false
    var count = 20
    var interval: TimeInterval = 2
    var timeout: TimeInterval = 10
    var burst = 16
    var localPort: UInt16?
    var output: URL?
}

private enum ProbeStage: String, Codable {
    case tcpConnect, hopHandshake, tls, send, firstByte
}

private final class StageBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: ProbeStage = .tcpConnect
    func set(_ newValue: ProbeStage) { lock.withLock { value = newValue } }
    func get() -> ProbeStage { lock.withLock { value } }
}

private struct ProbeResult: Codable {
    let timestamp: String
    let round: Int
    let route: String
    let url: String
    let success: Bool
    let stage: ProbeStage
    let milliseconds: Int
    let bytesReceived: Int
    let statusLine: String?
    let error: String?
}

private func usage(exitCode: Int32 = 2) -> Never {
    print("""
    Usage: chainy-diagnose [options]

      --site URL            Site to probe (repeat for multiple sites)
      --sites-file PATH     Text file containing one URL per line
      --count N             Number of rounds (default: 20, 0 = forever)
      --interval SECONDS    Delay between rounds (default: 2)
      --timeout SECONDS     Per-stage timeout (default: 10)
      --burst N             Extra simultaneous browser-like requests (default: 16, 0 = off)
      --chain NAME          Saved chain name (default: active chain)
      --config PATH         AppData.json path
      --compare-local PORT  Also probe through the running Chainy listener
      --output PATH         Append machine-readable JSON Lines

    Each request uses a brand-new connection. The tool never modifies the
    configuration and never prints node credentials.
    """)
    exit(exitCode)
}

private func parseOptions(_ args: [String]) -> Options {
    var result = Options()
    var i = 0
    func value(_ flag: String) -> String {
        guard i + 1 < args.count else { print("Missing value for \(flag)"); usage() }
        i += 1
        return args[i]
    }
    while i < args.count {
        switch args[i] {
        case "--site":
            let site = value(args[i])
            if !result.customSites { result.sites = []; result.customSites = true }
            result.sites.append(site)
        case "--sites-file":
            let path = value(args[i])
            guard let contents = try? String(contentsOfFile: path, encoding: .utf8) else {
                fputs("Cannot read sites file: \(path)\n", stderr); exit(2)
            }
            if !result.customSites { result.sites = []; result.customSites = true }
            result.sites += contents.split(whereSeparator: \Character.isNewline)
                .map(String.init).map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty && !$0.hasPrefix("#") }
        case "--count":
            guard let n = Int(value(args[i])), n >= 0 else { usage() }
            result.count = n
        case "--interval":
            guard let n = Double(value(args[i])), n >= 0 else { usage() }
            result.interval = n
        case "--timeout":
            guard let n = Double(value(args[i])), n > 0 else { usage() }
            result.timeout = n
        case "--burst":
            guard let n = Int(value(args[i])), n >= 0, n <= 200 else { usage() }
            result.burst = n
        case "--chain": result.chainName = value(args[i])
        case "--config": result.config = URL(fileURLWithPath: value(args[i]))
        case "--compare-local":
            guard let port = UInt16(value(args[i])) else { usage() }
            result.localPort = port
        case "--output": result.output = URL(fileURLWithPath: value(args[i]))
        case "-h", "--help": usage(exitCode: 0)
        default: print("Unknown option: \(args[i])"); usage()
        }
        i += 1
    }
    return result
}

private func loadChain(_ options: Options) throws -> NamedProxyChain {
    let data = try Data(contentsOf: options.config)
    let settings = try JSONDecoder().decode(AppDataEnvelope.self, from: data).settings
    if let name = options.chainName {
        guard let chain = settings.chains.first(where: { $0.name == name }) else {
            throw NSError(domain: "ChainDiagnostic", code: 1, userInfo: [NSLocalizedDescriptionKey: "No saved chain named '\(name)'"])
        }
        return chain
    }
    guard let chain = settings.activeChain else {
        throw NSError(domain: "ChainDiagnostic", code: 2, userInfo: [NSLocalizedDescriptionKey: "No active chain in \(options.config.path)"])
    }
    return chain
}

private func normalizedURL(_ string: String) throws -> URL {
    guard let url = URL(string: string), let scheme = url.scheme?.lowercased(),
          scheme == "http" || scheme == "https", url.host != nil else {
        throw NSError(domain: "ChainDiagnostic", code: 3, userInfo: [NSLocalizedDescriptionKey: "Invalid HTTP(S) URL: \(string)"])
    }
    return url
}

private func probe(url: URL, hops: [ProxyHop], route: String, round: Int, timeout: TimeInterval) async -> ProbeResult {
    let started = Date()
    let stage = StageBox()
    var transport: (any ProxyTransport)?
    defer { transport?.close() }

    func result(success: Bool, bytes: Int = 0, status: String? = nil, error: Error? = nil) -> ProbeResult {
        ProbeResult(
            timestamp: ISO8601DateFormatter().string(from: started), round: round, route: route,
            url: url.absoluteString, success: success, stage: stage.get(),
            milliseconds: Int(Date().timeIntervalSince(started) * 1000), bytesReceived: bytes,
            statusLine: status, error: error.map { String(describing: $0) }
        )
    }

    do {
        let host = url.host!
        let isTLS = url.scheme?.lowercased() == "https"
        let port = UInt16(url.port ?? (isTLS ? 443 : 80))
        transport = try await ProxyChain.open(
            hops: hops, finalTargetHost: host, finalTargetPort: port,
            connectTimeout: timeout, logID: "diag-\(round)-\(route)",
            onTCPConnected: { stage.set(.hopHandshake) },
            onHandshakeComplete: { stage.set(.tls) }
        )
        if isTLS {
            stage.set(.tls)
            transport = try await TLSConn.handshake(over: transport!, options: TLSOptions(serverName: host), timeout: timeout)
        }
        var path = url.path.isEmpty ? "/" : url.path
        if let query = url.query { path += "?\(query)" }
        let request = "GET \(path) HTTP/1.1\r\nHost: \(host)\r\nUser-Agent: chainy-diagnose/1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        stage.set(.send)
        try await transport!.send(Array(request.utf8), timeout: timeout)
        stage.set(.firstByte)
        let chunk = try await transport!.readAvailable(timeout: timeout)
        guard !chunk.isEmpty else { return result(success: false, error: ProxyError.connectionClosed) }
        let text = String(decoding: chunk.prefix(512), as: UTF8.self)
        let status = text.components(separatedBy: "\r\n").first
        return result(success: true, bytes: chunk.count, status: status)
    } catch {
        return result(success: false, error: error)
    }
}

private func appendJSON(_ result: ProbeResult, to url: URL?) {
    guard let url, let data = try? JSONEncoder().encode(result) else { return }
    let line = data + Data([0x0a])
    if !FileManager.default.fileExists(atPath: url.path) {
        FileManager.default.createFile(atPath: url.path, contents: line)
    } else if let handle = try? FileHandle(forWritingTo: url) {
        defer { try? handle.close() }
        do { try handle.seekToEnd(); try handle.write(contentsOf: line) } catch {}
    }
}

private func printResult(_ r: ProbeResult) {
    let mark = r.success ? "OK " : "FAIL"
    let detail = r.success ? "\(r.bytesReceived) B \(r.statusLine ?? "response")" : "\(r.stage.rawValue): \(r.error ?? "unknown")"
    print(String(format: "[%03d] %-5@ %-12@ %5d ms  %@  %@", r.round, mark as NSString, r.route as NSString, r.milliseconds, r.url, detail))
}

@main
struct ChainDiagnosticCLI {
    static func main() async {
        var arguments = Array(CommandLine.arguments.dropFirst())
        if arguments.first == "udp" {
            arguments.removeFirst()
            await runUDPDiagnostic(arguments: arguments)
            return
        }
        if arguments.first == "http" { arguments.removeFirst() }
        let options = parseOptions(arguments)
        do {
            let chain = try loadChain(options)
            let sites = try options.sites.map(normalizedURL)
            guard !sites.isEmpty else { throw NSError(domain: "ChainDiagnostic", code: 4, userInfo: [NSLocalizedDescriptionKey: "No sites to test"]) }
            print("Chain: \(chain.name) (\(chain.hops.count) hop(s)); config is read-only")
            print("Site matrix: \(sites.count) probes + \(options.burst) simultaneous browser-like requests per route/round")
            if options.localPort != nil { print("Comparing direct ChainCore with the running local proxy") }
            print("")

            var round = 1
            while options.count == 0 || round <= options.count {
                // Auto Optimize can change activeChainID while this process is
                // running. Reload before every round so direct-core does not
                // remain pinned to the chain that happened to be active at
                // launch while local-proxy exercises a newly selected chain.
                let currentChain = try loadChain(options)
                var routes: [(String, [ProxyHop])] = [("direct-core", currentChain.hops)]
                if let port = options.localPort {
                    routes.append(("local-proxy", [ProxyHop(host: "127.0.0.1", port: port, protocolConfig: .socks5(auth: .none))]))
                }
                var results: [ProbeResult] = []
                await withTaskGroup(of: ProbeResult.self) { group in
                    for (route, hops) in routes {
                        for (index, site) in sites.enumerated() {
                            group.addTask { await probe(url: site, hops: hops, route: route + "/site-\(index + 1)", round: round, timeout: options.timeout) }
                        }
                        // Browsers commonly fan a page load out into many
                        // simultaneous CONNECT/TLS transactions. These use
                        // independent sockets and a spread of destinations;
                        // that deliberately stresses accept bookkeeping,
                        // per-connection protocol state, and the two relay
                        // pumps without pretending to implement HTTP/2 here.
                        if options.burst > 0 {
                            for index in 0..<options.burst {
                                let site = sites[index % sites.count]
                                group.addTask {
                                    await probe(
                                        url: site, hops: hops,
                                        route: route + "/burst-\(String(format: "%03d", index + 1))",
                                        round: round, timeout: options.timeout
                                    )
                                }
                            }
                        }
                    }
                    for await result in group { results.append(result) }
                }
                // An isolated failure is the interesting symptom here. Retry it
                // immediately over a fresh connection to distinguish a transient
                // per-connection failure from a destination that remains down.
                let failed = results.filter { !$0.success }
                for failure in failed {
                    guard let site = URL(string: failure.url),
                          let route = routes.first(where: { failure.route.hasPrefix($0.0 + "/") }) else { continue }
                    let retry = await probe(url: site, hops: route.1, route: failure.route + "/retry", round: round, timeout: options.timeout)
                    results.append(retry)
                }
                for result in results.sorted(by: { $0.route < $1.route }) {
                    printResult(result)
                    appendJSON(result, to: options.output)
                }
                fflush(stdout)
                round += 1
                if options.count == 0 || round <= options.count {
                    try await Task.sleep(nanoseconds: UInt64(options.interval * 1_000_000_000))
                }
            }
        } catch {
            fputs("chainy-diagnose: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }
}
