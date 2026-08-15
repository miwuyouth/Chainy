import Foundation
import ChainCore

private struct UDPAppDataEnvelope: Decodable { let settings: ChainySettings }

private struct UDPOptions {
    var config = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/Chainy/AppData.json")
    var chainName: String?
    var resolvers: [(name: String, host: String)] = [
        ("Google", "8.8.8.8"),
        ("Cloudflare", "1.1.1.1"),
        ("Quad9", "9.9.9.9"),
        ("OpenDNS", "208.67.222.222"),
    ]
    var customResolvers = false
    var passes = 3
    var timeout: TimeInterval = 8
    var output: URL?
}

private struct UDPProbeResult: Codable {
    let timestamp: String
    let pass: Int
    let chain: String
    let resolverName: String
    let resolverHost: String
    let success: Bool
    let milliseconds: Int
    let bytesReceived: Int
    let error: String?
}

private func udpUsage(exitCode: Int32 = 2) -> Never {
    print("""
    Usage: chainy-diagnose udp [options]

      --resolver NAME=HOST  DNS resolver to probe (repeatable)
      --passes N            Number of passes (default: 3)
      --timeout SECONDS     Send/receive timeout (default: 8)
      --chain NAME          Saved chain name (default: active chain)
      --config PATH         AppData.json path
      --output PATH         Append machine-readable JSON Lines

    A non-zero exit status means at least one probe failed. Public DNS UDP/53
    can be blocked or rate-limited independently of the proxy protocol, so the
    per-resolver success rate is more informative than a single pass/fail label.
    The configuration is read-only and credentials are never printed.
    """)
    exit(exitCode)
}

private func parseUDPOptions(_ args: [String]) -> UDPOptions {
    var options = UDPOptions()
    var index = 0
    func value(_ flag: String) -> String {
        guard index + 1 < args.count else { print("Missing value for \(flag)"); udpUsage() }
        index += 1
        return args[index]
    }
    while index < args.count {
        switch args[index] {
        case "--resolver":
            let specification = value(args[index])
            guard let separator = specification.firstIndex(of: "="), separator != specification.startIndex else { udpUsage() }
            let name = String(specification[..<separator])
            let host = String(specification[specification.index(after: separator)...])
            guard !host.isEmpty else { udpUsage() }
            if !options.customResolvers { options.resolvers = []; options.customResolvers = true }
            options.resolvers.append((name, host))
        case "--passes":
            guard let count = Int(value(args[index])), count > 0 else { udpUsage() }
            options.passes = count
        case "--timeout":
            guard let timeout = Double(value(args[index])), timeout > 0 else { udpUsage() }
            options.timeout = timeout
        case "--chain": options.chainName = value(args[index])
        case "--config": options.config = URL(fileURLWithPath: value(args[index]))
        case "--output": options.output = URL(fileURLWithPath: value(args[index]))
        case "-h", "--help": udpUsage(exitCode: 0)
        default: print("Unknown UDP option: \(args[index])"); udpUsage()
        }
        index += 1
    }
    return options
}

private func loadUDPChain(_ options: UDPOptions) throws -> NamedProxyChain {
    let envelope = try JSONDecoder().decode(UDPAppDataEnvelope.self, from: Data(contentsOf: options.config))
    if let name = options.chainName {
        guard let chain = envelope.settings.chains.first(where: { $0.name == name }) else {
            throw NSError(domain: "UDPDiagnostic", code: 1, userInfo: [NSLocalizedDescriptionKey: "No saved chain named '\(name)'"])
        }
        return chain
    }
    guard let chain = envelope.settings.activeChain else {
        throw NSError(domain: "UDPDiagnostic", code: 2, userInfo: [NSLocalizedDescriptionKey: "No active chain"])
    }
    return chain
}

private func dnsQuery(id: UInt16, name: String = "example.com") -> [UInt8] {
    var bytes: [UInt8] = [
        UInt8(id >> 8), UInt8(id & 0xff), 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
    for label in name.split(separator: ".") {
        bytes.append(UInt8(label.utf8.count))
        bytes += label.utf8
    }
    bytes += [0x00, 0x00, 0x01, 0x00, 0x01]
    return bytes
}

private func isValidDNSResponse(_ bytes: [UInt8], id: UInt16) -> Bool {
    bytes.count >= 12 && UInt16(bytes[0]) << 8 | UInt16(bytes[1]) == id && bytes[2] & 0x80 != 0
}

private func appendUDPJSON(_ result: UDPProbeResult, to url: URL?) {
    guard let url, let data = try? JSONEncoder().encode(result) else { return }
    let line = data + Data([0x0a])
    if !FileManager.default.fileExists(atPath: url.path) {
        FileManager.default.createFile(atPath: url.path, contents: line)
    } else if let handle = try? FileHandle(forWritingTo: url) {
        defer { try? handle.close() }
        do { try handle.seekToEnd(); try handle.write(contentsOf: line) } catch {}
    }
}

func runUDPDiagnostic(arguments: [String]) async {
    let options = parseUDPOptions(arguments)
    do {
        let chain = try loadUDPChain(options)
        print("UDP test: \(chain.name) (\(chain.hops.count) hop(s)); config is read-only")
        var successesByResolver: [String: Int] = [:]
        var totalSuccesses = 0
        let totalAttempts = options.passes * options.resolvers.count

        for pass in 1...options.passes {
            for (resolverIndex, resolver) in options.resolvers.enumerated() {
                let id = UInt16(truncatingIfNeeded: 0x4000 + pass * 257 + resolverIndex)
                let started = Date()
                var bytesReceived = 0
                var failure: String?
                do {
                    let relay = try await ProxyChain.openUDPRelay(hops: chain.hops, connectTimeout: options.timeout, logID: "udp-diag")
                    defer { relay.close() }
                    try await relay.send(targetHost: resolver.host, targetPort: 53, payload: dnsQuery(id: id), timeout: options.timeout)
                    let reply = try await relay.receive(timeout: options.timeout)
                    bytesReceived = reply.payload.count
                    if !isValidDNSResponse(reply.payload, id: id) { failure = "invalid DNS response" }
                } catch {
                    failure = String(describing: error)
                }

                let elapsed = Int(Date().timeIntervalSince(started) * 1000)
                let success = failure == nil
                if success {
                    totalSuccesses += 1
                    successesByResolver[resolver.name, default: 0] += 1
                    print("PASS \(pass) \(resolver.name) \(resolver.host): \(bytesReceived) bytes, \(elapsed) ms")
                } else {
                    print("FAIL \(pass) \(resolver.name) \(resolver.host): \(failure!), \(elapsed) ms")
                }
                appendUDPJSON(UDPProbeResult(
                    timestamp: ISO8601DateFormatter().string(from: started), pass: pass, chain: chain.name,
                    resolverName: resolver.name, resolverHost: resolver.host, success: success,
                    milliseconds: elapsed, bytesReceived: bytesReceived, error: failure
                ), to: options.output)
            }
        }

        for resolver in options.resolvers {
            print("Resolver \(resolver.name): \(successesByResolver[resolver.name, default: 0])/\(options.passes)")
        }
        print("Result: \(totalSuccesses)/\(totalAttempts) valid UDP DNS replies")
        if totalSuccesses != totalAttempts { exit(1) }
    } catch {
        fputs("chainy-diagnose udp: \(error.localizedDescription)\n", stderr)
        exit(2)
    }
}
