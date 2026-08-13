// SubscriptionInteropTests.swift
//
// Part A of the plan: proves a subscription generated in the shapes real
// Clash/v2ray tooling actually emits -- not synthetic fixtures -- both (1)
// parses through `SubscriptionCore` into the expected hops, and (2) each
// resulting hop actually connects, through a real xray-core server, all the
// way to a local echo target. The Clash-YAML variant is additionally run
// through `mihomo -t` (a real Clash-family kernel's own config validator),
// since that's the one authenticity check Chainy's own hand-rolled parser
// can never provide for itself.

import XCTest
import Foundation
import ChainCore
import SubscriptionCore

final class SubscriptionInteropTests: XCTestCase {
    private func skipIfXrayUnavailable() throws {
        try XCTSkipUnless(XrayTestEnvironment.isAvailable, "xray/openssl not found on this machine")
    }

    private func skipIfMihomoUnavailable() throws {
        try XCTSkipUnless(ExternalTool.mihomo != nil, "mihomo not found on this machine")
    }

    // MARK: - Clash YAML (block-mapping style, mihomo's own default export shape)

    private var clashYAML: String {
        """
        mixed-port: 17890
        mode: rule
        log-level: warning

        proxies:
          - name: test-ss
            type: ss
            server: 127.0.0.1
            port: \(XrayTestEnvironment.Ports.shadowsocks)
            cipher: \(XrayTestEnvironment.shadowsocksCipher.rawValue)
            password: \(XrayTestEnvironment.shadowsocksPassword)
          - name: test-vmess
            type: vmess
            server: 127.0.0.1
            port: \(XrayTestEnvironment.Ports.vmess)
            uuid: \(XrayTestEnvironment.vmessUUID)
            alterId: 0
            cipher: none
          - name: test-socks5
            type: socks5
            server: 127.0.0.1
            port: \(XrayTestEnvironment.Ports.socks5)
          - name: test-trojan
            type: trojan
            server: 127.0.0.1
            port: \(XrayTestEnvironment.Ports.trojan)
            password: \(XrayTestEnvironment.trojanPassword)
            sni: localhost
            skip-cert-verify: true
          - name: test-vless
            type: vless
            server: 127.0.0.1
            port: \(XrayTestEnvironment.Ports.vless)
            uuid: \(XrayTestEnvironment.vlessUUID)
            network: tcp
            tls: true
            servername: localhost
            skip-cert-verify: true
          - name: test-http
            type: http
            server: 127.0.0.1
            port: \(XrayTestEnvironment.Ports.http)

        proxy-groups:
          - name: relay-test
            type: select
            proxies:
              - test-ss
              - test-vmess
              - test-socks5
              - test-trojan
              - test-vless
              - test-http

        rules:
          - MATCH,relay-test
        """
    }

    /// Authenticity check: a real Clash-family kernel (mihomo) accepts this
    /// as valid config, not just Chainy's own hand-rolled parser.
    func testGeneratedClashYAMLIsAuthenticMihomoConfig() throws {
        try skipIfMihomoUnavailable()

        let tempFile = FileManager.default.temporaryDirectory.appendingPathComponent("interop-clash-\(UUID().uuidString).yaml")
        try clashYAML.write(to: tempFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tempFile) }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: ExternalTool.mihomo!)
        process.arguments = ["-t", "-f", tempFile.path]
        let stderrPipe = Pipe()
        process.standardError = stderrPipe
        process.standardOutput = Pipe()
        try process.run()
        process.waitUntilExit()
        let stderrText = String(decoding: stderrPipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        XCTAssertEqual(process.terminationStatus, 0, "mihomo rejected the generated Clash config:\n\(stderrText)")
    }

    func testClashYAMLParsesIntoExpectedHopsAndEachDialsForReal() async throws {
        try skipIfXrayUnavailable()
        _ = XrayTestEnvironment.shared
        let (tcp, _) = try await EchoTargets.shared.value

        let result = SubscriptionParser.parse(clashYAML)
        XCTAssertTrue(result.skipped.isEmpty, "unexpected skips: \(result.skipped)")
        XCTAssertEqual(result.nodes.count, 6)

        for node in result.nodes {
            let payload = Array("hello-\(node.name)".utf8)
            let transport = try await ProxyChain.open(hops: [node.hop], finalTargetHost: XrayTestEnvironment.host, finalTargetPort: tcp.port)
            try await transport.send(payload, timeout: 5)
            let echoed = try await transport.readExactly(payload.count, timeout: 5)
            XCTAssertEqual(echoed, payload, "\(node.name) round-trip mismatch")
            transport.close()
        }
    }

    // MARK: - v2ray-style URI subscription (ss/vmess/trojan/vless/http share links)
    //
    // No `socks5://` scheme exists in this format (neither in real-world
    // practice nor in `V2RaySubscriptionParser`), so this variant covers 5
    // of the 6 protocols -- SOCKS5 is Clash-YAML-only, covered above.

    private var v2rayURISubscription: String {
        let ssCredential = Data("\(XrayTestEnvironment.shadowsocksCipher.rawValue):\(XrayTestEnvironment.shadowsocksPassword)".utf8).base64EncodedString()
        let ssLine = "ss://\(ssCredential)@127.0.0.1:\(XrayTestEnvironment.Ports.shadowsocks)#test-ss"

        let vmessJSON: [String: Any] = [
            "ps": "test-vmess", "add": "127.0.0.1", "port": Int(XrayTestEnvironment.Ports.vmess),
            "id": XrayTestEnvironment.vmessUUID, "net": "tcp", "tls": "",
        ]
        let vmessData = try! JSONSerialization.data(withJSONObject: vmessJSON)
        let vmessLine = "vmess://\(vmessData.base64EncodedString())"

        let trojanLine = "trojan://\(XrayTestEnvironment.trojanPassword)@127.0.0.1:\(XrayTestEnvironment.Ports.trojan)?sni=localhost&allowInsecure=1#test-trojan"

        let vlessLine = "vless://\(XrayTestEnvironment.vlessUUID)@127.0.0.1:\(XrayTestEnvironment.Ports.vless)?security=tls&sni=localhost&allowInsecure=1&type=tcp#test-vless"

        let httpLine = "http://127.0.0.1:\(XrayTestEnvironment.Ports.http)#test-http"

        return [ssLine, vmessLine, trojanLine, vlessLine, httpLine].joined(separator: "\n")
    }

    func testV2RayURISubscriptionParsesIntoExpectedHopsAndEachDialsForReal() async throws {
        try skipIfXrayUnavailable()
        _ = XrayTestEnvironment.shared
        let (tcp, _) = try await EchoTargets.shared.value

        let result = SubscriptionParser.parse(v2rayURISubscription)
        XCTAssertTrue(result.skipped.isEmpty, "unexpected skips: \(result.skipped)")
        XCTAssertEqual(result.nodes.count, 5)

        for node in result.nodes {
            let payload = Array("hello-\(node.name)".utf8)
            let transport = try await ProxyChain.open(hops: [node.hop], finalTargetHost: XrayTestEnvironment.host, finalTargetPort: tcp.port)
            try await transport.send(payload, timeout: 5)
            let echoed = try await transport.readExactly(payload.count, timeout: 5)
            XCTAssertEqual(echoed, payload, "\(node.name) round-trip mismatch")
            transport.close()
        }
    }
}
