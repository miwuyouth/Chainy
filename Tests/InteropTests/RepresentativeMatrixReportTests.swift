// RepresentativeMatrixReportTests.swift
//
// A representative (not exhaustive) cross-validation report: one real
// end-to-end TCP/UDP transfer per point in the "does every parameter
// combination actually work" matrix -- every protocol's WS on/off x TLS
// on/off corners where the client supports both axes (vmess, vless),
// every auxiliary variant (auth, cipher choice) already covered by
// `ProtocolVariantSpotChecks`, a handful of representative chains from
// 2 to 5 hops (including a protocol-repeat shape), and the distinct real
// UDP relay paths (`ProxyChain.openUDPRelay`'s per-last-hop dispatch).
//
// Unlike `ChainExhaustiveTCPTests`/`ChainExhaustiveUDPTests` (9,330
// combinations each, too many to eyeball), every case here prints one
// `REPORT_ROW` line with the actual bytes sent and actually received, so
// results can be cross-checked by hand against this file's own case
// definitions rather than trusted from a pass/fail count alone.

import XCTest
import ChainCore
import ProxyKit

final class RepresentativeMatrixReportTests: XCTestCase {
    private func skipIfUnavailable() throws {
        try XCTSkipUnless(XrayTestEnvironment.isAvailable, "xray/openssl not found on this machine")
    }

    private enum Kind {
        case tcp
        case udpRelay
        case udpRefused(expectedProtocolName: String)
    }

    private struct MatrixCase {
        let id: String
        let description: String
        let hops: [ProxyHop]
        let kind: Kind
    }

    private func emit(_ id: String, _ description: String, sent: String, received: String, status: String, detail: String) {
        print("REPORT_ROW|||\(id)|||\(description)|||\(sent)|||\(received)|||\(status)|||\(detail)")
    }

    private func runTCP(_ c: MatrixCase, tcpEchoPort: UInt16) async {
        let sent = "\(c.id)-\(c.description)"
        let payload = Array(sent.utf8)
        do {
            let transport = try await ProxyChain.open(
                hops: c.hops, finalTargetHost: XrayTestEnvironment.host, finalTargetPort: tcpEchoPort, connectTimeout: 10
            )
            defer { transport.close() }
            try await transport.send(payload, timeout: 10)
            let echoed = try await transport.readExactly(payload.count, timeout: 10)
            let received = String(decoding: echoed, as: UTF8.self)
            if echoed == payload {
                emit(c.id, c.description, sent: sent, received: received, status: "PASS", detail: "match")
            } else {
                emit(c.id, c.description, sent: sent, received: received, status: "FAIL", detail: "byte mismatch")
                XCTFail("[\(c.id)] \(c.description): echo mismatch")
            }
        } catch {
            emit(c.id, c.description, sent: sent, received: "", status: "FAIL", detail: "\(error)")
            XCTFail("[\(c.id)] \(c.description): \(error)")
        }
    }

    private func runUDPRelay(_ c: MatrixCase, udpEchoPort: UInt16) async {
        let sent = "\(c.id)-\(c.description)"
        let payload = Array(sent.utf8)
        do {
            let relay = try await ProxyChain.openUDPRelay(hops: c.hops, connectTimeout: 20)
            defer { relay.close() }
            try await relay.send(targetHost: XrayTestEnvironment.host, targetPort: udpEchoPort, payload: payload, timeout: 20)
            let (_, _, echoed) = try await relay.receive(timeout: 20)
            let received = String(decoding: echoed, as: UTF8.self)
            if echoed == payload {
                emit(c.id, c.description, sent: sent, received: received, status: "PASS", detail: "match")
            } else {
                emit(c.id, c.description, sent: sent, received: received, status: "FAIL", detail: "byte mismatch")
                XCTFail("[\(c.id)] \(c.description): UDP echo mismatch")
            }
        } catch {
            emit(c.id, c.description, sent: sent, received: "", status: "FAIL", detail: "\(error)")
            XCTFail("[\(c.id)] \(c.description): \(error)")
        }
    }

    private func runUDPRefused(_ c: MatrixCase, expectedProtocolName: String) async {
        let sent = "\(c.id)-\(c.description) (expect refusal)"
        do {
            _ = try await ProxyChain.openUDPRelay(hops: c.hops, connectTimeout: 10)
            emit(c.id, c.description, sent: sent, received: "", status: "FAIL", detail: "expected udpUnsupportedLastHop but relay opened")
            XCTFail("[\(c.id)] \(c.description): expected UDP to be refused but openUDPRelay succeeded")
        } catch ProxyChainError.udpUnsupportedLastHop(let protocolName) {
            if protocolName == expectedProtocolName {
                emit(c.id, c.description, sent: sent, received: "udpUnsupportedLastHop(\(protocolName))", status: "PASS", detail: "refused as expected")
            } else {
                emit(c.id, c.description, sent: sent, received: "udpUnsupportedLastHop(\(protocolName))", status: "FAIL", detail: "refused for wrong hop name")
                XCTFail("[\(c.id)] \(c.description): refused for wrong hop's name")
            }
        } catch {
            emit(c.id, c.description, sent: sent, received: "", status: "FAIL", detail: "\(error)")
            XCTFail("[\(c.id)] \(c.description): unexpected error \(error)")
        }
    }

    /// Every case in the representative matrix. Built lazily (inside the
    /// test method, not a stored property) since several hops reference
    /// `XrayTestEnvironment` constants that are cheap but pointless to
    /// evaluate if the whole suite is about to skip.
    private func buildCases() -> [MatrixCase] {
        let host = XrayTestEnvironment.host
        func hop(_ port: UInt16, _ config: ProxyHopProtocol) -> ProxyHop { ProxyHop(host: host, port: port, protocolConfig: config) }

        return [
            // MARK: Single-hop parameter matrix (TC01-TC20)
            MatrixCase(id: "TC01", description: "socks5-noauth", hops: [CanonicalProtocol.socks5.hop()], kind: .tcp),
            MatrixCase(id: "TC02", description: "socks5-userpass-auth", hops: [
                hop(XrayTestEnvironment.Ports.socks5WithAuth, .socks5(auth: .usernamePassword(username: XrayTestEnvironment.spotCheckUsername, password: XrayTestEnvironment.spotCheckPassword))),
            ], kind: .tcp),
            MatrixCase(id: "TC03", description: "http-noauth", hops: [CanonicalProtocol.http.hop()], kind: .tcp),
            MatrixCase(id: "TC04", description: "http-userpass-auth", hops: [
                hop(XrayTestEnvironment.Ports.httpWithAuth, .http(auth: .usernamePassword(username: XrayTestEnvironment.spotCheckUsername, password: XrayTestEnvironment.spotCheckPassword))),
            ], kind: .tcp),
            MatrixCase(id: "TC05", description: "shadowsocks-aes256gcm", hops: [CanonicalProtocol.shadowsocks.hop()], kind: .tcp),
            MatrixCase(id: "TC06", description: "shadowsocks-aes128gcm", hops: [
                hop(XrayTestEnvironment.Ports.shadowsocksAes128Gcm, .shadowsocks(password: XrayTestEnvironment.shadowsocksPassword, cipher: .aes128Gcm)),
            ], kind: .tcp),
            MatrixCase(id: "TC07", description: "shadowsocks-chacha20-ietf-poly1305", hops: [
                hop(XrayTestEnvironment.Ports.shadowsocksChacha20, .shadowsocks(password: XrayTestEnvironment.shadowsocksPassword, cipher: .chacha20IetfPoly1305)),
            ], kind: .tcp),
            MatrixCase(id: "TC08", description: "shadowsocks2022-aes128gcm", hops: [
                hop(XrayTestEnvironment.Ports.shadowsocks2022Aes128Gcm, .shadowsocks(password: XrayTestEnvironment.shadowsocks2022PSK128, cipher: .aead2022Blake3Aes128Gcm)),
            ], kind: .tcp),
            MatrixCase(id: "TC09", description: "shadowsocks2022-aes256gcm", hops: [
                hop(XrayTestEnvironment.Ports.shadowsocks2022Aes256Gcm, .shadowsocks(password: XrayTestEnvironment.shadowsocks2022PSK256, cipher: .aead2022Blake3Aes256Gcm)),
            ], kind: .tcp),
            MatrixCase(id: "TC10", description: "shadowsocks2022-chacha20-poly1305", hops: [
                hop(XrayTestEnvironment.Ports.shadowsocks2022Chacha20, .shadowsocks(password: XrayTestEnvironment.shadowsocks2022PSK256, cipher: .aead2022Blake3Chacha20Poly1305)),
            ], kind: .tcp),
            MatrixCase(id: "TC11", description: "vmess-plain-noWS-noTLS", hops: [CanonicalProtocol.vmess.hop()], kind: .tcp),
            MatrixCase(id: "TC12", description: "vmess-TLS-noWS", hops: [
                hop(XrayTestEnvironment.Ports.vmessTLSOnly, .vmess(uuid: XrayTestEnvironment.vmessUUID, tls: true, sni: "localhost", allowInsecure: true)),
            ], kind: .tcp),
            MatrixCase(id: "TC13", description: "vmess-WS-noTLS", hops: [
                hop(XrayTestEnvironment.Ports.vmessWSOnly, .vmess(uuid: XrayTestEnvironment.vmessUUID, tls: false, wsPath: XrayTestEnvironment.vmessWSOnlyPath, wsHost: "localhost")),
            ], kind: .tcp),
            MatrixCase(id: "TC14", description: "vmess-WS-TLS", hops: [
                hop(XrayTestEnvironment.Ports.vmessWSTLS, .vmess(uuid: XrayTestEnvironment.vmessUUID, tls: true, sni: "localhost", allowInsecure: true, wsPath: XrayTestEnvironment.vmessWSPath, wsHost: "localhost")),
            ], kind: .tcp),
            MatrixCase(id: "TC15", description: "vless-plain-noWS-noTLS", hops: [
                hop(XrayTestEnvironment.Ports.vlessNoTLS, .vless(uuid: XrayTestEnvironment.vlessUUID, tls: false)),
            ], kind: .tcp),
            MatrixCase(id: "TC16", description: "vless-TLS-noWS", hops: [CanonicalProtocol.vless.hop()], kind: .tcp),
            MatrixCase(id: "TC17", description: "vless-WS-noTLS", hops: [
                hop(XrayTestEnvironment.Ports.vlessWSOnly, .vless(uuid: XrayTestEnvironment.vlessUUID, tls: false, wsPath: XrayTestEnvironment.vlessWSOnlyPath, wsHost: "localhost")),
            ], kind: .tcp),
            MatrixCase(id: "TC18", description: "vless-WS-TLS", hops: [
                hop(XrayTestEnvironment.Ports.vlessWSTLS, .vless(uuid: XrayTestEnvironment.vlessUUID, tls: true, sni: "localhost", allowInsecure: true, wsPath: XrayTestEnvironment.vlessWSPath, wsHost: "localhost")),
            ], kind: .tcp),
            MatrixCase(id: "TC19", description: "trojan-TLS-noWS (always TLS)", hops: [CanonicalProtocol.trojan.hop()], kind: .tcp),
            MatrixCase(id: "TC20", description: "trojan-WS-TLS", hops: [
                hop(XrayTestEnvironment.Ports.trojanWS, .trojan(password: XrayTestEnvironment.trojanPassword, sni: "localhost", allowInsecure: true, wsPath: XrayTestEnvironment.trojanWSPath, wsHost: "localhost")),
            ], kind: .tcp),

            // MARK: Representative chains, 2-5 hops (TC21-TC25)
            MatrixCase(id: "TC21", description: "chain2: socks5->vmess(ws+tls)", hops: [
                CanonicalProtocol.socks5.hop(),
                hop(XrayTestEnvironment.Ports.vmessWSTLS, .vmess(uuid: XrayTestEnvironment.vmessUUID, tls: true, sni: "localhost", allowInsecure: true, wsPath: XrayTestEnvironment.vmessWSPath, wsHost: "localhost")),
            ], kind: .tcp),
            MatrixCase(id: "TC22", description: "chain3: socks5->trojan(ws)->vmess(ws+tls)", hops: [
                CanonicalProtocol.socks5.hop(),
                hop(XrayTestEnvironment.Ports.trojanWS, .trojan(password: XrayTestEnvironment.trojanPassword, sni: "localhost", allowInsecure: true, wsPath: XrayTestEnvironment.trojanWSPath, wsHost: "localhost")),
                hop(XrayTestEnvironment.Ports.vmessWSTLS, .vmess(uuid: XrayTestEnvironment.vmessUUID, tls: true, sni: "localhost", allowInsecure: true, wsPath: XrayTestEnvironment.vmessWSPath, wsHost: "localhost")),
            ], kind: .tcp),
            MatrixCase(id: "TC23", description: "chain4: http->shadowsocks->vless(ws+tls)->trojan(ws)", hops: [
                CanonicalProtocol.http.hop(),
                CanonicalProtocol.shadowsocks.hop(),
                hop(XrayTestEnvironment.Ports.vlessWSTLS, .vless(uuid: XrayTestEnvironment.vlessUUID, tls: true, sni: "localhost", allowInsecure: true, wsPath: XrayTestEnvironment.vlessWSPath, wsHost: "localhost")),
                hop(XrayTestEnvironment.Ports.trojanWS, .trojan(password: XrayTestEnvironment.trojanPassword, sni: "localhost", allowInsecure: true, wsPath: XrayTestEnvironment.trojanWSPath, wsHost: "localhost")),
            ], kind: .tcp),
            MatrixCase(id: "TC24", description: "chain5: socks5->http->shadowsocks->vless->vmess (5 distinct protocols)", hops: [
                CanonicalProtocol.socks5.hop(),
                CanonicalProtocol.http.hop(),
                CanonicalProtocol.shadowsocks.hop(),
                CanonicalProtocol.vless.hop(),
                CanonicalProtocol.vmess.hop(),
            ], kind: .tcp),
            MatrixCase(id: "TC25", description: "chain5-repeat: vmess->vmess->trojan->trojan->vless", hops: [
                CanonicalProtocol.vmess.hop(),
                CanonicalProtocol.vmess.hop(),
                CanonicalProtocol.trojan.hop(),
                CanonicalProtocol.trojan.hop(),
                CanonicalProtocol.vless.hop(),
            ], kind: .tcp),

            // MARK: UDP relay dispatch (TC26-TC30)
            MatrixCase(id: "TC26", description: "udp: every hop shadowsocks (real relay)", hops: [CanonicalProtocol.shadowsocks.hop()], kind: .udpRelay),
            MatrixCase(id: "TC27", description: "udp: last hop vmess (real relay)", hops: [CanonicalProtocol.socks5.hop(), CanonicalProtocol.vmess.hop()], kind: .udpRelay),
            MatrixCase(id: "TC28", description: "udp: last hop vless (real relay)", hops: [CanonicalProtocol.http.hop(), CanonicalProtocol.vless.hop()], kind: .udpRelay),
            MatrixCase(id: "TC29", description: "udp: last hop trojan (real relay)", hops: [CanonicalProtocol.shadowsocks.hop(), CanonicalProtocol.trojan.hop()], kind: .udpRelay),
            MatrixCase(id: "TC30", description: "udp: last hop socks5 (prefix carries relay)", hops: [CanonicalProtocol.vmess.hop(), CanonicalProtocol.socks5.hop()], kind: .udpRelay),
        ]
    }

    func testRepresentativeMatrixReport() async throws {
        try skipIfUnavailable()
        _ = XrayTestEnvironment.shared
        let (tcp, udp) = try await EchoTargets.shared.value

        for c in buildCases() {
            switch c.kind {
            case .tcp: await runTCP(c, tcpEchoPort: tcp.port)
            case .udpRelay: await runUDPRelay(c, udpEchoPort: udp.port)
            case .udpRefused(let expectedProtocolName): await runUDPRefused(c, expectedProtocolName: expectedProtocolName)
            }
        }
    }
}
