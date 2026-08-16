// HopDraft.swift
//
// A mutable, form-friendly stand-in for `ProxyHop` (whose `protocolConfig`
// is an enum with per-case payloads, awkward to bind directly to text
// fields). Every hop-editing screen -- a library node, a manually-typed
// chain hop -- edits one of these, then calls `makeHop()` to get back the
// real `ProxyHop` ChainCore expects.

import Foundation
import ChainCore
import ShadowsocksCore
import VMessCore
import HTTPProxyCore

enum HopProtocolKind: String, CaseIterable, Identifiable {
    case socks5, shadowsocks, vmess, trojan, vless, http

    var id: String { rawValue }

    var label: String {
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

struct HopDraft {
    var kind: HopProtocolKind = .socks5 {
        didSet {
            // Trojan defaults to TLS on (its whole design goal is to look
            // like ordinary HTTPS -- see `ChainCore`'s `ProxyHopProtocol.trojan`
            // doc comment); vmess/vless default to off. Only fires the
            // moment the picker switches *into* trojan, so it doesn't
            // clobber an existing toggle when switching between vmess/vless.
            if kind == .trojan && oldValue != .trojan { tls = true }
        }
    }
    var host: String = ""
    var port: String = ""
    var username: String = ""
    var password: String = ""
    var cipher: ShadowsocksCipher = .aes256Gcm
    var uuid: String = UUID().uuidString
    var vmessSecurity: VMessSecurity = .auto
    var sni: String = ""
    var allowInsecure: Bool = false
    /// Whether a `.vmess`/`.vless`/`.trojan` draft wraps the connection in
    /// TLS. Trojan defaults to `true` (its own design implies TLS; see
    /// `kind`'s `didSet` above); vmess/vless default to `false` (neither
    /// protocol's own wire format implies encryption, so it's opt-in -- see
    /// `ChainCore`'s `ProxyHopProtocol.vless` doc comment).
    var tls: Bool = false
    /// Whether a `.vmess`/`.vless`/`.trojan` draft wraps the connection in a
    /// WebSocket tunnel (between TLS, if any, and the protocol's own
    /// handshake) at `wsPath`, with `wsHostHeader` as the upgrade request's
    /// `Host:` header (defaults to `sni`/`host` when left blank).
    var useWebSocket: Bool = false
    var wsPath: String = ""
    var wsHostHeader: String = ""

    init() {}

    init(hop: ProxyHop) {
        host = hop.host
        port = String(hop.port)
        switch hop.protocolConfig {
        case .socks5(let auth):
            kind = .socks5
            if case .usernamePassword(let username, let password) = auth {
                self.username = username
                self.password = password
            }
        case .shadowsocks(let password, let cipher):
            kind = .shadowsocks
            self.password = password
            self.cipher = cipher
        case .vmess(let uuid, let security, let tls, let sni, let allowInsecure, let wsPath, let wsHost):
            kind = .vmess
            self.uuid = uuid
            self.vmessSecurity = security
            self.tls = tls
            self.sni = sni ?? ""
            self.allowInsecure = allowInsecure
            self.useWebSocket = wsPath != nil
            self.wsPath = wsPath ?? ""
            self.wsHostHeader = wsHost ?? ""
        case .trojan(let password, let tls, let sni, let allowInsecure, let wsPath, let wsHost):
            kind = .trojan
            self.password = password
            self.tls = tls
            self.sni = sni ?? ""
            self.allowInsecure = allowInsecure
            self.useWebSocket = wsPath != nil
            self.wsPath = wsPath ?? ""
            self.wsHostHeader = wsHost ?? ""
        case .vless(let uuid, let tls, let sni, let allowInsecure, let wsPath, let wsHost):
            kind = .vless
            self.uuid = uuid
            self.tls = tls
            self.sni = sni ?? ""
            self.allowInsecure = allowInsecure
            self.useWebSocket = wsPath != nil
            self.wsPath = wsPath ?? ""
            self.wsHostHeader = wsHost ?? ""
        case .http(let auth):
            kind = .http
            if case .usernamePassword(let username, let password) = auth {
                self.username = username
                self.password = password
            }
        }
    }

    var isValid: Bool {
        makeHop() != nil
    }

    /// `nil` when `useWebSocket` is off, or the field is left blank --
    /// shared by all three protocols' `wsPath`/`wsHost` construction below.
    private var trimmedWSPath: String? {
        guard useWebSocket else { return nil }
        let trimmed = wsPath.trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty ? "/" : trimmed
    }
    private var trimmedWSHost: String? {
        guard useWebSocket else { return nil }
        let trimmed = wsHostHeader.trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Builds the real `ProxyHop`, or `nil` if the draft is incomplete/invalid.
    func makeHop() -> ProxyHop? {
        let trimmedHost = host.trimmingCharacters(in: .whitespaces)
        guard !trimmedHost.isEmpty, let portValue = UInt16(port), portValue > 0 else { return nil }

        let protocolConfig: ProxyHopProtocol
        switch kind {
        case .socks5:
            if username.isEmpty || password.isEmpty {
                protocolConfig = .socks5(auth: .none)
            } else {
                protocolConfig = .socks5(auth: .usernamePassword(username: username, password: password))
            }
        case .shadowsocks:
            guard !password.isEmpty else { return nil }
            protocolConfig = .shadowsocks(password: password, cipher: cipher)
        case .vmess:
            guard UUID(uuidString: uuid) != nil else { return nil }
            let trimmedSNI = sni.trimmingCharacters(in: .whitespaces)
            protocolConfig = .vmess(
                uuid: uuid, security: vmessSecurity, tls: tls, sni: trimmedSNI.isEmpty ? nil : trimmedSNI, allowInsecure: allowInsecure,
                wsPath: trimmedWSPath, wsHost: trimmedWSHost
            )
        case .trojan:
            guard !password.isEmpty else { return nil }
            let trimmedSNI = sni.trimmingCharacters(in: .whitespaces)
            protocolConfig = .trojan(
                password: password, tls: tls, sni: trimmedSNI.isEmpty ? nil : trimmedSNI, allowInsecure: allowInsecure,
                wsPath: trimmedWSPath, wsHost: trimmedWSHost
            )
        case .vless:
            guard UUID(uuidString: uuid) != nil else { return nil }
            let trimmedSNI = sni.trimmingCharacters(in: .whitespaces)
            protocolConfig = .vless(
                uuid: uuid, tls: tls, sni: trimmedSNI.isEmpty ? nil : trimmedSNI, allowInsecure: allowInsecure,
                wsPath: trimmedWSPath, wsHost: trimmedWSHost
            )
        case .http:
            if username.isEmpty || password.isEmpty {
                protocolConfig = .http(auth: .none)
            } else {
                protocolConfig = .http(auth: .usernamePassword(username: username, password: password))
            }
        }
        return ProxyHop(host: trimmedHost, port: portValue, protocolConfig: protocolConfig)
    }
}
