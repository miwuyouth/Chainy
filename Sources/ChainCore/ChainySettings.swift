// ChainySettings.swift
//
// `ChainySettings` on its own encodes/decodes as just a *list* of named
// chains plus which one, if any, is currently active/selected -- since a
// user builds up more than one saved chain over time (a home relay, a work
// relay, ...). Each chain itself is just an ordered hop list: unlike
// ChainDemoCLI's one-shot `<hop>... <target-host:port>` command-line
// arguments (see ChainDemoCLI/main.swift), a saved chain has no fixed final
// target of its own -- Chainy relays each client connection to whatever
// destination *that* client's own SOCKS5 CONNECT request asked for (see
// LocalProxyServer), so baking a single target into the saved chain would
// misrepresent what it's actually used for.
//
// Shape in isolation:
//
//   {
//     "chains": [
//       {
//         "id": "3F2504E0-4F89-11D3-9A0C-0305E82C3301",
//         "name": "Home relay",
//         "hops": [
//           { "protocol": "socks5", "host": "127.0.0.1", "port": 28401 },
//           { "protocol": "shadowsocks", "host": "127.0.0.1", "port": 28402, "password": "mypassword", "cipher": "aes-256-gcm" },
//           { "protocol": "vmess", "host": "127.0.0.1", "port": 28403, "uuid": "0398d470-bc09-4cd5-889d-3ae4c569b6da" },
//           { "protocol": "trojan", "host": "127.0.0.1", "port": 28404, "password": "mypassword", "sni": "example.com", "allowInsecure": false },
//           { "protocol": "trojan", "host": "127.0.0.1", "port": 28414, "password": "mypassword", "tls": false },
//           { "protocol": "vless", "host": "127.0.0.1", "port": 28406, "uuid": "0398d470-bc09-4cd5-889d-3ae4c569b6da", "tls": true, "sni": "example.com", "allowInsecure": false },
//           { "protocol": "vless", "host": "127.0.0.1", "port": 28407, "uuid": "0398d470-bc09-4cd5-889d-3ae4c569b6da", "tls": true, "sni": "example.com", "wsPath": "/ray", "wsHost": "example.com" },
//           { "protocol": "http", "host": "127.0.0.1", "port": 28405, "username": "u", "password": "p" }
//         ]
//       }
//     ],
//     "activeChainID": "3F2504E0-4F89-11D3-9A0C-0305E82C3301"
//   }
//
// A SOCKS5 or HTTP hop may add "username"/"password" for username/password
// auth; omitting both means `.none`. "cipher" is one of `ShadowsocksCipher`'s
// raw values (aes-128-gcm/aes-256-gcm/chacha20-ietf-poly1305). A trojan hop's
// "tls" is optional and defaults to true (Trojan's own design implies TLS; a
// bare-metal deployment can still turn it off, and only that non-default
// false is ever written out), and its "sni"/"allowInsecure" are optional
// (defaulting to "host"/false) and only meaningful when "tls" is true. A
// vmess/vless hop's "tls" is optional too but defaults to false instead
// (opposite of trojan's default, and only ever written out when true) --
// unlike trojan, neither protocol's own wire format implies encryption, so
// TLS is opt-in rather than implied); its "sni"/"allowInsecure" mean the same
// as trojan's, but are only meaningful when "tls" is true. Any
// vmess/vless/trojan hop may also add "wsPath" (opts into wrapping the
// connection in a WebSocket tunnel -- between TLS, if any, and the
// protocol's own handshake -- at that path) and "wsHost" (the WS upgrade
// request's "Host:" header, defaulting to "sni" or "host" when omitted).
// `id` is a stable identifier that survives renaming `name` -- it's what
// `activeChainID` (and, later, any "last used" bookkeeping) points at
// instead of a name.
//
// Chainy (the GUI frontend) doesn't write this shape to disk directly,
// though: it persists one combined file -- AppStore's `AppData` -- with this
// type's encoding nested under a top-level "settings" key, alongside
// "library" and "subscriptions" arrays that are Chainy-only concepts
// (see AppStore.swift). See ChainySettings.example.json for the
// checked-in copy of that combined shape this module is tested against
// (ChainySettingsTests.testLoadsCheckedInExampleFile).

import Foundation
import SOCKS5Core
import ShadowsocksCore
import HTTPProxyCore

extension ProxyHop: Codable {
    private enum CodingKeys: String, CodingKey {
        case protocolName = "protocol"
        case host, port, username, password, cipher, uuid, sni, allowInsecure, tls
        case wsPath, wsHost
    }

    private enum ProtocolName: String, Codable {
        case socks5, shadowsocks, vmess, trojan, vless, http
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let host = try container.decode(String.self, forKey: .host)
        let port = try container.decode(UInt16.self, forKey: .port)

        let protocolConfig: ProxyHopProtocol
        switch try container.decode(ProtocolName.self, forKey: .protocolName) {
        case .socks5:
            let username = try container.decodeIfPresent(String.self, forKey: .username)
            let password = try container.decodeIfPresent(String.self, forKey: .password)
            if let username, let password {
                protocolConfig = .socks5(auth: .usernamePassword(username: username, password: password))
            } else {
                protocolConfig = .socks5(auth: .none)
            }

        case .shadowsocks:
            guard let password = try container.decodeIfPresent(String.self, forKey: .password) else {
                throw DecodingError.keyNotFound(
                    CodingKeys.password,
                    .init(codingPath: decoder.codingPath, debugDescription: "shadowsocks hop needs \"password\"")
                )
            }
            let cipherRaw = try container.decode(String.self, forKey: .cipher)
            guard let cipher = ShadowsocksCipher(rawValue: cipherRaw) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .cipher, in: container,
                    debugDescription: "unknown cipher \"\(cipherRaw)\", expected one of \(ShadowsocksCipher.allCases.map(\.rawValue).joined(separator: ", "))"
                )
            }
            protocolConfig = .shadowsocks(password: password, cipher: cipher)

        case .vmess:
            let uuid = try container.decode(String.self, forKey: .uuid)
            guard UUID(uuidString: uuid) != nil else {
                throw DecodingError.dataCorruptedError(forKey: .uuid, in: container, debugDescription: "\"\(uuid)\" is not a valid UUID")
            }
            let tls = try container.decodeIfPresent(Bool.self, forKey: .tls) ?? false
            let sni = try container.decodeIfPresent(String.self, forKey: .sni)
            let allowInsecure = try container.decodeIfPresent(Bool.self, forKey: .allowInsecure) ?? false
            let wsPath = try container.decodeIfPresent(String.self, forKey: .wsPath)
            let wsHost = try container.decodeIfPresent(String.self, forKey: .wsHost)
            protocolConfig = .vmess(uuid: uuid, tls: tls, sni: sni, allowInsecure: allowInsecure, wsPath: wsPath, wsHost: wsHost)

        case .trojan:
            guard let password = try container.decodeIfPresent(String.self, forKey: .password) else {
                throw DecodingError.keyNotFound(
                    CodingKeys.password,
                    .init(codingPath: decoder.codingPath, debugDescription: "trojan hop needs \"password\"")
                )
            }
            let tls = try container.decodeIfPresent(Bool.self, forKey: .tls) ?? true
            let sni = try container.decodeIfPresent(String.self, forKey: .sni)
            let allowInsecure = try container.decodeIfPresent(Bool.self, forKey: .allowInsecure) ?? false
            let wsPath = try container.decodeIfPresent(String.self, forKey: .wsPath)
            let wsHost = try container.decodeIfPresent(String.self, forKey: .wsHost)
            protocolConfig = .trojan(password: password, tls: tls, sni: sni, allowInsecure: allowInsecure, wsPath: wsPath, wsHost: wsHost)

        case .vless:
            let uuid = try container.decode(String.self, forKey: .uuid)
            guard UUID(uuidString: uuid) != nil else {
                throw DecodingError.dataCorruptedError(forKey: .uuid, in: container, debugDescription: "\"\(uuid)\" is not a valid UUID")
            }
            let tls = try container.decodeIfPresent(Bool.self, forKey: .tls) ?? false
            let sni = try container.decodeIfPresent(String.self, forKey: .sni)
            let allowInsecure = try container.decodeIfPresent(Bool.self, forKey: .allowInsecure) ?? false
            let wsPath = try container.decodeIfPresent(String.self, forKey: .wsPath)
            let wsHost = try container.decodeIfPresent(String.self, forKey: .wsHost)
            protocolConfig = .vless(uuid: uuid, tls: tls, sni: sni, allowInsecure: allowInsecure, wsPath: wsPath, wsHost: wsHost)

        case .http:
            let username = try container.decodeIfPresent(String.self, forKey: .username)
            let password = try container.decodeIfPresent(String.self, forKey: .password)
            if let username, let password {
                protocolConfig = .http(auth: .usernamePassword(username: username, password: password))
            } else {
                protocolConfig = .http(auth: .none)
            }
        }

        self.init(host: host, port: port, protocolConfig: protocolConfig)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(host, forKey: .host)
        try container.encode(port, forKey: .port)

        switch protocolConfig {
        case .socks5(let auth):
            try container.encode(ProtocolName.socks5, forKey: .protocolName)
            if case .usernamePassword(let username, let password) = auth {
                try container.encode(username, forKey: .username)
                try container.encode(password, forKey: .password)
            }

        case .shadowsocks(let password, let cipher):
            try container.encode(ProtocolName.shadowsocks, forKey: .protocolName)
            try container.encode(password, forKey: .password)
            try container.encode(cipher.rawValue, forKey: .cipher)

        case .vmess(let uuid, let tls, let sni, let allowInsecure, let wsPath, let wsHost):
            try container.encode(ProtocolName.vmess, forKey: .protocolName)
            try container.encode(uuid, forKey: .uuid)
            if tls { try container.encode(tls, forKey: .tls) }
            try container.encodeIfPresent(sni, forKey: .sni)
            if allowInsecure { try container.encode(allowInsecure, forKey: .allowInsecure) }
            try container.encodeIfPresent(wsPath, forKey: .wsPath)
            try container.encodeIfPresent(wsHost, forKey: .wsHost)

        case .trojan(let password, let tls, let sni, let allowInsecure, let wsPath, let wsHost):
            try container.encode(ProtocolName.trojan, forKey: .protocolName)
            try container.encode(password, forKey: .password)
            if !tls { try container.encode(tls, forKey: .tls) }
            try container.encodeIfPresent(sni, forKey: .sni)
            if allowInsecure { try container.encode(allowInsecure, forKey: .allowInsecure) }
            try container.encodeIfPresent(wsPath, forKey: .wsPath)
            try container.encodeIfPresent(wsHost, forKey: .wsHost)

        case .vless(let uuid, let tls, let sni, let allowInsecure, let wsPath, let wsHost):
            try container.encode(ProtocolName.vless, forKey: .protocolName)
            try container.encode(uuid, forKey: .uuid)
            if tls { try container.encode(tls, forKey: .tls) }
            try container.encodeIfPresent(sni, forKey: .sni)
            if allowInsecure { try container.encode(allowInsecure, forKey: .allowInsecure) }
            try container.encodeIfPresent(wsPath, forKey: .wsPath)
            try container.encodeIfPresent(wsHost, forKey: .wsHost)

        case .http(let auth):
            try container.encode(ProtocolName.http, forKey: .protocolName)
            if case .usernamePassword(let username, let password) = auth {
                try container.encode(username, forKey: .username)
                try container.encode(password, forKey: .password)
            }
        }
    }
}

/// One saved, nameable chain: just an ordered hop list. `id` is a stable
/// identifier that survives renaming `name` -- it's what
/// `ChainySettings.activeChainID` points at, and what a GUI list view
/// would key its rows on (`Identifiable`).
public struct NamedProxyChain: Codable, Equatable, Identifiable {
    public let id: UUID
    public var name: String
    public var hops: [ProxyHop]

    private enum CodingKeys: String, CodingKey {
        case id, name, hops
    }

    public init(id: UUID = UUID(), name: String, hops: [ProxyHop]) {
        self.id = id
        self.name = name
        self.hops = hops
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let hops = try container.decode([ProxyHop].self, forKey: .hops)
        guard !hops.isEmpty else {
            throw DecodingError.dataCorruptedError(forKey: .hops, in: container, debugDescription: "chain needs at least one hop")
        }

        self.id = try container.decode(UUID.self, forKey: .id)
        self.name = try container.decode(String.self, forKey: .name)
        self.hops = hops
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(hops, forKey: .hops)
    }
}

/// The full settings file Chainy loads/saves: every chain the user has
/// saved, plus which one (if any) is currently active/selected. Load with
/// `ChainySettings.load(contentsOf:)`, write back with `save(to:)`.
public struct ChainySettings: Codable, Equatable {
    public var chains: [NamedProxyChain]
    public var activeChainID: UUID?

    private enum CodingKeys: String, CodingKey {
        case chains, activeChainID
    }

    public init(chains: [NamedProxyChain] = [], activeChainID: UUID? = nil) {
        self.chains = chains
        self.activeChainID = activeChainID
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let chains = try container.decode([NamedProxyChain].self, forKey: .chains)
        let activeChainID = try container.decodeIfPresent(UUID.self, forKey: .activeChainID)

        if let activeChainID, !chains.contains(where: { $0.id == activeChainID }) {
            throw DecodingError.dataCorruptedError(
                forKey: .activeChainID, in: container,
                debugDescription: "activeChainID \(activeChainID) does not match any chain's id"
            )
        }

        self.chains = chains
        self.activeChainID = activeChainID
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(chains, forKey: .chains)
        try container.encodeIfPresent(activeChainID, forKey: .activeChainID)
    }

    /// The chain `activeChainID` points at, if any.
    public var activeChain: NamedProxyChain? {
        guard let activeChainID else { return nil }
        return chains.first { $0.id == activeChainID }
    }

    /// Loads and decodes settings from a JSON file on disk.
    public static func load(contentsOf url: URL) throws -> ChainySettings {
        try JSONDecoder().decode(ChainySettings.self, from: Data(contentsOf: url))
    }

    /// Encodes and writes these settings to a JSON file on disk, replacing
    /// whatever was there.
    public func save(to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(self).write(to: url, options: .atomic)
    }
}
