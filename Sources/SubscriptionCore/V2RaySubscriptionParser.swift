// V2RaySubscriptionParser.swift
//
// Parses the "v2ray-style" subscription format: a (usually base64-encoded)
// blob that decodes to a newline-separated list of `scheme://...` share
// links, e.g.:
//
//   ss://<base64(method:password)>@host:port/?plugin=...#name
//   ss://<base64(method:password@host:port)>#name          (legacy form)
//   vmess://<base64(json)>
//   trojan://password@host:port?sni=...&allowInsecure=1#name
//   vless://uuid@host:port?security=tls&sni=...&flow=...&type=tcp#name
//   http://[username:password@]host:port#name
//
// Only `ss://`, `vmess://`, `trojan://`, `vless://`, and `http://` are
// understood; anything else (ssr/hysteria2/tuic/https/...) is reported in
// `SubscriptionParseResult.skipped` rather than silently dropped, since
// ChainCore has no protocol for them (an `https://` link in particular is
// a TLS-wrapped HTTP proxy -- ChainCore's `.http` hop has no such transport).
// vmess/trojan/vless all support plain TCP or WS (`net`/`type` == "ws",
// path/host taken from the JSON's `path`/`host` fields or the URI's
// `path`/`host` query params) -- anything else (grpc/h2/quic/...) is
// skipped the same way `ClashSubscriptionParser` skips it, since ChainCore
// has no other transport. Standard values in a vmess link's JSON "scy"
// (security/cipher) are accepted and preserved for VMessCore; the VMess
// server reads the actual cipher from the request
// header. A vless link whose `security` asks for anything but
// "none"/"tls" (in particular "reality", which needs a separate X25519 key
// exchange this client doesn't implement), or whose `flow` is non-empty
// (XTLS's "xtls-rprx-vision" needs transport-level stream splicing this
// client doesn't implement) is skipped the same way.

import Foundation
import ChainCore
import ShadowsocksCore
import VMessCore
import HTTPProxyCore

public enum V2RaySubscriptionParser {
    public static func parse(_ text: String) -> SubscriptionParseResult {
        let lines: [Substring]
        // `Character` treats "\r\n" as a single grapheme cluster distinct from
        // a lone "\n", so `split(separator: "\n")` silently fails to split
        // CRLF-terminated subscriptions (the whole blob comes back as one
        // "line"). Splitting on `isNewline` handles LF, CR, and CRLF alike.
        if let decoded = base64Decode(text), let decodedText = String(data: decoded, encoding: .utf8), decodedText.contains("://") {
            lines = decodedText.split(whereSeparator: { $0.isNewline })
        } else {
            lines = text.split(whereSeparator: { $0.isNewline })
        }

        var nodes: [SubscriptionNode] = []
        var skipped: [SkippedSubscriptionEntry] = []

        for rawLine in lines {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty else { continue }

            guard let schemeEnd = line.range(of: "://") else {
                skipped.append(SkippedSubscriptionEntry(name: nil, reason: "unrecognized line (no \"scheme://\")"))
                continue
            }
            let scheme = String(line[line.startIndex..<schemeEnd.lowerBound])

            switch scheme {
            case "ss":
                parseSS(line, into: &nodes, skipped: &skipped)
            case "vmess":
                parseVMess(line, into: &nodes, skipped: &skipped)
            case "trojan":
                parseTrojan(line, into: &nodes, skipped: &skipped)
            case "vless":
                parseVLESS(line, into: &nodes, skipped: &skipped)
            case "http":
                parseHTTP(line, into: &nodes, skipped: &skipped)
            default:
                skipped.append(SkippedSubscriptionEntry(name: nil, reason: "unsupported protocol \"\(scheme)\""))
            }
        }

        return SubscriptionParseResult(nodes: nodes, skipped: skipped)
    }

    // MARK: - ss://

    private static func parseSS(_ line: String, into nodes: inout [SubscriptionNode], skipped: inout [SkippedSubscriptionEntry]) {
        guard let components = URLComponents(string: line) else {
            skipped.append(SkippedSubscriptionEntry(name: nil, reason: "malformed ss:// URI"))
            return
        }
        let name = (components.fragment?.isEmpty == false) ? components.fragment : nil

        // SIP002: ss://base64(method:password)@host:port/?...
        if let user = components.user, let host = components.host, let port = components.port {
            guard let decoded = base64Decode(user), let methodPassword = String(data: decoded, encoding: .utf8) else {
                skipped.append(SkippedSubscriptionEntry(name: name, reason: "ss node has an unreadable credential blob"))
                return
            }
            appendSSNode(name: name ?? "\(host):\(port)", host: host, port: port, methodPassword: methodPassword, into: &nodes, skipped: &skipped)
            return
        }

        // Legacy: ss://base64(method:password@host:port)#name
        if components.user == nil, components.port == nil, let blob = components.host,
           let decoded = base64Decode(blob), let inner = String(data: decoded, encoding: .utf8),
           let atRange = inner.range(of: "@", options: .backwards) {
            let methodPassword = String(inner[inner.startIndex..<atRange.lowerBound])
            let hostPort = inner[atRange.upperBound...]
            guard let colonRange = hostPort.range(of: ":", options: .backwards), let realPort = Int(hostPort[colonRange.upperBound...]) else {
                skipped.append(SkippedSubscriptionEntry(name: name, reason: "legacy ss:// URI has a malformed host:port"))
                return
            }
            let realHost = String(hostPort[hostPort.startIndex..<colonRange.lowerBound])
            appendSSNode(name: name ?? "\(realHost):\(realPort)", host: realHost, port: realPort, methodPassword: methodPassword, into: &nodes, skipped: &skipped)
            return
        }

        skipped.append(SkippedSubscriptionEntry(name: name, reason: "unrecognized ss:// URI shape"))
    }

    private static func appendSSNode(name: String, host: String, port: Int, methodPassword: String, into nodes: inout [SubscriptionNode], skipped: inout [SkippedSubscriptionEntry]) {
        guard let port16 = UInt16(exactly: port) else {
            skipped.append(SkippedSubscriptionEntry(name: name, reason: "invalid port \(port)"))
            return
        }
        guard let colonIndex = methodPassword.firstIndex(of: ":") else {
            skipped.append(SkippedSubscriptionEntry(name: name, reason: "ss credentials missing \":\""))
            return
        }
        let method = String(methodPassword[methodPassword.startIndex..<colonIndex])
        let password = String(methodPassword[methodPassword.index(after: colonIndex)...])
        guard let cipher = ShadowsocksCipher(rawValue: method) else {
            skipped.append(SkippedSubscriptionEntry(name: name, reason: "unsupported cipher \"\(method)\""))
            return
        }
        nodes.append(SubscriptionNode(name: name, host: host, port: port16, protocolConfig: .shadowsocks(password: password, cipher: cipher)))
    }

    // MARK: - vmess://

    private struct VMessLink: Decodable {
        let ps: String?
        let add: String
        let port: PortValue
        let id: String
        let net: String?
        let tls: String?
        let sni: String?
        let host: String?
        let path: String?
        /// "Security" in v2rayN's VMess JSON schema. VMess servers identify
        /// the body cipher from each request header, so a link's client-side
        /// preference is preserved for VMessCore. Keep accepting `none` for
        /// older exported links by upgrading it to encrypted AES-128-GCM.
        let scy: String?

        /// v2rayN's vmess JSON has historically sent `port` as either a
        /// number or a numeric string depending on the generator.
        enum PortValue: Decodable {
            case string(String)
            case int(Int)

            var intValue: Int? {
                switch self {
                case .string(let s): return Int(s)
                case .int(let i): return i
                }
            }

            init(from decoder: Decoder) throws {
                let container = try decoder.singleValueContainer()
                if let intValue = try? container.decode(Int.self) {
                    self = .int(intValue)
                } else {
                    self = .string(try container.decode(String.self))
                }
            }
        }
    }

    private static func parseVMess(_ line: String, into nodes: inout [SubscriptionNode], skipped: inout [SkippedSubscriptionEntry]) {
        let body = String(line.dropFirst("vmess://".count))
        guard let decoded = base64Decode(body) else {
            skipped.append(SkippedSubscriptionEntry(name: nil, reason: "vmess link is not valid base64"))
            return
        }
        guard let link = try? JSONDecoder().decode(VMessLink.self, from: decoded) else {
            skipped.append(SkippedSubscriptionEntry(name: nil, reason: "vmess link's JSON payload could not be parsed"))
            return
        }
        let name = link.ps?.isEmpty == false ? link.ps! : link.add

        guard UUID(uuidString: link.id) != nil else {
            skipped.append(SkippedSubscriptionEntry(name: name, reason: "vmess node has a missing/invalid uuid"))
            return
        }
        guard let port = link.port.intValue, let port16 = UInt16(exactly: port) else {
            skipped.append(SkippedSubscriptionEntry(name: name, reason: "vmess node has an invalid port"))
            return
        }
        let securityName = link.scy?.lowercased() ?? "auto"
        let security: VMessSecurity
        switch securityName {
        case "", "auto": security = .auto
        case "aes-128-gcm", "none": security = .aes128GCM
        case "chacha20-poly1305": security = .chacha20Poly1305
        default:
            let scy = securityName
            skipped.append(SkippedSubscriptionEntry(name: name, reason: "vmess cipher \"\(scy)\" is not recognized"))
            return
        }
        guard link.tls != "reality" else {
            skipped.append(SkippedSubscriptionEntry(name: name, reason: "vmess security \"reality\" is not supported"))
            return
        }
        let network = (link.net?.isEmpty == false) ? link.net! : "tcp"
        guard network == "tcp" || network == "ws" else {
            skipped.append(SkippedSubscriptionEntry(name: name, reason: "vmess transport \"\(network)\" is not supported (plain TCP/WS only)"))
            return
        }
        let tls = link.tls == "tls"
        let sni = (link.sni?.isEmpty == false) ? link.sni : nil
        let wsPath = network == "ws" ? (link.path?.isEmpty == false ? link.path : "/") : nil
        let wsHost = network == "ws" ? (link.host?.isEmpty == false ? link.host : nil) : nil

        nodes.append(SubscriptionNode(
            name: name, host: link.add, port: port16,
            protocolConfig: .vmess(uuid: link.id, security: security, tls: tls, sni: sni, wsPath: wsPath, wsHost: wsHost)
        ))
    }

    // MARK: - trojan://

    /// `trojan://password@host:port?sni=...&allowInsecure=1&type=tcp&security=tls#name`
    /// -- the share-link shape every Trojan client generator in practice
    /// emits (the password lives where SIP002 `ss://` puts its base64
    /// credential blob, except here it's plain, percent-encoded text, per
    /// the original trojan-gfw client's own URL scheme). `security=none`
    /// (present, not just absent -- see below) opts out of TLS entirely for
    /// the rarer real-world node that runs the trojan handshake over plain
    /// TCP; every other value, or its absence, keeps TLS on by default.
    private static func parseTrojan(_ line: String, into nodes: inout [SubscriptionNode], skipped: inout [SkippedSubscriptionEntry]) {
        guard let components = URLComponents(string: line) else {
            skipped.append(SkippedSubscriptionEntry(name: nil, reason: "malformed trojan:// URI"))
            return
        }
        let name = (components.fragment?.isEmpty == false) ? components.fragment! : nil

        guard let password = components.user, !password.isEmpty, let host = components.host, let port = components.port else {
            skipped.append(SkippedSubscriptionEntry(name: name, reason: "unrecognized trojan:// URI shape (need password@host:port)"))
            return
        }
        guard let port16 = UInt16(exactly: port) else {
            skipped.append(SkippedSubscriptionEntry(name: name, reason: "invalid port \(port)"))
            return
        }
        let displayName = name ?? "\(host):\(port16)"

        let queryItems = components.queryItems ?? []
        func queryValue(_ key: String) -> String? {
            queryItems.first { $0.name.caseInsensitiveCompare(key) == .orderedSame }?.value
        }

        let network = queryValue("type") ?? queryValue("network") ?? "tcp"
        guard network == "tcp" || network.isEmpty || network == "ws" else {
            skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "trojan transport \"\(network)\" is not supported (plain TCP/WS only)"))
            return
        }

        // Unlike VLESS (`security` defaults to "none"), Trojan's own wire
        // format implies TLS, so a bare/absent `security` here means "tls"
        // -- only an explicit "none" (some real-world nodes really do skip
        // TLS entirely; confirmed live against one) opts out.
        let security = queryValue("security") ?? "tls"
        guard security == "none" || security == "tls" else {
            skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "trojan security \"\(security)\" is not supported (none/tls only)"))
            return
        }
        let tls = security != "none"

        let sni = queryValue("sni") ?? queryValue("peer")
        let allowInsecureValue = queryValue("allowInsecure") ?? queryValue("allowinsecure")
        let allowInsecure = allowInsecureValue == "1" || allowInsecureValue?.lowercased() == "true"
        let wsPath = network == "ws" ? (queryValue("path").flatMap { $0.removingPercentEncoding } ?? "/") : nil
        let wsHost = network == "ws" ? queryValue("host") : nil

        nodes.append(SubscriptionNode(
            name: displayName, host: host, port: port16,
            protocolConfig: .trojan(password: password.removingPercentEncoding ?? password, tls: tls, sni: sni, allowInsecure: allowInsecure, wsPath: wsPath, wsHost: wsHost)
        ))
    }

    // MARK: - vless://

    /// `vless://uuid@host:port?security=tls&sni=...&flow=...&type=tcp#name`
    /// -- the share-link shape every VLESS client generator in practice
    /// emits (uuid lives where SIP002 `ss://` puts its base64 credential
    /// blob, plain and unencoded, same slot trojan's password uses).
    private static func parseVLESS(_ line: String, into nodes: inout [SubscriptionNode], skipped: inout [SkippedSubscriptionEntry]) {
        guard let components = URLComponents(string: line) else {
            skipped.append(SkippedSubscriptionEntry(name: nil, reason: "malformed vless:// URI"))
            return
        }
        let name = (components.fragment?.isEmpty == false) ? components.fragment! : nil

        guard let uuid = components.user, UUID(uuidString: uuid) != nil, let host = components.host, let port = components.port else {
            skipped.append(SkippedSubscriptionEntry(name: name, reason: "unrecognized vless:// URI shape (need uuid@host:port), or uuid is not a valid UUID"))
            return
        }
        guard let port16 = UInt16(exactly: port) else {
            skipped.append(SkippedSubscriptionEntry(name: name, reason: "invalid port \(port)"))
            return
        }
        let displayName = name ?? "\(host):\(port16)"

        let queryItems = components.queryItems ?? []
        func queryValue(_ key: String) -> String? {
            queryItems.first { $0.name.caseInsensitiveCompare(key) == .orderedSame }?.value
        }

        let network = queryValue("type") ?? "tcp"
        guard network == "tcp" || network.isEmpty || network == "ws" else {
            skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "vless transport \"\(network)\" is not supported (plain TCP/WS only)"))
            return
        }
        if let flow = queryValue("flow"), !flow.isEmpty {
            skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "vless flow \"\(flow)\" is not supported"))
            return
        }
        let security = queryValue("security") ?? "none"
        guard security == "none" || security == "tls" else {
            skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "vless security \"\(security)\" is not supported (none/tls only)"))
            return
        }

        let tls = security == "tls"
        let sni = queryValue("sni") ?? queryValue("peer")
        let allowInsecureValue = queryValue("allowInsecure") ?? queryValue("allowinsecure")
        let allowInsecure = allowInsecureValue == "1" || allowInsecureValue?.lowercased() == "true"
        let wsPath = network == "ws" ? (queryValue("path").flatMap { $0.removingPercentEncoding } ?? "/") : nil
        let wsHost = network == "ws" ? queryValue("host") : nil

        nodes.append(SubscriptionNode(
            name: displayName, host: host, port: port16,
            protocolConfig: .vless(uuid: uuid, tls: tls, sni: sni, allowInsecure: allowInsecure, wsPath: wsPath, wsHost: wsHost)
        ))
    }

    // MARK: - http://

    /// `http://[username:password@]host:port#name` -- the plain-URL shape
    /// tools like v2rayN emit for a plain HTTP CONNECT proxy (credentials
    /// in the userinfo slot exactly like a normal URL, unlike `ss://`'s
    /// base64-blob or trojan's password-as-username convention). Missing
    /// credentials mean no auth, same as a Clash `type: http` entry with no
    /// "username"/"password" fields.
    private static func parseHTTP(_ line: String, into nodes: inout [SubscriptionNode], skipped: inout [SkippedSubscriptionEntry]) {
        guard let components = URLComponents(string: line) else {
            skipped.append(SkippedSubscriptionEntry(name: nil, reason: "malformed http:// URI"))
            return
        }
        let name = (components.fragment?.isEmpty == false) ? components.fragment! : nil

        guard let host = components.host, let port = components.port else {
            skipped.append(SkippedSubscriptionEntry(name: name, reason: "unrecognized http:// URI shape (need host:port)"))
            return
        }
        guard let port16 = UInt16(exactly: port) else {
            skipped.append(SkippedSubscriptionEntry(name: name, reason: "invalid port \(port)"))
            return
        }
        let displayName = name ?? "\(host):\(port16)"

        let auth: HTTPProxyAuth
        if let username = components.user, !username.isEmpty, let password = components.password {
            auth = .usernamePassword(username: username.removingPercentEncoding ?? username, password: password.removingPercentEncoding ?? password)
        } else {
            auth = .none
        }

        nodes.append(SubscriptionNode(name: displayName, host: host, port: port16, protocolConfig: .http(auth: auth)))
    }

    // MARK: - Base64 (URL-safe aware, unpadded-tolerant)

    static func base64Decode(_ s: String) -> Data? {
        var str = s.trimmingCharacters(in: .whitespacesAndNewlines)
        str = str.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let padding = (4 - str.count % 4) % 4
        str += String(repeating: "=", count: padding)
        return Data(base64Encoded: str)
    }
}
