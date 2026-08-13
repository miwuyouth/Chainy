// ClashSubscriptionParser.swift
//
// Parses the `proxies:` list out of a Clash subscription. This is *not* a
// general YAML parser -- it only understands the single-line (or
// brace-balanced multi-line) flow-mapping shape every Clash subscription
// generator in practice emits for `proxies:`, e.g.:
//
//   proxies:
//     - {name: HK 01, server: hk01.example.com, port: 443, type: ss, cipher: aes-256-gcm, password: hunter2, udp: true}
//     - {name: JP 01, server: jp01.example.com, port: 443, type: vmess, uuid: 11111111-1111-1111-1111-111111111111, alterId: 0, cipher: auto, tls: false, udp: true}
//
// Everything else in the file (dns/rules/proxy-groups/...) is ignored.
//
// Only plain-TCP or WS ss/vmess/socks5/http nodes, trojan nodes (which are
// TLS by definition -- see TrojanCore), and vless nodes (TLS optional -- see
// VLESSCore), become a `SubscriptionNode` -- ChainCore's `ProxyHopProtocol`
// has no gRPC/HTTP2/QUIC transport or Shadowsocks plugin/obfs support (no
// TLS-wrapped transport for http, and no REALITY/XTLS-vision for vless), so
// a node needing any of those is reported in `SubscriptionParseResult.skipped`
// instead of silently mis-imported as something that will fail to connect.
// A vmess node's "cipher" is checked the same way: this client only speaks
// VMess's `Security: none` body encryption (see VMessCore's own doc
// comment), so a node whose cipher isn't absent/"auto"/"none" is skipped
// with a clear reason rather than imported and left to fail silently at
// connect time with no explanation anywhere.

import Foundation
import ChainCore
import SOCKS5Core
import ShadowsocksCore
import HTTPProxyCore

public enum ClashSubscriptionParser {
    /// True if `text` contains a top-level `proxies:` key -- the signal
    /// `SubscriptionParser.parse` uses to route to this parser instead of
    /// `V2RaySubscriptionParser`.
    public static func looksLikeClashYAML(_ text: String) -> Bool {
        text.components(separatedBy: .newlines).contains { $0.trimmingCharacters(in: .whitespaces) == "proxies:" }
    }

    public static func parse(_ text: String) -> SubscriptionParseResult {
        var nodes: [SubscriptionNode] = []
        var skipped: [SkippedSubscriptionEntry] = []

        for fields in extractProxyEntries(from: text) {
            append(fields, into: &nodes, skipped: &skipped)
        }

        return SubscriptionParseResult(nodes: nodes, skipped: skipped)
    }

    // MARK: - Field interpretation

    private static func append(_ fields: [String: String], into nodes: inout [SubscriptionNode], skipped: inout [SkippedSubscriptionEntry]) {
        let name = fields["name"]

        guard let server = fields["server"], let port = fields["port"].flatMap(UInt16.init) else {
            skipped.append(SkippedSubscriptionEntry(name: name, reason: "missing or invalid \"server\"/\"port\""))
            return
        }
        guard let type = fields["type"] else {
            skipped.append(SkippedSubscriptionEntry(name: name, reason: "missing \"type\""))
            return
        }
        let displayName = name ?? "\(server):\(port)"

        switch type {
        case "ss":
            if let plugin = fields["plugin"], !plugin.isEmpty {
                skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "shadowsocks plugin \"\(plugin)\" is not supported"))
                return
            }
            guard let password = fields["password"] else {
                skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "shadowsocks node missing \"password\""))
                return
            }
            guard let cipherRaw = fields["cipher"], let cipher = ShadowsocksCipher(rawValue: cipherRaw) else {
                skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "unsupported cipher \"\(fields["cipher"] ?? "?")\""))
                return
            }
            nodes.append(SubscriptionNode(name: displayName, host: server, port: port, protocolConfig: .shadowsocks(password: password, cipher: cipher)))

        case "vmess":
            guard let uuid = fields["uuid"], UUID(uuidString: uuid) != nil else {
                skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "vmess node has a missing/invalid uuid"))
                return
            }
            if let cipher = fields["cipher"], !cipher.isEmpty, cipher != "auto", cipher != "none" {
                skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "vmess cipher \"\(cipher)\" is not supported (security=none/auto only)"))
                return
            }
            let network = fields["network"] ?? "tcp"
            let tls = fields["tls"] == "true"
            let allowInsecure = fields["skip-cert-verify"] == "true"
            let sni = fields["servername"] ?? fields["sni"]
            guard network == "tcp" || network == "ws" else {
                skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "vmess transport \"\(network)\" is not supported (plain TCP/WS only)"))
                return
            }
            guard network != "ws" || wsInfo(from: fields) != nil else {
                skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "vmess node's \"ws-opts\" is missing a \"path\""))
                return
            }
            let ws = network == "ws" ? wsInfo(from: fields) : nil
            nodes.append(SubscriptionNode(
                name: displayName, host: server, port: port,
                protocolConfig: .vmess(uuid: uuid, tls: tls, sni: sni, allowInsecure: allowInsecure, wsPath: ws?.path, wsHost: ws?.host)
            ))

        case "socks5":
            let auth: SOCKS5Auth
            if let username = fields["username"], let password = fields["password"] {
                auth = .usernamePassword(username: username, password: password)
            } else {
                auth = .none
            }
            nodes.append(SubscriptionNode(name: displayName, host: server, port: port, protocolConfig: .socks5(auth: auth)))

        case "trojan":
            guard let password = fields["password"] else {
                skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "trojan node missing \"password\""))
                return
            }
            let network = fields["network"] ?? "tcp"
            guard network == "tcp" || network == "ws" else {
                skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "trojan transport \"\(network)\" is not supported (plain TCP/WS only)"))
                return
            }
            guard network != "ws" || wsInfo(from: fields) != nil else {
                skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "trojan node's \"ws-opts\" is missing a \"path\""))
                return
            }
            let ws = network == "ws" ? wsInfo(from: fields) : nil
            let allowInsecure = fields["skip-cert-verify"] == "true"
            nodes.append(SubscriptionNode(
                name: displayName, host: server, port: port,
                protocolConfig: .trojan(password: password, sni: fields["sni"], allowInsecure: allowInsecure, wsPath: ws?.path, wsHost: ws?.host)
            ))

        case "vless":
            guard let uuid = fields["uuid"], UUID(uuidString: uuid) != nil else {
                skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "vless node has a missing/invalid uuid"))
                return
            }
            // mihomo signals REALITY purely via a nested `reality-opts:`
            // map (there's no separate "security: reality" field like the
            // v2ray URI convention `V2RaySubscriptionParser` checks) -- a
            // REALITY node's own `flow` is optional (many `network: tcp`
            // REALITY setups omit it), so the `flow` guard below doesn't
            // catch a flow-less REALITY node on its own. `reality-opts`
            // always ends up in `fields` (as `""` for a block-mapping
            // entry's nested-block header, or the nested map's own raw text
            // for a flow-mapping entry -- see `extractProxyEntries`/
            // `wsInfo`'s same "nested map kept as opaque value" shape), so
            // its mere presence as a key is what's checked, not its value.
            guard fields["reality-opts"] == nil else {
                skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "vless REALITY is not supported"))
                return
            }
            let network = fields["network"] ?? "tcp"
            guard network == "tcp" || network == "ws" else {
                skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "vless transport \"\(network)\" is not supported (plain TCP/WS only)"))
                return
            }
            guard network != "ws" || wsInfo(from: fields) != nil else {
                skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "vless node's \"ws-opts\" is missing a \"path\""))
                return
            }
            if let flow = fields["flow"], !flow.isEmpty {
                skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "vless flow \"\(flow)\" is not supported"))
                return
            }
            let ws = network == "ws" ? wsInfo(from: fields) : nil
            let tls = fields["tls"] == "true"
            let allowInsecure = fields["skip-cert-verify"] == "true"
            // Clash Meta/mihomo uses "servername" for vless/vmess (unlike
            // trojan's "sni"); accept either since generators aren't fully
            // consistent about it.
            let sni = fields["servername"] ?? fields["sni"]
            nodes.append(SubscriptionNode(
                name: displayName, host: server, port: port,
                protocolConfig: .vless(uuid: uuid, tls: tls, sni: sni, allowInsecure: allowInsecure, wsPath: ws?.path, wsHost: ws?.host)
            ))

        case "http":
            guard fields["tls"] != "true" else {
                skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "HTTPS (TLS-wrapped) HTTP proxy is not supported"))
                return
            }
            let auth: HTTPProxyAuth
            if let username = fields["username"], let password = fields["password"] {
                auth = .usernamePassword(username: username, password: password)
            } else {
                auth = .none
            }
            nodes.append(SubscriptionNode(name: displayName, host: server, port: port, protocolConfig: .http(auth: auth)))

        default:
            skipped.append(SkippedSubscriptionEntry(name: displayName, reason: "unsupported protocol \"\(type)\""))
        }
    }

    // MARK: - Extracting each proxy entry under "proxies:"

    /// Returns the parsed field dictionary of every proxy entry under the
    /// top-level `proxies:` key, in order. Real-world Clash subscription
    /// generators emit list items in either shape, and this dispatches each
    /// one to whichever of `parseFlowMap`/block-parsing below matches its
    /// first line:
    ///
    ///   proxies:
    ///     - {name: HK 01, server: hk01.example.com, port: 443, type: ss, ...}   # flow mapping, one line
    ///     - name: HK 01                                                        # block mapping, one
    ///       server: hk01.example.com                                           # field per line
    ///       port: 443
    ///       type: ss
    ///
    /// Handles the common single-line-flow-mapping case, brace-depth
    /// tracking for a flow mapping a generator happens to wrap across
    /// multiple lines, and block mappings (mihomo's own default export
    /// shape, among others) whose nested child maps/lists (`reality-opts:`,
    /// `alpn:`, ...) are skipped by indentation rather than parsed, since
    /// none of the fields this parser reads are ever nested.
    static func extractProxyEntries(from text: String) -> [[String: String]] {
        let lines = text.components(separatedBy: .newlines).map(stripInlineComment)
        guard let startIndex = lines.firstIndex(where: { $0.trimmingCharacters(in: .whitespaces) == "proxies:" }) else {
            return []
        }

        var entries: [[String: String]] = []
        var i = startIndex + 1

        while i < lines.count {
            let line = lines[i]
            // A non-blank, non-indented line means the proxies list (a YAML
            // sub-key's value) has ended -- back at top level.
            if !line.isEmpty && !line.hasPrefix(" ") && !line.hasPrefix("\t") {
                break
            }
            let dashIndent = line.prefix { $0 == " " || $0 == "\t" }.count
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("- ") else { i += 1; continue }
            let itemContent = String(trimmed.dropFirst(2))

            if itemContent.hasPrefix("{") {
                var current = itemContent
                var j = i
                while braceDepth(of: current) > 0, j + 1 < lines.count {
                    j += 1
                    current += " " + lines[j].trimmingCharacters(in: .whitespaces)
                }
                entries.append(parseFlowMap(current))
                i = j + 1
            } else {
                // Block mapping: `itemContent` is the entry's first
                // "key: value" field, at the same indentation every later
                // top-level field in this entry sits at (`dashIndent` plus
                // the 2 columns "- " itself took).
                var fields: [String: String] = [:]
                if let (key, value) = parseKeyValueEntry(itemContent) {
                    fields[key] = value
                }
                let fieldIndent = dashIndent + 2
                var j = i + 1
                while j < lines.count {
                    let l = lines[j]
                    let t = l.trimmingCharacters(in: .whitespaces)
                    if t.isEmpty { j += 1; continue }
                    let indent = l.prefix { $0 == " " || $0 == "\t" }.count
                    if indent < fieldIndent { break }
                    if indent == fieldIndent {
                        if t.hasPrefix("- ") { break } // next list item at this same level
                        if t.hasPrefix("ws-opts:") {
                            // Some generators keep `ws-opts` as an inline
                            // flow map even inside an otherwise block-style
                            // entry (`ws-opts: {path: /ws, headers: {...}}`)
                            // -- caught here before assuming a nested block
                            // follows on later lines. Kept as the same
                            // opaque raw-string shape a flow-mapping entry's
                            // own "ws-opts" value already is, so `wsInfo`'s
                            // existing `parseFlowMap(raw)` fallback handles
                            // it unchanged.
                            if let (_, value) = parseKeyValueEntry(t), !value.isEmpty {
                                fields["ws-opts"] = value
                                j += 1
                                continue
                            }
                            // The one nested child map this parser actually
                            // reads into (flattened here as synthetic
                            // "ws-path"/"ws-host" keys) -- every other
                            // nested map/list (reality-opts:, alpn:, ...)
                            // still just falls through to the generic
                            // "indent > fieldIndent: skip" case below.
                            let (consumed, path, host) = parseWSOpts(lines: lines, from: j + 1, parentIndent: indent)
                            if let path { fields["ws-path"] = path }
                            if let host { fields["ws-host"] = host }
                            j += 1 + consumed
                            continue
                        }
                        if let (key, value) = parseKeyValueEntry(t) {
                            fields[key] = value
                        }
                    }
                    // indent > fieldIndent: a nested map/list's own contents
                    // -- skipped rather than parsed, same reasoning as above.
                    j += 1
                }
                entries.append(fields)
                i = j
            }
        }
        return entries
    }

    /// Walks a `ws-opts:` block-mapping child's own nested fields (deeper
    /// indentation than `parentIndent`), extracting `path` and (a further
    /// nested) `headers.Host` -- the two fields VMessCore/VLESSCore/
    /// TrojanCore need for a WS-transport hop. Returns how many lines were
    /// consumed so the caller can skip past the whole nested block, same
    /// "skip anything deeper, only parse what's actually read" scope as the
    /// rest of this parser.
    private static func parseWSOpts(lines: [String], from start: Int, parentIndent: Int) -> (consumed: Int, path: String?, host: String?) {
        var path: String?
        var host: String?
        var j = start
        while j < lines.count {
            let l = lines[j]
            let t = l.trimmingCharacters(in: .whitespaces)
            if t.isEmpty { j += 1; continue }
            let indent = l.prefix { $0 == " " || $0 == "\t" }.count
            if indent <= parentIndent { break }
            if indent == parentIndent + 2, let (key, value) = parseKeyValueEntry(t) {
                if key == "path" {
                    path = value
                } else if key == "headers" {
                    var k = j + 1
                    while k < lines.count {
                        let hl = lines[k]
                        let ht = hl.trimmingCharacters(in: .whitespaces)
                        if ht.isEmpty { k += 1; continue }
                        let hIndent = hl.prefix { $0 == " " || $0 == "\t" }.count
                        if hIndent <= indent { break }
                        if let (hKey, hValue) = parseKeyValueEntry(ht), hKey.caseInsensitiveCompare("Host") == .orderedSame {
                            host = hValue
                        }
                        k += 1
                    }
                    j = k
                    continue
                }
            }
            j += 1
        }
        return (j - start, path, host)
    }

    /// Extracts `ws-opts.path`/`ws-opts.headers.Host` -- present as
    /// flattened `"ws-path"`/`"ws-host"` keys for a block-mapping entry (see
    /// `parseWSOpts` above), or still nested as a raw opaque `"ws-opts"`
    /// string for a flow-mapping entry (a second pass through `parseFlowMap`
    /// peels that open, the same "nested map kept as one opaque value"
    /// shape every other nested field in a flow map already gets). `nil` if
    /// there's no usable path either way.
    private static func wsInfo(from fields: [String: String]) -> (path: String, host: String?)? {
        if let path = fields["ws-path"], !path.isEmpty {
            return (path, fields["ws-host"].flatMap { $0.isEmpty ? nil : $0 })
        }
        guard let raw = fields["ws-opts"] else { return nil }
        let opts = parseFlowMap(raw)
        guard let path = opts["path"], !path.isEmpty else { return nil }
        let host = opts["headers"].flatMap { headersRaw -> String? in
            let headers = parseFlowMap(headersRaw)
            return headers["Host"] ?? headers["host"]
        }
        return (path, host)
    }

    private static func braceDepth(of s: String) -> Int {
        var depth = 0
        var quote: Character?
        for ch in s {
            if let q = quote {
                if ch == q { quote = nil }
            } else if ch == "\"" || ch == "'" {
                quote = ch
            } else if ch == "{" {
                depth += 1
            } else if ch == "}" {
                depth -= 1
            }
        }
        return depth
    }

    /// Strips a trailing YAML comment from one line -- a `#` outside any
    /// quoted string, at the start of the line or preceded by whitespace,
    /// per YAML's own comment-recognition rule (a `#` with no preceding
    /// whitespace, or one inside a quoted scalar, doesn't start a comment
    /// and is left alone). Applied to every line up front in
    /// `extractProxyEntries` so a generator's inline `# note` can never leave
    /// stray text in a parsed value (block style) or leave a flow mapping's
    /// closing "}" unstripped (breaking `parseFlowMap`'s own `hasSuffix("}")`
    /// check and appending the brace, plus the comment text, onto the last
    /// field's value instead).
    private static func stripInlineComment(_ line: String) -> String {
        var result = ""
        var quote: Character?
        var previousWasSpace = true
        // Whether the next non-space character could legally *open* a
        // quoted YAML scalar: true at the start of the line and right after
        // any delimiter a value can start after (`:`, `-`, `,`, `{`, `[`).
        // Without this, a bare apostrophe anywhere in an *unquoted* value
        // (e.g. a proxy name like "Grandma's House") got treated as an
        // opening quote; with an odd count of them on the line, the parser
        // stayed stuck thinking it was still inside a quoted string for the
        // rest of the line, so a real trailing `# comment` never got
        // recognized and ended up left in the parsed field.
        var atValueStart = true
        for ch in line {
            if let q = quote {
                result.append(ch)
                if ch == q { quote = nil }
                previousWasSpace = false
                continue
            }
            if ch == "#" && previousWasSpace {
                break
            }
            if ch == " " || ch == "\t" {
                result.append(ch)
                previousWasSpace = true
                continue
            }
            if atValueStart && (ch == "\"" || ch == "'") {
                quote = ch
                atValueStart = false
                result.append(ch)
                previousWasSpace = false
                continue
            }
            result.append(ch)
            previousWasSpace = false
            atValueStart = (ch == ":" || ch == "-" || ch == "," || ch == "{" || ch == "[")
        }
        return result
    }

    // MARK: - Flow-mapping field parsing

    /// Parses `{key: value, key2: "value, with comma", nested: {...}}` into
    /// a flat `[String: String]` of its top-level scalar fields (a nested
    /// map's own raw text is kept as one opaque string value, since none of
    /// the fields this parser reads -- name/server/port/type/cipher/
    /// password/uuid/network/tls/username/plugin -- are ever nested).
    static func parseFlowMap(_ raw: String) -> [String: String] {
        var s = raw.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("{") { s.removeFirst() }
        if s.hasSuffix("}") { s.removeLast() }

        var fields: [String: String] = [:]
        for entry in splitTopLevel(s, separator: ",") {
            if let (key, value) = parseKeyValueEntry(entry) {
                fields[key] = value
            }
        }
        return fields
    }

    /// Parses one `key: value` pair, shared by `parseFlowMap`'s
    /// comma-separated entries and `extractProxyEntries`'s block-mapping
    /// lines. `nil` for a malformed entry (no colon, or an empty key).
    private static func parseKeyValueEntry(_ entry: String) -> (key: String, value: String)? {
        let trimmedEntry = entry.trimmingCharacters(in: .whitespaces)
        guard let colon = trimmedEntry.firstIndex(of: ":") else { return nil }
        let key = trimmedEntry[trimmedEntry.startIndex..<colon].trimmingCharacters(in: .whitespaces)
        let value = unquote(String(trimmedEntry[trimmedEntry.index(after: colon)...]))
        guard !key.isEmpty else { return nil }
        return (key, value)
    }

    /// Splits `s` on top-level occurrences of `separator`, ignoring ones
    /// inside `{...}`/`[...]` or single/double-quoted strings.
    private static func splitTopLevel(_ s: String, separator: Character) -> [String] {
        var result: [String] = []
        var current = ""
        var depth = 0
        var quote: Character?

        for ch in s {
            if let q = quote {
                current.append(ch)
                if ch == q { quote = nil }
                continue
            }
            if ch == "\"" || ch == "'" {
                quote = ch
                current.append(ch)
            } else if ch == "{" || ch == "[" {
                depth += 1
                current.append(ch)
            } else if ch == "}" || ch == "]" {
                depth -= 1
                current.append(ch)
            } else if ch == separator, depth == 0 {
                result.append(current)
                current = ""
            } else {
                current.append(ch)
            }
        }
        if !current.isEmpty { result.append(current) }
        return result
    }

    private static func unquote(_ s: String) -> String {
        let value = s.trimmingCharacters(in: .whitespaces)
        guard value.count >= 2, let first = value.first, let last = value.last else { return value }
        if (first == "\"" && last == "\"") || (first == "'" && last == "'") {
            return String(value.dropFirst().dropLast())
        }
        return value
    }
}
