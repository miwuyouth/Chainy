// SubscriptionNode.swift
//
// The result shape both subscription parsers (Clash YAML and v2ray-style
// URI lists, see ClashSubscriptionParser.swift/V2RaySubscriptionParser.swift)
// produce: every node this client can actually dial, plus every node the
// parser *recognized* but couldn't turn into one -- an unsupported protocol
// (ssr/hysteria2/tuic/...), an unsupported transport (this client only
// speaks plain-TCP SOCKS5/Shadowsocks/VMess, TLS-wrapped Trojan, and
// plain-or-TLS VLESS, see ChainCore's `ProxyHopProtocol` -- no WebSocket, no
// Shadowsocks plugins/obfs, no trojan-over-ws/grpc, no vless
// REALITY/XTLS-vision), or a malformed entry. Reporting skips instead of
// silently dropping nodes is what lets a GUI say "41 imported, 5 skipped:
// vmess+ws/tls unsupported" rather than leaving the user to wonder where the
// rest of their nodes went.

import ChainCore

/// One proxy node parsed from a subscription, already validated and ready
/// to become a single-hop `ProxyHop`.
public struct SubscriptionNode: Equatable {
    public let name: String
    public let host: String
    public let port: UInt16
    public let protocolConfig: ProxyHopProtocol

    public init(name: String, host: String, port: UInt16, protocolConfig: ProxyHopProtocol) {
        self.name = name
        self.host = host
        self.port = port
        self.protocolConfig = protocolConfig
    }

    /// The single-hop `ProxyHop` this node describes.
    public var hop: ProxyHop {
        ProxyHop(host: host, port: port, protocolConfig: protocolConfig)
    }
}

/// A subscription entry the parser recognized but could not turn into a
/// `SubscriptionNode`, and why.
public struct SkippedSubscriptionEntry: Equatable {
    public let name: String?
    public let reason: String

    public init(name: String?, reason: String) {
        self.name = name
        self.reason = reason
    }
}

/// The full result of parsing one subscription.
public struct SubscriptionParseResult: Equatable {
    public let nodes: [SubscriptionNode]
    public let skipped: [SkippedSubscriptionEntry]

    public init(nodes: [SubscriptionNode] = [], skipped: [SkippedSubscriptionEntry] = []) {
        self.nodes = nodes
        self.skipped = skipped
    }

    public static func + (lhs: SubscriptionParseResult, rhs: SubscriptionParseResult) -> SubscriptionParseResult {
        SubscriptionParseResult(nodes: lhs.nodes + rhs.nodes, skipped: lhs.skipped + rhs.skipped)
    }
}
