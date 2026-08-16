// swift-tools-version:5.9
import PackageDescription

// Package layout:
//
//   ProxyKit           - shared, protocol-agnostic: TCP I/O + timeouts,
//                        address parsing (IPv4/IPv6/domain), and generic
//                        crypto primitives (MD5/SHA256/HMAC/AES-GCM/
//                        ChaCha20-Poly1305/HKDF/AES-128/CRC32/FNV1a).
//   VMessCore          - the VMess protocol, built on ProxyKit.
//   VMessDemoCLI       - a small CLI exercising VMessCore.
//   ShadowsocksCore    - the Shadowsocks AEAD protocol, built on ProxyKit.
//   ShadowsocksDemoCLI - a small CLI exercising ShadowsocksCore.
//   SOCKS5Core         - the SOCKS5 (RFC 1928) protocol, built on ProxyKit.
//   SOCKS5DemoCLI      - a small CLI exercising SOCKS5Core.
//   HTTPProxyCore      - both sides of the HTTP CONNECT/plain-HTTP proxy
//                        protocol, built on ProxyKit: the server (accept)
//                        side Chainy's local listener uses to speak HTTP
//                        alongside SOCKS5Core's SOCKS5 on the same port, and
//                        the client (dial) side ChainCore uses as an
//                        outbound hop protocol like any other.
//   TrojanCore         - the Trojan protocol (TLS via ProxyKit's `TLSConn`,
//                        then a plaintext credential header), built on ProxyKit.
//   TrojanDemoCLI      - a small CLI exercising TrojanCore.
//   VLESSCore          - the VLESS protocol (UUID + address request header,
//                        optionally wrapped in TLS), built on ProxyKit.
//   VLESSDemoCLI       - a small CLI exercising VLESSCore.
//   ChainCore          - combines SOCKS5Core/ShadowsocksCore/VMessCore/
//                        TrojanCore/VLESSCore into an ordered proxy chain
//                        (any protocol, any order, any length), built on the
//                        fact that each protocol's `Session` is itself a
//                        `ProxyTransport` that the next hop's handshake can
//                        run over.
//   ChainDemoCLI       - a small CLI exercising ChainCore.
//   SubscriptionCore   - parses Clash-YAML and v2ray-style (ss:///vmess://)
//                        subscriptions into ChainCore's `ProxyHop`s, for
//                        Chainy to import nodes from instead of the
//                        user hand-typing host/port/credentials.
//   Chainy         - the SwiftUI app tying the above together.
let package = Package(
    name: "ProxyDemo",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "ProxyKit", targets: ["ProxyKit"]),
        .library(name: "VMessCore", targets: ["VMessCore"]),
        .library(name: "ShadowsocksCore", targets: ["ShadowsocksCore"]),
        .library(name: "SOCKS5Core", targets: ["SOCKS5Core"]),
        .library(name: "HTTPProxyCore", targets: ["HTTPProxyCore"]),
        .library(name: "TrojanCore", targets: ["TrojanCore"]),
        .library(name: "VLESSCore", targets: ["VLESSCore"]),
        .library(name: "ChainCore", targets: ["ChainCore"]),
        .library(name: "SubscriptionCore", targets: ["SubscriptionCore"]),
        .executable(name: "chainy-diagnose", targets: ["ChainDiagnosticCLI"]),
    ],
    targets: [
        .target(name: "ProxyKit"),
        .target(name: "VMessCore", dependencies: ["ProxyKit"]),
        .executableTarget(name: "VMessDemoCLI", dependencies: ["VMessCore", "ProxyKit"]),
        .target(name: "ShadowsocksCore", dependencies: ["ProxyKit"]),
        .executableTarget(name: "ShadowsocksDemoCLI", dependencies: ["ShadowsocksCore", "ProxyKit"]),
        .target(name: "SOCKS5Core", dependencies: ["ProxyKit"]),
        .executableTarget(name: "SOCKS5DemoCLI", dependencies: ["SOCKS5Core", "ProxyKit"]),
        .target(name: "HTTPProxyCore", dependencies: ["ProxyKit"]),
        .target(name: "TrojanCore", dependencies: ["ProxyKit"]),
        .executableTarget(name: "TrojanDemoCLI", dependencies: ["TrojanCore", "ProxyKit"]),
        .target(name: "VLESSCore", dependencies: ["ProxyKit"]),
        .executableTarget(name: "VLESSDemoCLI", dependencies: ["VLESSCore", "ProxyKit"]),
        .target(name: "ChainCore", dependencies: ["ProxyKit", "SOCKS5Core", "ShadowsocksCore", "VMessCore", "TrojanCore", "VLESSCore", "HTTPProxyCore"]),
        .executableTarget(name: "ChainDemoCLI", dependencies: ["ChainCore", "ProxyKit", "SOCKS5Core", "ShadowsocksCore", "VMessCore", "TrojanCore"]),
        .executableTarget(name: "ChainDiagnosticCLI", dependencies: ["ChainCore", "ProxyKit", "SOCKS5Core"]),
        .target(name: "SubscriptionCore", dependencies: ["ChainCore", "SOCKS5Core", "ShadowsocksCore", "VMessCore", "HTTPProxyCore"]),
        .executableTarget(name: "Chainy", dependencies: ["ChainCore", "SubscriptionCore", "ProxyKit", "SOCKS5Core", "VMessCore", "HTTPProxyCore"], resources: [.process("Resources")]),
        .testTarget(name: "ProxyKitTests", dependencies: ["ProxyKit"]),
        .testTarget(name: "VMessCoreTests", dependencies: ["VMessCore", "ProxyKit"]),
        .testTarget(name: "ShadowsocksCoreTests", dependencies: ["ShadowsocksCore", "ProxyKit"]),
        .testTarget(name: "SOCKS5CoreTests", dependencies: ["SOCKS5Core", "ProxyKit"]),
        .testTarget(name: "HTTPProxyCoreTests", dependencies: ["HTTPProxyCore", "ProxyKit"]),
        .testTarget(name: "TrojanCoreTests", dependencies: ["TrojanCore", "ProxyKit", "ChainCore"]),
        .testTarget(name: "VLESSCoreTests", dependencies: ["VLESSCore", "ProxyKit"]),
        .testTarget(name: "ChainCoreTests", dependencies: ["ChainCore", "ProxyKit", "SOCKS5Core", "ShadowsocksCore", "VMessCore", "TrojanCore", "VLESSCore", "HTTPProxyCore"]),
        .testTarget(name: "SubscriptionCoreTests", dependencies: ["SubscriptionCore", "ChainCore", "SOCKS5Core", "ShadowsocksCore", "VMessCore", "HTTPProxyCore"]),
        .testTarget(name: "ChainyTests", dependencies: ["Chainy", "ChainCore", "SOCKS5Core", "HTTPProxyCore", "ProxyKit"]),
        .testTarget(name: "InteropTests", dependencies: ["ChainCore", "SubscriptionCore", "SOCKS5Core", "ShadowsocksCore", "VMessCore", "TrojanCore", "VLESSCore", "HTTPProxyCore", "ProxyKit"]),
    ]
)
