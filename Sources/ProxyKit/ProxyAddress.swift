// ProxyAddress.swift
//
// A proxy target is always one of IPv4, IPv6, or a domain name -- VMess,
// SOCKS5 (RFC 1928), and Shadowsocks all encode exactly this shape on the
// wire, they just disagree on the type-tag byte values and field order.
// This type owns the one genuinely shared piece: recognizing which kind of
// address a string is. Each protocol module defines its own `encoded`-style
// property/function for its own wire format (see VMessCore's `vmessEncoded`).

import Foundation

public enum ProxyAddress: Equatable {
    case ipv4([UInt8])
    case ipv6([UInt8])
    case domain(String)

    /// Uses inet_pton to properly recognize IPv4/IPv6 literals (rather than
    /// guessing from string shape), falling back to a domain name.
    public static func parse(_ host: String) -> ProxyAddress {
        var addr4 = in_addr()
        if host.withCString({ inet_pton(AF_INET, $0, &addr4) }) == 1 {
            return .ipv4(withUnsafeBytes(of: addr4.s_addr) { Array($0) })
        }
        var addr6 = in6_addr()
        if host.withCString({ inet_pton(AF_INET6, $0, &addr6) }) == 1 {
            return .ipv6(withUnsafeBytes(of: addr6) { Array($0) })
        }
        return .domain(host)
    }
}

public enum ProxyAddressError: Error, Equatable { case domainTooLong }

extension ProxyAddress {
    /// Encodes a domain name as a single length byte followed by its UTF-8
    /// bytes -- the length-prefixed domain format shared by VMess and SOCKS5.
    /// The wire format's length is a single byte, so anything over 255 UTF-8
    /// bytes can't be encoded at all (real DNS names never get close to
    /// this, but nothing stops a caller from passing an arbitrary String).
    /// This throws instead of crashing (`UInt8(bytes.count)` would trap on
    /// overflow) -- matching v2ray-core's own `IsDomainTooLong` check.
    public static func lengthPrefixedDomain(_ domain: String) throws -> [UInt8] {
        let bytes = Array(domain.utf8)
        guard let length = UInt8(exactly: bytes.count) else { throw ProxyAddressError.domainTooLong }
        return [length] + bytes
    }

    /// The RFC 1928 (SOCKS5) address encoding: ATYP(1=IPv4, 3=domain,
    /// 4=IPv6) + address. Shadowsocks reuses this exact format verbatim for
    /// its TCP relay header, and SOCKS5Core's own CONNECT request uses it
    /// directly -- unlike VMess's own 1/2/3 mapping (see VMessCore's
    /// `vmessEncoded`), this one is genuinely shared, not just "shaped the same."
    public var socks5Encoded: [UInt8] {
        get throws {
            switch self {
            case .ipv4(let b): return [0x01] + b
            case .domain(let d): return try [0x03] + ProxyAddress.lengthPrefixedDomain(d)
            case .ipv6(let b): return [0x04] + b
            }
        }
    }

    /// A round-trippable host string: dotted-decimal IPv4, colon-grouped
    /// IPv6 (via `inet_ntop`, mirroring `.parse`'s own use of `inet_pton`),
    /// or the domain string verbatim. Needed wherever a decoded address
    /// flows back into an API expecting a plain `String` host (e.g.
    /// `ProxyChain.open(finalTargetHost:)`, which re-parses it per hop) --
    /// a non-canonical rendering (like flattening IPv6 bytes into one hex
    /// run with no colons) would silently mis-parse back as a domain name.
    public var displayHost: String {
        switch self {
        case .ipv4(let bytes):
            var addr = in_addr()
            withUnsafeMutableBytes(of: &addr) { $0.copyBytes(from: bytes) }
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            inet_ntop(AF_INET, &addr, &buffer, socklen_t(buffer.count))
            return String(cString: buffer)
        case .ipv6(let bytes):
            var addr = in6_addr()
            withUnsafeMutableBytes(of: &addr) { $0.copyBytes(from: bytes) }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            inet_ntop(AF_INET6, &addr, &buffer, socklen_t(buffer.count))
            return String(cString: buffer)
        case .domain(let domain):
            return domain
        }
    }
}
