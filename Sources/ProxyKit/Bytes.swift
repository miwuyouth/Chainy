// Bytes.swift
//
// Small byte/endianness helpers and "host:port" parsing shared by every
// proxy protocol implementation (VMess today; SOCKS5/Shadowsocks/HTTP CONNECT
// later all need the same big-endian port encoding and address-string splitting).

import Foundation

extension UInt16 {
    public var bigEndianBytes: [UInt8] { [UInt8(self >> 8), UInt8(self & 0xff)] }
}

extension Int64 {
    public var bigEndianBytes: [UInt8] {
        (0..<8).map { UInt8((UInt64(bitPattern: self) >> (56 - $0 * 8)) & 0xff) }
    }
}

extension UInt32 {
    public var bigEndianBytes: [UInt8] { (0..<4).map { UInt8((self >> (24 - $0 * 8)) & 0xff) } }
}

extension UInt64 {
    public var bigEndianBytes: [UInt8] { (0..<8).map { UInt8((self >> (56 - $0 * 8)) & 0xff) } }
}

/// Splits "host:port" (or "[ipv6]:port") into its parts, falling back to
/// `defaultPort` when no port is present.
public func parseHostPort(_ s: String, defaultPort: UInt16) -> (host: String, port: UInt16) {
    if s.hasPrefix("["), let closeBracket = s.firstIndex(of: "]") {
        let host = String(s[s.index(after: s.startIndex)..<closeBracket])
        let rest = s[s.index(after: closeBracket)...]
        if rest.hasPrefix(":"), let port = UInt16(rest.dropFirst()) { return (host, port) }
        return (host, defaultPort)
    }
    // A bracket-less IPv6 literal (e.g. "::1", "2001:db8::1") has more than
    // one colon -- unlike a real "host:port"/"domain:port" pair, which has
    // exactly one. Splitting on the *last* colon regardless would treat that
    // address's final hextet as a port whenever it happens to parse as one
    // (`UInt16("1")` succeeds), silently truncating the address instead of
    // rejecting the ambiguous input. The convention for pairing an IPv6
    // literal with an explicit port requires brackets (the case above), so a
    // bracket-less string with more than one colon has no port to extract at all.
    if let idx = s.lastIndex(of: ":"), !s[..<idx].contains(":"), let port = UInt16(s[s.index(after: idx)...]) {
        return (String(s[..<idx]), port)
    }
    return (s, defaultPort)
}
