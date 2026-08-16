// VMessCore.swift
//
// A minimal, self-contained VMess client library written in Swift, built on
// top of ProxyKit's shared networking/crypto/address primitives.
//
// It implements the actual VMess AEAD wire protocol (the format used by
// v2ray-core / Xray-core / mihomo / Clash.Meta when alterId == 0), verified
// against the reference implementation in v2fly/v2ray-core
// (proxy/vmess/aead, proxy/vmess/encoding) and sagernet/sing-vmess, and
// cross-checked against v2ray-core's own test vectors (see VMessCoreTests).
//
// The handshake (AuthID, the HMAC-SHA256 KDF chain, and the AES-128-GCM
// sealed request/response headers) and the connection body (chunked,
// individually AES-128-GCM- or ChaCha20-Poly1305-sealed application data,
// not "none") are both fully implemented for real using CryptoKit -- nothing
// about the crypto is faked or stubbed. Some real-world VMess servers
// reject a client that requests "Security: none" outright -- observed live,
// such a server closes the connection right after the handshake instead of
// relaying anything -- which is why the body is always actually encrypted
// rather than sent as a plain byte pipe.
//
// Requires macOS 10.15+ (CryptoKit, Network.framework).

import Foundation
import ProxyKit

// MARK: - Configuration

public enum VMessSecurity: String, Codable, CaseIterable, Sendable {
    case auto
    case aes128GCM = "aes-128-gcm"
    case chacha20Poly1305 = "chacha20-poly1305"

    /// Xray's `auto` selects AES on ARM64/AMD64, including every Mac this
    /// package supports. Resolve it once so the request header and body codec
    /// can never disagree about the algorithm in use.
    public var resolved: VMessSecurity { self == .auto ? .aes128GCM : self }
}

public struct VMessBodyOptions: Codable, Equatable, Sendable {
    public var chunkMasking: Bool
    public var globalPadding: Bool
    public var authenticatedLength: Bool

    public init(chunkMasking: Bool = true, globalPadding: Bool = true, authenticatedLength: Bool = false) {
        self.chunkMasking = chunkMasking
        self.globalPadding = globalPadding
        self.authenticatedLength = authenticatedLength
    }

    public static let modern = VMessBodyOptions()
    public var effectiveGlobalPadding: Bool { chunkMasking && globalPadding }
}

public struct VMessServerConfig {
    public let host: String
    public let port: UInt16
    public let uuid: String
    public let security: VMessSecurity
    public let bodyOptions: VMessBodyOptions
    /// Wraps the connection in TLS before sending the VMess request header
    /// -- matches VLESSServerConfig's own `tls`/`sni`/`allowInsecure` shape;
    /// `false` (the historical default here) sends the request directly
    /// over the dialed TCP connection.
    public let tls: Bool
    public let sni: String?
    public let allowInsecure: Bool
    /// Wraps the (possibly TLS-wrapped) connection in a WebSocket tunnel
    /// before sending the VMess request header -- `nil` means plain TCP.
    /// `wsHost` is the `Host:` header sent in the upgrade request (defaults
    /// to `sni ?? host` when `nil`), separate from `host` the same way a
    /// front domain can differ from the real server address.
    public let wsPath: String?
    public let wsHost: String?

    public init(host: String, port: UInt16, uuid: String, security: VMessSecurity = .auto, bodyOptions: VMessBodyOptions = .modern, tls: Bool = false, sni: String? = nil, allowInsecure: Bool = false, wsPath: String? = nil, wsHost: String? = nil) {
        self.host = host
        self.port = port
        self.uuid = uuid
        self.security = security
        self.bodyOptions = bodyOptions
        self.tls = tls
        self.sni = sni
        self.allowInsecure = allowInsecure
        self.wsPath = wsPath
        self.wsHost = wsHost
    }
}

public struct VMessTarget {
    public let host: String   // domain, IPv4 literal, or IPv6 literal
    public let port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }
}

public func parseUUID(_ s: String) -> [UInt8] {
    let hex = s.replacingOccurrences(of: "-", with: "")
    precondition(hex.count == 32, "invalid uuid")
    var bytes = [UInt8]()
    var idx = hex.startIndex
    while idx < hex.endIndex {
        let next = hex.index(idx, offsetBy: 2)
        bytes.append(UInt8(hex[idx..<next], radix: 16)!)
        idx = next
    }
    return bytes
}

// MARK: - VMess AEAD KDF

/// VMess AEAD KDF: HMAC-SHA256 chained through "VMess AEAD KDF" plus a
/// variable path of extra keys (salts / authID / nonce), exactly mirroring
/// v2ray-core's proxy/vmess/aead/kdf.go, built on ProxyKit's generic
/// `genericHMAC`. Cross-checked against v2ray-core's own kdf_test.go vector
/// in VMessCoreTests.
public func vmessKDF(key: [UInt8], path: [[UInt8]]) -> [UInt8] {
    var hashFn: ([UInt8]) -> [UInt8] = { sha256($0) }
    let chain = [Array("VMess AEAD KDF".utf8)] + path
    for levelKey in chain {
        let previous = hashFn
        hashFn = { msg in genericHMAC(key: levelKey, message: msg, hash: previous) }
    }
    return hashFn(key)
}

public func vmessKDF16(key: [UInt8], path: [[UInt8]]) -> [UInt8] { Array(vmessKDF(key: key, path: path).prefix(16)) }

// MARK: - VMess's own address wire encoding
//
// The *parsing* (is this an IPv4/IPv6 literal or a domain?) lives in
// ProxyKit's `ProxyAddress`, shared with future protocols. The type-tag byte
// values below (1/2/3) are VMess-specific -- SOCKS5, for instance, uses
// 1/3/4 for the same three cases -- so the wire encoding itself stays here.

extension ProxyAddress {
    public var vmessEncoded: [UInt8] {
        get throws {
            switch self {
            case .ipv4(let b): return [0x01] + b                              // AddressType IPv4 = 1
            case .domain(let d): return try [0x02] + ProxyAddress.lengthPrefixedDomain(d) // AddressType Domain = 2
            case .ipv6(let b): return [0x03] + b                              // AddressType IPv6 = 3
            }
        }
    }
}

public let cmdKeyMagic = Array("c48619fe-8f02-49e0-b9e9-edf763e17e21".utf8)

/// Seals an arbitrary VMess header payload the same way v2ray-core's
/// `SealVMessAEADHeader(key, data)` does: a fresh AuthID + connection nonce,
/// then AES-128-GCM over a 2-byte length field and the payload itself, both
/// authenticated against the AuthID. Cross-checked against v2ray-core's own
/// aead package in VMessCoreTests (round-trip + tamper detection).
public func sealVMessAEADHeader(key: [UInt8], data: [UInt8]) -> [UInt8] {
    let ts = Int64(Date().timeIntervalSince1970)
    var authPlain = ts.bigEndianBytes + (0..<4).map { _ in UInt8.random(in: 0...255) }
    authPlain += crc32(authPlain).bigEndianBytes
    let authIDKey = vmessKDF16(key: key, path: [Array("AES Auth ID Encryption".utf8)])
    let authID = AES128.encryptBlock(authPlain, key: authIDKey)

    let connectionNonce = (0..<8).map { _ in UInt8.random(in: 0...255) }

    let lengthKey = vmessKDF16(key: key, path: [Array("VMess Header AEAD Key_Length".utf8), authID, connectionNonce])
    let lengthNonce = Array(vmessKDF(key: key, path: [Array("VMess Header AEAD Nonce_Length".utf8), authID, connectionNonce]).prefix(12))
    let sealedLength = aesGCMSeal(key: lengthKey, nonce: lengthNonce, plaintext: UInt16(data.count).bigEndianBytes, aad: authID)

    let headerKey = vmessKDF16(key: key, path: [Array("VMess Header AEAD Key".utf8), authID, connectionNonce])
    let headerNonce = Array(vmessKDF(key: key, path: [Array("VMess Header AEAD Nonce".utf8), authID, connectionNonce]).prefix(12))
    let sealedHeader = aesGCMSeal(key: headerKey, nonce: headerNonce, plaintext: data, aad: authID)

    return authID + sealedLength + connectionNonce + sealedHeader
}

public enum VMessAEADOpenError: Error { case truncated, authenticationFailed }

/// Mirrors v2ray-core's `OpenVMessAEADHeader(key, authID, reader)`, but
/// operates on an in-memory buffer of whatever followed the 16-byte AuthID
/// (which the caller has already peeled off), since that's all a unit test
/// needs. Not used by the live client (which only ever seals requests and
/// opens *response* headers, a related but distinct framing) -- this exists
/// so the seal path can be round-tripped and fuzzed in VMessCoreTests the
/// same way v2ray-core's own encrypt_test.go does.
public func openVMessAEADHeader(key: [UInt8], authID: [UInt8], remainder: [UInt8]) throws -> [UInt8] {
    guard remainder.count >= 18 + 8 else { throw VMessAEADOpenError.truncated }
    let sealedLength = Array(remainder[0..<18])
    let connectionNonce = Array(remainder[18..<26])
    let sealedHeader = Array(remainder[26...])

    let lengthKey = vmessKDF16(key: key, path: [Array("VMess Header AEAD Key_Length".utf8), authID, connectionNonce])
    let lengthNonce = Array(vmessKDF(key: key, path: [Array("VMess Header AEAD Nonce_Length".utf8), authID, connectionNonce]).prefix(12))
    guard let lengthBytes = try? aesGCMOpen(key: lengthKey, nonce: lengthNonce, sealed: sealedLength, aad: authID) else {
        throw VMessAEADOpenError.authenticationFailed
    }
    let headerLen = Int(lengthBytes[0]) << 8 | Int(lengthBytes[1])
    guard sealedHeader.count == headerLen + 16 else { throw VMessAEADOpenError.truncated }

    let headerKey = vmessKDF16(key: key, path: [Array("VMess Header AEAD Key".utf8), authID, connectionNonce])
    let headerNonce = Array(vmessKDF(key: key, path: [Array("VMess Header AEAD Nonce".utf8), authID, connectionNonce]).prefix(12))
    guard let header = try? aesGCMOpen(key: headerKey, nonce: headerNonce, sealed: sealedHeader, aad: authID) else {
        throw VMessAEADOpenError.authenticationFailed
    }
    return header
}

public struct VMessRequest {
    public let cmdKey: [UInt8]      // MD5(uuid + magic)
    public let requestBodyIV: [UInt8]
    public let requestBodyKey: [UInt8]
    public let responseHeaderByte: UInt8
    public let wireBytes: [UInt8]

    public static let securityAES128GCM: UInt8 = 3
    public static let securityChaCha20Poly1305: UInt8 = 4
    /// `RequestOptionChunkStream` -- tells the server the body that follows
    /// is framed into length-prefixed chunks (see `sealVMessBodyChunk`)
    /// rather than a raw byte pipe, which any non-`none` Security implies.
    public static let optionChunkStream: UInt8 = 0x01
    public static let optionChunkMasking: UInt8 = 0x04
    public static let optionGlobalPadding: UInt8 = 0x08
    public static let optionAuthenticatedLength: UInt8 = 0x10
    public static let commandTCP: UInt8 = 1
    /// UDP-over-this-connection: the body that follows is framed into
    /// per-datagram chunks (see ChainCore's `TunneledUDPRelay`) rather than
    /// being a raw byte pipe -- everything else about the handshake
    /// (KDF, AEAD header sealing, response-header decode) is identical to
    /// `commandTCP`.
    public static let commandUDP: UInt8 = 2

    public static func build(uuid: [UInt8], target: VMessTarget, command: UInt8 = commandTCP, security: VMessSecurity = .auto, bodyOptions: VMessBodyOptions = .modern) throws -> VMessRequest {
        let cmdKey = md5(uuid + cmdKeyMagic)
        let requestBodyIV = (0..<16).map { _ in UInt8.random(in: 0...255) }
        let requestBodyKey = (0..<16).map { _ in UInt8.random(in: 0...255) }
        let responseHeaderByte = UInt8.random(in: 0...255)
        let paddingLen = Int.random(in: 0...15)

        var plain: [UInt8] = []
        plain.append(1)                              // Ver
        plain += requestBodyIV
        plain += requestBodyKey
        plain.append(responseHeaderByte)
        var option = optionChunkStream
        if bodyOptions.chunkMasking { option |= optionChunkMasking }
        if bodyOptions.effectiveGlobalPadding { option |= optionGlobalPadding }
        if bodyOptions.authenticatedLength { option |= optionAuthenticatedLength }
        plain.append(option)
        let securityByte = security.resolved == .chacha20Poly1305 ? securityChaCha20Poly1305 : securityAES128GCM
        plain.append(UInt8(paddingLen << 4) | securityByte)
        plain.append(0)                               // Reserved
        plain.append(command)
        plain += target.port.bigEndianBytes
        plain += try ProxyAddress.parse(target.host).vmessEncoded
        if paddingLen > 0 { plain += (0..<paddingLen).map { _ in UInt8.random(in: 0...255) } }
        plain += fnv1a32(plain).bigEndianBytes

        let wire = sealVMessAEADHeader(key: cmdKey, data: plain)
        return VMessRequest(cmdKey: cmdKey, requestBodyIV: requestBodyIV, requestBodyKey: requestBodyKey,
                             responseHeaderByte: responseHeaderByte, wireBytes: wire)
    }
}

// MARK: - Response header decode

public struct VMessResponseHeader {
    public let optionByte: UInt8
    public let bytesConsumedBeforeBody: Int // not used, the response body's own chunk framing (see sealVMessBodyChunk) starts immediately after header decode
}

public enum VMessError: Error, Equatable { case malformedResponse, responseHeaderMismatch }

/// A VMess server deliberately gives no distinguishing response to a bad
/// UUID/AuthID (to resist active probing) -- it just stops talking -- so
/// `timeout` (see ProxyKit's `ProxyError.timedOut`) is what turns "wrong
/// credentials" (or an unreachable/firewalled server) into a prompt,
/// reported error instead of an indefinite hang. (Found by testing against a
/// real local xray-core server with a deliberately wrong UUID -- see
/// Scripts/integration_test.sh.)
public func decodeResponseHeader(requestBodyKey: [UInt8], requestBodyIV: [UInt8], responseHeaderByte: UInt8, connection: any ByteStreamSource, timeout: TimeInterval? = 10) async throws -> VMessResponseHeader {
    let responseBodyKey = Array(sha256(requestBodyKey).prefix(16))
    let responseBodyIV = Array(sha256(requestBodyIV).prefix(16))

    let lengthKey = vmessKDF16(key: responseBodyKey, path: [Array("AEAD Resp Header Len Key".utf8)])
    let lengthNonce = Array(vmessKDF(key: responseBodyIV, path: [Array("AEAD Resp Header Len IV".utf8)]).prefix(12))

    let sealedLength = try await connection.readExactly(18, timeout: timeout)
    let lengthBytes = try aesGCMOpen(key: lengthKey, nonce: lengthNonce, sealed: sealedLength, aad: [])
    let headerLen = Int(lengthBytes[0]) << 8 | Int(lengthBytes[1])

    let headerKey = vmessKDF16(key: responseBodyKey, path: [Array("AEAD Resp Header Key".utf8)])
    let headerNonce = Array(vmessKDF(key: responseBodyIV, path: [Array("AEAD Resp Header IV".utf8)]).prefix(12))

    let sealedHeader = try await connection.readExactly(headerLen + 16, timeout: timeout)
    let header = try aesGCMOpen(key: headerKey, nonce: headerNonce, sealed: sealedHeader, aad: [])

    guard header.count >= 4 else { throw VMessError.malformedResponse }
    guard header[0] == responseHeaderByte else { throw VMessError.responseHeaderMismatch }
    return VMessResponseHeader(optionByte: header[1], bytesConsumedBeforeBody: 4)
}

// MARK: - VMess AEAD body chunking (AES-128-GCM / ChaCha20-Poly1305)
//
// Once the request/response AEAD headers are exchanged, application data in
// each direction is split into individually authenticated chunks. Modern
// framing masks each 2-byte length with a SHAKE128 stream derived from that
// direction's IV and appends 0...63 cleartext random padding bytes; the
// optional Authenticated Length experiment replaces the masked prefix with
// an independently AEAD-sealed 18-byte length. The request option bits tell
// the server exactly which framing is in use. The selected body AEAD is
// declared independently in the request header's security nibble.
//
// Each direction's body key is that direction's own body key (`requestBodyKey`
// for client->server, `sha256(requestBodyKey).prefix(16)` for server->client,
// per `decodeResponseHeader` above) used directly as the AES-128 key -- no
// further KDF step, matching v2ray-core's own `proxy/vmess/aead.go`. The
// per-chunk nonce is a monotonic `UInt16` counter (big-endian, wrapping) plus
// bytes `[2..<12]` of that direction's body IV.

let vmessMaxChunkPlaintext = 16 * 1024

/// Minimal streaming SHAKE128 used by VMess's chunk-size masker and padding
/// generator. SHAKE absorbs the direction's 16-byte IV once, then yields one
/// continuous byte stream shared by padding and length masking.
public struct VMessSHAKE128 {
    private static let rate = 168
    private static let rotations: [Int] = [
         0,  1, 62, 28, 27, 36, 44,  6, 55, 20,  3, 10, 43,
        25, 39, 41, 45, 15, 21,  8, 18,  2, 61, 56, 14,
    ]
    private static let roundConstants: [UInt64] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]

    private var state = [UInt64](repeating: 0, count: 25)
    private var offset = 0

    public init(seed: [UInt8]) {
        var block = [UInt8](repeating: 0, count: Self.rate)
        precondition(seed.count < Self.rate)
        block.replaceSubrange(0..<seed.count, with: seed)
        block[seed.count] ^= 0x1f // SHAKE domain separator
        block[Self.rate - 1] ^= 0x80
        for i in 0..<Self.rate { state[i / 8] ^= UInt64(block[i]) << UInt64(8 * (i % 8)) }
        Self.permute(&state)
    }

    public mutating func read(_ count: Int) -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(count)
        while result.count < count {
            if offset == Self.rate {
                Self.permute(&state)
                offset = 0
            }
            result.append(UInt8((state[offset / 8] >> UInt64(8 * (offset % 8))) & 0xff))
            offset += 1
        }
        return result
    }

    public mutating func nextUInt16() -> UInt16 {
        let bytes = read(2)
        return UInt16(bytes[0]) << 8 | UInt16(bytes[1])
    }

    private static func permute(_ a: inout [UInt64]) {
        for rc in roundConstants {
            var c = [UInt64](repeating: 0, count: 5)
            for x in 0..<5 { c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] }
            var d = [UInt64](repeating: 0, count: 5)
            for x in 0..<5 { d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotatedLeft(1) }
            for y in 0..<5 { for x in 0..<5 { a[x + 5 * y] ^= d[x] } }

            var b = [UInt64](repeating: 0, count: 25)
            for y in 0..<5 {
                for x in 0..<5 {
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotatedLeft(rotations[x + 5 * y])
                }
            }
            for y in 0..<5 {
                for x in 0..<5 { a[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]) }
            }
            a[0] ^= rc
        }
    }
}

private extension UInt64 {
    func rotatedLeft(_ count: Int) -> UInt64 {
        guard count != 0 else { return self }
        return (self << UInt64(count)) | (self >> UInt64(64 - count))
    }
}

func vmessChunkNonce(counter: UInt16, iv: [UInt8]) -> [UInt8] {
    counter.bigEndianBytes + Array(iv[2..<12])
}

func sealVMessLength(_ value: UInt16, key: [UInt8], iv: [UInt8], counter: UInt16, security: VMessSecurity) -> [UInt8] {
    let authKey = vmessKDF16(key: key, path: [Array("auth_len".utf8)])
    let nonce = vmessChunkNonce(counter: counter, iv: iv)
    switch security.resolved {
    case .chacha20Poly1305:
        return chachaPolySeal(key: vmessChaCha20Poly1305Key(authKey), nonce: nonce, plaintext: value.bigEndianBytes, aad: [])
    case .auto, .aes128GCM:
        return aesGCMSeal(key: authKey, nonce: nonce, plaintext: value.bigEndianBytes, aad: [])
    }
}

func openVMessLength(_ sealed: [UInt8], key: [UInt8], iv: [UInt8], counter: UInt16, security: VMessSecurity) throws -> UInt16 {
    let authKey = vmessKDF16(key: key, path: [Array("auth_len".utf8)])
    let nonce = vmessChunkNonce(counter: counter, iv: iv)
    let plain: [UInt8]
    switch security.resolved {
    case .chacha20Poly1305:
        plain = try chachaPolyOpen(key: vmessChaCha20Poly1305Key(authKey), nonce: nonce, sealed: sealed, aad: [])
    case .auto, .aes128GCM:
        plain = try aesGCMOpen(key: authKey, nonce: nonce, sealed: sealed, aad: [])
    }
    guard plain.count == 2 else { throw VMessError.malformedResponse }
    return UInt16(plain[0]) << 8 | UInt16(plain[1])
}

/// Seals one chunk of outgoing application data, returning the 2-byte
/// length prefix plus the sealed ciphertext ready to write to the wire.
public func vmessChaCha20Poly1305Key(_ key: [UInt8]) -> [UInt8] {
    let firstHalf = md5(key)
    return firstHalf + md5(firstHalf)
}

func sealVMessBodyChunk(key: [UInt8], iv: [UInt8], counter: UInt16, plaintext: [UInt8], security: VMessSecurity = .aes128GCM) -> [UInt8] {
    let nonce = vmessChunkNonce(counter: counter, iv: iv)
    let sealed: [UInt8]
    switch security.resolved {
    case .chacha20Poly1305:
        sealed = chachaPolySeal(key: vmessChaCha20Poly1305Key(key), nonce: nonce, plaintext: plaintext, aad: [])
    case .auto, .aes128GCM:
        sealed = aesGCMSeal(key: key, nonce: nonce, plaintext: plaintext, aad: [])
    }
    return UInt16(sealed.count).bigEndianBytes + sealed
}

/// Opens one already-length-delimited chunk's ciphertext (the bytes
/// following its 2-byte length prefix) back into plaintext.
func openVMessBodyChunkPayload(key: [UInt8], iv: [UInt8], counter: UInt16, sealed: [UInt8], security: VMessSecurity = .aes128GCM) throws -> [UInt8] {
    let nonce = vmessChunkNonce(counter: counter, iv: iv)
    switch security.resolved {
    case .chacha20Poly1305:
        return try chachaPolyOpen(key: vmessChaCha20Poly1305Key(key), nonce: nonce, sealed: sealed, aad: [])
    case .auto, .aes128GCM:
        return try aesGCMOpen(key: key, nonce: nonce, sealed: sealed, aad: [])
    }
}

// MARK: - Reusable VMess session
//
// Encapsulates one VMess-proxied connection: send the AEAD request header
// for `target`, then expose a plain send/receive byte pipe -- backed by real,
// chunked AEAD body encryption on the wire -- so callers don't need
// to know any protocol internals to relay their own application data.
//
// `VMessSession` conforms to `ProxyTransport` itself, so it can serve as the
// transport for a *further* hop's handshake (e.g. SOCKS5 or Shadowsocks
// tunneled through this VMess proxy): `readExactly` buffers across
// underlying reads the same way `TCPConn.readExactly` buffers partial TCP
// reads, just one layer up over whatever `conn` hands back from `readAvailable`.

public final class VMessSession: ByteStreamSource, ByteStreamSink, ByteStreamAvailableReader, ByteStreamCloser {
    private let conn: any ProxyTransport
    private let requestBodyKey: [UInt8]
    private let requestBodyIV: [UInt8]
    private let responseBodyKey: [UInt8]
    private let responseBodyIV: [UInt8]
    private let responseHeaderByte: UInt8
    private let security: VMessSecurity
    private let bodyOptions: VMessBodyOptions
    private var buffered: [UInt8] = []
    private var cachedResponseHeader: VMessResponseHeader?
    private var outboundChunkCounter: UInt16 = 0
    private var inboundChunkCounter: UInt16 = 0
    private var outboundShake: VMessSHAKE128?
    private var inboundShake: VMessSHAKE128?

    private init(conn: any ProxyTransport, requestBodyKey: [UInt8], requestBodyIV: [UInt8], responseHeaderByte: UInt8, security: VMessSecurity, bodyOptions: VMessBodyOptions) {
        self.conn = conn
        self.requestBodyKey = requestBodyKey
        self.requestBodyIV = requestBodyIV
        self.responseBodyKey = Array(sha256(requestBodyKey).prefix(16))
        self.responseBodyIV = Array(sha256(requestBodyIV).prefix(16))
        self.responseHeaderByte = responseHeaderByte
        self.security = security.resolved
        self.bodyOptions = bodyOptions
        self.outboundShake = (bodyOptions.chunkMasking || bodyOptions.effectiveGlobalPadding) ? VMessSHAKE128(seed: requestBodyIV) : nil
        self.inboundShake = (bodyOptions.chunkMasking || bodyOptions.effectiveGlobalPadding) ? VMessSHAKE128(seed: Array(sha256(requestBodyIV).prefix(16))) : nil
    }

    /// Sends the AEAD request header asking to connect to `target` over an
    /// already-open `transport`. This is the primitive every other `open`
    /// overload reduces to -- `transport` is a fresh `TCPConn` when VMess is
    /// the first hop of a chain, or a previous hop's already-open `Session`
    /// when VMess is stacked on top of it.
    ///
    /// `tls`/`wsPath` optionally wrap `transport` first, in that order
    /// (dial -> TLS -> WS -> this handshake) -- the same composition
    /// VLESS/Trojan use, via `TLSConn`'s Secure Transport bridge (not native
    /// TLS: that's only available for a truly fresh dial, see
    /// `TrojanSession`'s own doc comment on why, and this generic entry
    /// point may be stacking VMess mid-chain instead) and `WSConn`.
    public static func open(
        over transport: any ProxyTransport, uuid: String, target: VMessTarget, command: UInt8 = VMessRequest.commandTCP, security: VMessSecurity = .auto, bodyOptions: VMessBodyOptions = .modern,
        tls: Bool = false, sni: String = "", allowInsecure: Bool = false,
        wsPath: String? = nil, wsHost: String? = nil,
        timeout: TimeInterval? = 10
    ) async throws -> VMessSession {
        var conn: any ProxyTransport = transport
        if tls {
            conn = try await TLSConn.handshake(over: conn, options: TLSOptions(serverName: sni, allowInsecure: allowInsecure), timeout: timeout)
        }
        if let wsPath {
            // `sni` is expected to already be a meaningful hostname by this
            // point (the caller's own fallback to the hop's real `host`,
            // same discipline `ChainCore`'s VLESS/Trojan wiring already
            // uses) even when `tls` is `false` -- this generic entry point
            // has no `host` of its own to fall back to further.
            conn = try await WSConn.handshake(over: conn, host: wsHost ?? sni, path: wsPath, timeout: timeout)
        }
        let request = try VMessRequest.build(uuid: parseUUID(uuid), target: target, command: command, security: security, bodyOptions: bodyOptions)
        try await conn.send(request.wireBytes, timeout: timeout)
        return VMessSession(conn: conn, requestBodyKey: request.requestBodyKey,
                             requestBodyIV: request.requestBodyIV, responseHeaderByte: request.responseHeaderByte, security: security, bodyOptions: bodyOptions)
    }

    /// Dials `server` directly over TCP, optionally wraps TLS/WS, then sends
    /// the AEAD request header. `connectTimeout` guards the dial, any
    /// TLS/WS handshake, and the header send alike against a
    /// firewalled/unresponsive server.
    public static func open(server: VMessServerConfig, target: VMessTarget, command: UInt8 = VMessRequest.commandTCP, connectTimeout: TimeInterval? = 10) async throws -> VMessSession {
        let conn = TCPConn(host: server.host, port: server.port)
        try await conn.connect(timeout: connectTimeout)
        do {
            return try await open(
                over: conn, uuid: server.uuid, target: target, command: command, security: server.security, bodyOptions: server.bodyOptions,
                tls: server.tls, sni: server.sni ?? server.host, allowInsecure: server.allowInsecure,
                wsPath: server.wsPath, wsHost: server.wsHost,
                timeout: connectTimeout
            )
        } catch {
            // `conn` already connected above -- without this, a failure
            // inside `open(over:)`'s own TLS/WS handshake or request send
            // would leak that socket, since nothing else still references
            // `conn` once this rethrows.
            conn.close()
            throw error
        }
    }

    /// Sends application bytes toward `target`, split into `vmessMaxChunkPlaintext`-sized
    /// chunks and individually sealed with the selected AEAD before hitting the wire.
    public func send(_ bytes: [UInt8], timeout: TimeInterval? = nil) async throws {
        guard !bytes.isEmpty else { return }
        var wire: [UInt8] = []
        var offset = 0
        while offset < bytes.count {
            let end = min(offset + vmessMaxChunkPlaintext, bytes.count)
            let plaintext = Array(bytes[offset..<end])
            let sealed = Array(sealVMessBodyChunk(key: requestBodyKey, iv: requestBodyIV, counter: outboundChunkCounter, plaintext: plaintext, security: security).dropFirst(2))
            let paddingLength = bodyOptions.effectiveGlobalPadding ? Int(outboundShake!.nextUInt16() % 64) : 0
            let totalLength = sealed.count + paddingLength
            if bodyOptions.authenticatedLength {
                wire += sealVMessLength(UInt16(totalLength - 16), key: requestBodyKey, iv: requestBodyIV, counter: outboundChunkCounter, security: security)
            } else {
                let mask = bodyOptions.chunkMasking ? outboundShake!.nextUInt16() : 0
                wire += (UInt16(totalLength) ^ mask).bigEndianBytes
            }
            wire += sealed
            if paddingLength > 0 { wire += (0..<paddingLength).map { _ in UInt8.random(in: 0...255) } }
            outboundChunkCounter &+= 1
            offset = end
        }
        try await conn.send(wire, timeout: timeout)
    }

    /// Reads and validates the AEAD response header, caching the result so
    /// it's safe to call this explicitly (as a caller wanting `optionByte`
    /// up front does) *and* to let it happen lazily on the first
    /// `receive()`/`readAvailable`/`readExactly` call otherwise -- callers
    /// don't have to call this at all if they don't need `optionByte`.
    ///
    /// This must stay lazy rather than eager (e.g. run automatically right
    /// after `open`): a real VMess server has nothing to send back yet at
    /// that point -- there's no separate "handshake ack", the response
    /// header is only sent piggybacked with the first real response data
    /// once the server has something to relay. Reading it
    /// before this session's caller has sent anything (its own request body,
    /// or -- when this session is a chain's transport for the next hop --
    /// that hop's handshake bytes) deadlocks against a real server: confirmed
    /// against real xray-core, which never writes anything back until the
    /// outbound connection it dialed produces data of its own.
    public func readResponseHeader(timeout: TimeInterval? = 10) async throws -> VMessResponseHeader {
        if let cachedResponseHeader { return cachedResponseHeader }
        let header = try await decodeResponseHeader(requestBodyKey: requestBodyKey, requestBodyIV: requestBodyIV,
                                                      responseHeaderByte: responseHeaderByte, connection: conn, timeout: timeout)
        cachedResponseHeader = header
        return header
    }

    /// Reads raw application bytes coming back from `target` ([] once the stream ends).
    public func receive() async throws -> [UInt8] {
        try await readAvailable(timeout: nil)
    }

    public func readAvailable(timeout: TimeInterval? = nil) async throws -> [UInt8] {
        _ = try await readResponseHeader(timeout: timeout ?? 10) // no-op once cached
        if !buffered.isEmpty {
            let result = buffered
            buffered = []
            return result
        }
        return try await readNextChunk(timeout: timeout)
    }

    /// Reads and decrypts exactly one length-prefixed body chunk off `conn`
    /// (see `openVMessBodyChunkPayload`). A clean EOF right at a chunk
    /// boundary (the length prefix itself never arrives) is the ordinary
    /// end of the stream, so it's folded into the same "[] means done"
    /// contract `readAvailable` already promises, rather than propagated as
    /// `ProxyError.connectionClosed` -- that error stays reserved for a
    /// connection dying mid-chunk, a real truncation worth surfacing.
    private func readNextChunk(timeout: TimeInterval?) async throws -> [UInt8] {
        let lengthBytes: [UInt8]
        do {
            lengthBytes = try await conn.readExactly(bodyOptions.authenticatedLength ? 18 : 2, timeout: timeout)
        } catch ProxyError.connectionClosed {
            return []
        }
        let paddingLength = bodyOptions.effectiveGlobalPadding ? Int(inboundShake!.nextUInt16() % 64) : 0
        let length: Int
        if bodyOptions.authenticatedLength {
            let decoded = try openVMessLength(lengthBytes, key: requestBodyKey, iv: requestBodyIV, counter: inboundChunkCounter, security: security)
            length = Int(decoded) + 16
        } else {
            let mask = bodyOptions.chunkMasking ? inboundShake!.nextUInt16() : 0
            length = Int((UInt16(lengthBytes[0]) << 8 | UInt16(lengthBytes[1])) ^ mask)
        }
        guard length > 0 else { return [] }
        guard length >= paddingLength + 16 else { throw VMessError.malformedResponse }
        let payloadAndPadding = try await conn.readExactly(length, timeout: timeout)
        let sealed = Array(payloadAndPadding.prefix(length - paddingLength))
        let plaintext = try openVMessBodyChunkPayload(key: responseBodyKey, iv: responseBodyIV, counter: inboundChunkCounter, sealed: sealed, security: security)
        inboundChunkCounter &+= 1
        return plaintext
    }

    /// Exact-length read for a protocol stacked *on top of* this VMess hop:
    /// buffers across as many decrypted chunks as needed, the same pattern
    /// `TCPConn.readExactly` uses over raw socket reads.
    public func readExactly(_ n: Int, timeout: TimeInterval? = nil) async throws -> [UInt8] {
        _ = try await readResponseHeader(timeout: timeout ?? 10) // no-op once cached
        while buffered.count < n {
            let chunk = try await readNextChunk(timeout: timeout)
            if chunk.isEmpty { throw ProxyError.connectionClosed }
            buffered += chunk
        }
        let result = Array(buffered.prefix(n))
        buffered.removeFirst(n)
        return result
    }

    public func close() { conn.close() }
}
