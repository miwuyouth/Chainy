// ShadowsocksCore.swift
//
// A minimal Shadowsocks (AEAD, SIP004 "2017 AEAD ciphers") TCP client, built
// on ProxyKit's shared networking/crypto/address primitives.
//
// Verified against the reference implementation in shadowsocks/shadowsocks-rust
// and its shadowsocks/shadowsocks-crypto crate (v1/cipher.rs, v1/aeadcipher):
//   - Master key: OpenSSL EVP_BytesToKey, MD5, no salt, chained digest.
//   - Per-connection subkey: HKDF-SHA1(IKM: master key, salt: connection
//     salt, info: "ss-subkey"), output length == cipher key length.
//   - AEAD nonce: starts at all-zero, incremented as a little-endian
//     counter (low byte first, carrying into the next byte) after *every*
//     seal/open call -- both the length-tag and the payload-tag each
//     consume one increment.
//   - No additional authenticated data on any AEAD operation.
//   - Max plaintext per chunk: 0x3FFF bytes.
//
// This targets the *AEAD* protocol specifically (not the older, insecure
// stream ciphers, and not the newer, less-widely-deployed "2022 edition"
// which uses a different, BLAKE3-based KDF) -- this is what shadowsocks-libev,
// shadowsocks-rust's default, and Outline all speak.
//
// The TCP relay above is the persistent, incrementing-nonce chunk stream
// AEAD mandates for connections; UDP relay (`shadowsocksSealUDPPacket`/
// `shadowsocksOpenUDPPacket` below) is a different, per-packet shape the
// same spec also defines: each datagram is independently AEAD-sealed with
// its own fresh salt and an all-zero nonce (no persistent stream, no
// incrementing counter -- there's nothing to increment *across* datagrams
// that arrive out of order or not at all, unlike TCP's ordered stream).

import Foundation
import ProxyKit

// MARK: - Cipher parameters

public enum ShadowsocksCipher: String, CaseIterable, Equatable {
    case aes128Gcm = "aes-128-gcm"
    case aes256Gcm = "aes-256-gcm"
    case chacha20IetfPoly1305 = "chacha20-ietf-poly1305"
    /// "AEAD-2022" edition (SIP022-ish -- see this file's own 2022 section
    /// below): a fixed-length raw pre-shared key + BLAKE3 session-subkey
    /// derivation and a replay-protected header, not just a different AEAD
    /// choice. TCP only for now -- UDP's session_id/packet_id framing is
    /// real, separate follow-on work (see `ChainCore.ShadowsocksUDPRelay`'s
    /// own guard against picking one of these for UDP).
    case aead2022Blake3Aes128Gcm = "2022-blake3-aes-128-gcm"
    case aead2022Blake3Aes256Gcm = "2022-blake3-aes-256-gcm"
    case aead2022Blake3Chacha20Poly1305 = "2022-blake3-chacha20-poly1305"

    public var is2022Edition: Bool {
        switch self {
        case .aead2022Blake3Aes128Gcm, .aead2022Blake3Aes256Gcm, .aead2022Blake3Chacha20Poly1305: return true
        case .aes128Gcm, .aes256Gcm, .chacha20IetfPoly1305: return false
        }
    }

    public var keyLength: Int {
        switch self {
        case .aes128Gcm, .aead2022Blake3Aes128Gcm: return 16
        case .aes256Gcm, .chacha20IetfPoly1305, .aead2022Blake3Aes256Gcm, .aead2022Blake3Chacha20Poly1305: return 32
        }
    }

    /// The AEAD spec mandates saltLength == keyLength for every cipher here, 2017 or 2022.
    public var saltLength: Int { keyLength }
    public var nonceLength: Int { 12 }
    public var tagLength: Int { 16 }

    /// 2022-edition ciphers raise the AEAD chunk stream's max plaintext
    /// size per chunk from 0x3FFF to 0xFFFF. Distinct from the public
    /// `ShadowsocksMaxChunkSize.value` constant below (which existing
    /// 2017-only tests already depend on as exactly 0x3FFF) -- this is the
    /// cipher-aware value `ShadowsocksChunkCrypto`/`ShadowsocksSession`
    /// actually use.
    var maxChunkSize: Int { is2022Edition ? 0xFFFF : 0x3FFF }

    fileprivate func seal(key: [UInt8], nonce: [UInt8], plaintext: [UInt8]) -> [UInt8] {
        switch self {
        case .aes128Gcm, .aes256Gcm, .aead2022Blake3Aes128Gcm, .aead2022Blake3Aes256Gcm:
            return aesGCMSeal(key: key, nonce: nonce, plaintext: plaintext, aad: [])
        case .chacha20IetfPoly1305, .aead2022Blake3Chacha20Poly1305:
            return chachaPolySeal(key: key, nonce: nonce, plaintext: plaintext, aad: [])
        }
    }

    fileprivate func open(key: [UInt8], nonce: [UInt8], sealed: [UInt8]) throws -> [UInt8] {
        switch self {
        case .aes128Gcm, .aes256Gcm, .aead2022Blake3Aes128Gcm, .aead2022Blake3Aes256Gcm:
            return try aesGCMOpen(key: key, nonce: nonce, sealed: sealed, aad: [])
        case .chacha20IetfPoly1305, .aead2022Blake3Chacha20Poly1305:
            return try chachaPolyOpen(key: key, nonce: nonce, sealed: sealed, aad: [])
        }
    }
}

public struct ShadowsocksServerConfig {
    public let host: String
    public let port: UInt16
    public let password: String
    public let cipher: ShadowsocksCipher

    public init(host: String, port: UInt16, password: String, cipher: ShadowsocksCipher) {
        self.host = host
        self.port = port
        self.password = password
        self.cipher = cipher
    }
}

// MARK: - Key derivation

/// OpenSSL's `EVP_BytesToKey` with MD5 and no salt: repeatedly
/// MD5(previous digest || password) until there are enough bytes, then
/// truncate to `keyLength`. This is how classic Shadowsocks (and, per the
/// AEAD spec, its master key too) turns a password into key bytes.
public func evpBytesToKey(password: String, keyLength: Int) -> [UInt8] {
    let passwordBytes = Array(password.utf8)
    var key: [UInt8] = []
    var previousDigest: [UInt8] = []
    while key.count < keyLength {
        previousDigest = md5(previousDigest + passwordBytes)
        key += previousDigest
    }
    return Array(key.prefix(keyLength))
}

/// Per-connection subkey: HKDF-SHA1(IKM: masterKey, salt, info: "ss-subkey"),
/// output length == the cipher's key length.
public func shadowsocksDeriveSubkey(masterKey: [UInt8], salt: [UInt8], cipher: ShadowsocksCipher) -> [UInt8] {
    hkdfSHA1(ikm: masterKey, salt: salt, info: Array("ss-subkey".utf8), outputByteCount: cipher.keyLength)
}

// MARK: - 2022 edition: PSK + BLAKE3 session-subkey derivation
//
// Unlike every cipher above, a 2022-edition cipher's "password" is a
// base64-encoded, fixed-length raw pre-shared key (PSK) -- never a
// passphrase run through `evpBytesToKey`. Real-world Shadowsocks 2022
// clients (shadowsocks-rust, Clash Meta) all reuse the same "password"
// config field for this, so this client does too rather than inventing a
// new field/case just for the credential-format difference.

public enum ShadowsocksPSKError: Error, Equatable {
    /// `password` wasn't valid base64 (standard or URL-safe, padded or not).
    case invalidBase64
    /// Decoded to the wrong number of bytes for this cipher's `keyLength`.
    case wrongLength(expected: Int, got: Int)
}

/// Decodes `password` as `cipher`'s raw PSK, tolerant of URL-safe alphabet
/// and missing padding (real-world generators aren't consistent about
/// either) -- same lenient decode `SubscriptionCore`'s own v2ray-URI parser
/// uses, duplicated here rather than shared across modules for one small
/// self-contained helper.
public func shadowsocks2022ParsePSK(password: String, cipher: ShadowsocksCipher) throws -> [UInt8] {
    var normalized = password.trimmingCharacters(in: .whitespacesAndNewlines)
    normalized = normalized.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    let padding = (4 - normalized.count % 4) % 4
    normalized += String(repeating: "=", count: padding)
    guard let data = Data(base64Encoded: normalized) else { throw ShadowsocksPSKError.invalidBase64 }
    guard data.count == cipher.keyLength else { throw ShadowsocksPSKError.wrongLength(expected: cipher.keyLength, got: data.count) }
    return Array(data)
}

/// `blake3::derive_key(context: "shadowsocks 2022 session subkey", key_material: psk + salt)`,
/// truncated to `psk.count` bytes -- replaces `shadowsocksDeriveSubkey`
/// (HKDF-SHA1) for 2022-edition ciphers.
public func shadowsocks2022DeriveSessionSubkey(psk: [UInt8], salt: [UInt8]) -> [UInt8] {
    blake3DeriveKey(context: "shadowsocks 2022 session subkey", keyMaterial: psk + salt, outputByteCount: psk.count)
}

// MARK: - AEAD chunk framing
//
// Each direction (client->server, server->client) is its own independent
// stream of chunks: [encrypted 2-byte length][length tag][encrypted
// payload][payload tag], sharing one subkey and one incrementing nonce
// counter across every chunk in that direction.

public enum ShadowsocksMaxChunkSize {
    public static let value = 0x3FFF
}

final class ShadowsocksChunkCrypto {
    private let cipher: ShadowsocksCipher
    private let key: [UInt8]
    private var nonce: [UInt8]

    init(cipher: ShadowsocksCipher, key: [UInt8]) {
        self.cipher = cipher
        self.key = key
        self.nonce = [UInt8](repeating: 0, count: cipher.nonceLength)
    }

    /// Little-endian increment with carry -- matches shadowsocks-crypto's
    /// `increase_nonce` exactly (increment the low byte; only touch the
    /// next byte if that one wrapped around to zero).
    private func incrementNonce() {
        for i in 0..<nonce.count {
            nonce[i] = nonce[i] &+ 1
            if nonce[i] != 0 { break }
        }
    }

    private func sealOnce(_ plaintext: [UInt8]) -> [UInt8] {
        let sealed = cipher.seal(key: key, nonce: nonce, plaintext: plaintext)
        incrementNonce()
        return sealed
    }

    private func openOnce(_ sealed: [UInt8]) throws -> [UInt8] {
        let opened = try cipher.open(key: key, nonce: nonce, sealed: sealed)
        incrementNonce()
        return opened
    }

    /// One raw AEAD seal/open with no chunk-length prefixing of its own --
    /// unlike `sealChunk`/`openChunk` below (which always build/expect the
    /// `[length][payload]` pair), 2022 edition's two request header chunks
    /// and one response header chunk are each their own complete AEAD unit,
    /// with any length field living *inside* one chunk's own plaintext
    /// instead of prefixing the next one. Still shares this same nonce
    /// counter -- every raw/chunk AEAD operation on one `ShadowsocksChunkCrypto`
    /// increments it, header chunks included, exactly like the spec's own
    /// "increment after every seal/open" rule.
    func sealRaw(_ plaintext: [UInt8]) -> [UInt8] { sealOnce(plaintext) }
    func openRaw(_ sealed: [UInt8]) throws -> [UInt8] { try openOnce(sealed) }

    /// Encrypts one chunk: `[encrypted length][length tag][encrypted payload][payload tag]`.
    func sealChunk(_ plaintext: [UInt8]) -> [UInt8] {
        precondition(plaintext.count <= cipher.maxChunkSize)
        let sealedLength = sealOnce(UInt16(plaintext.count).bigEndianBytes)
        let sealedPayload = sealOnce(plaintext)
        return sealedLength + sealedPayload
    }

    /// Decrypts one chunk read from `source`.
    func openChunk(from source: any ByteStreamSource, timeout: TimeInterval?) async throws -> [UInt8] {
        let sealedLength = try await source.readExactly(2 + cipher.tagLength, timeout: timeout)
        let lengthBytes = try openOnce(sealedLength)
        let length = Int(lengthBytes[0]) << 8 | Int(lengthBytes[1])
        let sealedPayload = try await source.readExactly(length + cipher.tagLength, timeout: timeout)
        return try openOnce(sealedPayload)
    }
}

// MARK: - UDP relay (single packet, chainable)
//
// One real Shadowsocks server, given a UDP packet, decrypts it, reads the
// embedded ATYP+addr+port, and does a raw `sendto(payload, addr:port)` --
// it never re-encrypts or inspects what `payload` looks like. That's what
// lets `ChainCore.ShadowsocksUDPRelay` chain N Shadowsocks hops just by
// nesting one of these packets inside another's `payload` (innermost = the
// real final target, built outward) rather than needing any transport
// -layering the way TCP chaining does -- see that type's own doc comment.

public enum ShadowsocksUDPError: Error, Equatable {
    /// Shorter than one cipher's salt, or the AEAD-sealed remainder didn't
    /// decrypt to at least an ATYP+addr+port prefix.
    case packetTooShort
    /// The decrypted plaintext's ATYP byte wasn't 0x01/0x03/0x04.
    case malformedAddress
    /// 2022-edition ciphers use an entirely different UDP packet format
    /// (a session_id+packet_id "separate header", encrypted differently
    /// again between the AES and ChaCha variants) that isn't implemented
    /// yet -- refused here rather than silently sealing with this (2017-only)
    /// scheme under the wrong cipher, which a real 2022 server wouldn't
    /// even recognize as a valid packet.
    case cipherNotSupportedForUDP(ShadowsocksCipher)
}

/// Seals one UDP packet: `[fresh salt][AEAD-seal(ATYP+addr+port+payload)]`,
/// zero nonce (see this file's own top comment for why -- every datagram is
/// its own independent AEAD operation, unlike the TCP chunk stream's
/// incrementing counter).
public func shadowsocksSealUDPPacket(password: String, cipher: ShadowsocksCipher, targetHost: ProxyAddress, targetPort: UInt16, payload: [UInt8]) throws -> [UInt8] {
    guard !cipher.is2022Edition else { throw ShadowsocksUDPError.cipherNotSupportedForUDP(cipher) }
    let masterKey = evpBytesToKey(password: password, keyLength: cipher.keyLength)
    let salt = (0..<cipher.saltLength).map { _ in UInt8.random(in: 0...255) }
    let subkey = shadowsocksDeriveSubkey(masterKey: masterKey, salt: salt, cipher: cipher)
    let plaintext = try targetHost.socks5Encoded + targetPort.bigEndianBytes + payload
    let zeroNonce = [UInt8](repeating: 0, count: cipher.nonceLength)
    return salt + cipher.seal(key: subkey, nonce: zeroNonce, plaintext: plaintext)
}

/// The inverse of `shadowsocksSealUDPPacket`: derives the same per-packet
/// subkey from the packet's own leading salt, opens the AEAD-sealed
/// remainder, and splits the decrypted `ATYP+addr+port+payload` prefix back
/// apart. The returned `address` is whichever address *this* packet's layer
/// embedded -- for a chain of N hops, only the last hop's layer embeds the
/// real remote address that actually replied (every other layer's embedded
/// address is just "which hop forwarded this").
public func shadowsocksOpenUDPPacket(password: String, cipher: ShadowsocksCipher, packet: [UInt8]) throws -> (address: ProxyAddress, port: UInt16, payload: [UInt8]) {
    guard !cipher.is2022Edition else { throw ShadowsocksUDPError.cipherNotSupportedForUDP(cipher) }
    guard packet.count > cipher.saltLength else { throw ShadowsocksUDPError.packetTooShort }
    let salt = Array(packet.prefix(cipher.saltLength))
    let masterKey = evpBytesToKey(password: password, keyLength: cipher.keyLength)
    let subkey = shadowsocksDeriveSubkey(masterKey: masterKey, salt: salt, cipher: cipher)
    let zeroNonce = [UInt8](repeating: 0, count: cipher.nonceLength)
    let plaintext = try cipher.open(key: subkey, nonce: zeroNonce, sealed: Array(packet.dropFirst(cipher.saltLength)))

    guard !plaintext.isEmpty else { throw ShadowsocksUDPError.packetTooShort }
    var offset = 1
    let address: ProxyAddress
    switch plaintext[0] {
    case 0x01:
        guard plaintext.count >= offset + 4 else { throw ShadowsocksUDPError.packetTooShort }
        address = .ipv4(Array(plaintext[offset..<offset + 4]))
        offset += 4
    case 0x04:
        guard plaintext.count >= offset + 16 else { throw ShadowsocksUDPError.packetTooShort }
        address = .ipv6(Array(plaintext[offset..<offset + 16]))
        offset += 16
    case 0x03:
        guard plaintext.count > offset else { throw ShadowsocksUDPError.packetTooShort }
        let length = Int(plaintext[offset])
        offset += 1
        guard plaintext.count >= offset + length else { throw ShadowsocksUDPError.packetTooShort }
        guard let domain = String(bytes: plaintext[offset..<offset + length], encoding: .utf8) else { throw ShadowsocksUDPError.malformedAddress }
        address = .domain(domain)
        offset += length
    default:
        throw ShadowsocksUDPError.malformedAddress
    }

    guard plaintext.count >= offset + 2 else { throw ShadowsocksUDPError.packetTooShort }
    let port = UInt16(plaintext[offset]) << 8 | UInt16(plaintext[offset + 1])
    offset += 2
    return (address, port, Array(plaintext[offset...]))
}

// MARK: - Reusable Shadowsocks session
//
// Encapsulates one Shadowsocks-proxied connection: send the target address
// as the first encrypted chunk, then expose a plain send/receive byte pipe
// -- callers don't need to know anything about chunk framing, salts, or
// nonces to relay their own application data.
//
// `ShadowsocksSession` conforms to `ProxyTransport` itself, so it can serve
// as the transport for a *further* hop's handshake (e.g. VMess tunneled
// through this Shadowsocks proxy): `readExactly` buffers across decrypted
// chunks -- its natural unit -- the same way `TCPConn.readExactly` buffers
// partial TCP reads, just one layer up.

public enum Shadowsocks2022HeaderError: Error, Equatable {
    /// Response header's `type` wasn't `1` (`HeaderTypeServerStream`).
    case unexpectedHeaderType(UInt8)
    /// Response header's timestamp was more than 30 seconds from now --
    /// the spec's own replay-protection tolerance.
    case timestampOutOfRange
    /// Response header's echoed salt didn't match the salt this client sent
    /// in its own request -- either a misbehaving/wrong server, or the
    /// stream got corrupted/desynced somewhere upstream.
    case saltMismatch
}

public final class ShadowsocksSession: ByteStreamSource, ByteStreamSink, ByteStreamAvailableReader, ByteStreamCloser {
    private let conn: any ProxyTransport
    /// The 2017 edition's `evpBytesToKey`-derived master key, *or* the 2022
    /// edition's raw PSK -- same slot, different derivation upstream (see
    /// `open(over:)`), since both are just "the long-lived secret every
    /// per-connection subkey is derived from."
    private let masterKey: [UInt8]
    private let cipher: ShadowsocksCipher
    private let writer: ShadowsocksChunkCrypto
    /// This session's own request salt -- unused for 2017 (empty), but
    /// needed for 2022's response-header salt-echo validation.
    private let requestSalt: [UInt8]
    private var reader: ShadowsocksChunkCrypto?
    private var buffered: [UInt8] = []

    private init(conn: any ProxyTransport, masterKey: [UInt8], cipher: ShadowsocksCipher, writer: ShadowsocksChunkCrypto, requestSalt: [UInt8] = []) {
        self.conn = conn
        self.masterKey = masterKey
        self.cipher = cipher
        self.writer = writer
        self.requestSalt = requestSalt
    }

    /// Sends the target address *and port* as the first encrypted chunk
    /// (`ATYP + address + port`, per the AEAD spec's TCP request header) over
    /// an already-open `transport`. This is the primitive every other `open`
    /// overload reduces to -- `transport` is a fresh `TCPConn` when
    /// Shadowsocks is the first hop of a chain, or a previous hop's
    /// already-open `Session` when Shadowsocks is stacked on top of it.
    ///
    /// 2022-edition ciphers send a differently-shaped request instead (see
    /// this file's own top comment): `password` is parsed as a raw PSK, the
    /// subkey comes from BLAKE3 not HKDF-SHA1, and two header chunks
    /// (fixed-length type+timestamp+length, then the variable-length
    /// address+port+padding) replace the 2017 single address chunk -- but
    /// both editions still funnel into the same `ShadowsocksChunkCrypto`
    /// for the ordinary chunk stream that follows.
    public static func open(over transport: any ProxyTransport, password: String, cipher: ShadowsocksCipher, targetHost: ProxyAddress, targetPort: UInt16, timeout: TimeInterval? = 10) async throws -> ShadowsocksSession {
        if cipher.is2022Edition {
            let psk = try shadowsocks2022ParsePSK(password: password, cipher: cipher)
            let salt = (0..<cipher.saltLength).map { _ in UInt8.random(in: 0...255) }
            let subkey = shadowsocks2022DeriveSessionSubkey(psk: psk, salt: salt)
            let writer = ShadowsocksChunkCrypto(cipher: cipher, key: subkey)

            let addressPortBytes = try targetHost.socks5Encoded + targetPort.bigEndianBytes
            // The spec's own `MinPaddingLength = 0` reads as "padding is
            // optional", but a real server (confirmed live against
            // xray-core) rejects a request with *both* zero padding and no
            // piggybacked initial payload outright ("bad request: missing
            // payload or padding") -- the whole point of padding is to keep
            // a payload-less request from having a suspiciously fixed,
            // tiny size, so a real implementation enforces "at least one of
            // the two" rather than treating 0 as always fine. This client
            // never piggybacks an initial payload (see this function's own
            // doc comment), so it always sends real random padding instead.
            let paddingLength = UInt16.random(in: 16...256)
            let padding = (0..<paddingLength).map { _ in UInt8.random(in: 0...255) }
            let header2Plaintext = addressPortBytes + paddingLength.bigEndianBytes + padding
            let header2Length = UInt16(header2Plaintext.count) // still always well under 0xFFFF.
            let timestamp = UInt64(Date().timeIntervalSince1970)
            let header1Plaintext: [UInt8] = [0] + timestamp.bigEndianBytes + header2Length.bigEndianBytes // type=0: HeaderTypeClientStream

            let sealedHeader1 = writer.sealRaw(header1Plaintext)
            let sealedHeader2 = writer.sealRaw(header2Plaintext)
            try await transport.send(salt + sealedHeader1 + sealedHeader2, timeout: timeout)

            return ShadowsocksSession(conn: transport, masterKey: psk, cipher: cipher, writer: writer, requestSalt: salt)
        }

        let masterKey = evpBytesToKey(password: password, keyLength: cipher.keyLength)
        let salt = (0..<cipher.saltLength).map { _ in UInt8.random(in: 0...255) }
        let subkey = shadowsocksDeriveSubkey(masterKey: masterKey, salt: salt, cipher: cipher)
        let writer = ShadowsocksChunkCrypto(cipher: cipher, key: subkey)

        let requestHeader = try targetHost.socks5Encoded + targetPort.bigEndianBytes
        let sealedAddressChunk = writer.sealChunk(requestHeader)
        try await transport.send(salt + sealedAddressChunk, timeout: timeout)

        return ShadowsocksSession(conn: transport, masterKey: masterKey, cipher: cipher, writer: writer)
    }

    /// Dials `server` directly over TCP, then sends the address chunk.
    /// `connectTimeout` guards against a firewalled/unreachable host that
    /// never completes the TCP handshake.
    public static func open(server: ShadowsocksServerConfig, targetHost: ProxyAddress, targetPort: UInt16, connectTimeout: TimeInterval? = 10) async throws -> ShadowsocksSession {
        let conn = TCPConn(host: server.host, port: server.port)
        try await conn.connect(timeout: connectTimeout)
        do {
            return try await open(over: conn, password: server.password, cipher: server.cipher, targetHost: targetHost, targetPort: targetPort, timeout: connectTimeout)
        } catch {
            // `conn` already connected above -- without this, a failure in
            // `open(over:)`'s own handshake would leak that socket, since
            // nothing else still references `conn` once this rethrows.
            conn.close()
            throw error
        }
    }

    /// Sends raw application bytes toward `target`, split into cipher-sized chunks as needed.
    public func send(_ bytes: [UInt8], timeout: TimeInterval? = nil) async throws {
        var offset = 0
        let maxChunkSize = cipher.maxChunkSize
        while offset < bytes.count {
            let end = min(offset + maxChunkSize, bytes.count)
            try await conn.send(writer.sealChunk(Array(bytes[offset..<end])), timeout: timeout)
            offset = end
        }
    }

    /// Reads and decrypts the next chunk of raw application bytes coming back
    /// from `target` ([] once the stream ends).
    public func receive(timeout: TimeInterval? = nil) async throws -> [UInt8] {
        try await readAvailable(timeout: timeout)
    }

    public func readAvailable(timeout: TimeInterval? = nil) async throws -> [UInt8] {
        if !buffered.isEmpty {
            let result = buffered
            buffered = []
            return result
        }
        return try await nextDecryptedChunk(timeout: timeout)
    }

    /// Exact-length read for a protocol stacked *on top of* this Shadowsocks
    /// hop: buffers across as many decrypted chunks as needed.
    public func readExactly(_ n: Int, timeout: TimeInterval? = nil) async throws -> [UInt8] {
        while buffered.count < n {
            let chunk = try await nextDecryptedChunk(timeout: timeout)
            if chunk.isEmpty { throw ProxyError.connectionClosed }
            buffered += chunk
        }
        let result = Array(buffered.prefix(n))
        buffered.removeFirst(n)
        return result
    }

    /// Lazily reads the server's own salt (and derives its subkey) on the
    /// very first call -- Shadowsocks has no separate response-header step
    /// the way VMess does for 2017 edition; a chunk that decrypts
    /// successfully *is* the proof the handshake worked. 2022 edition *does*
    /// have a real response header (see this file's own top comment) --
    /// read and validate it here on first call instead, then fall through
    /// to the ordinary chunk stream exactly like 2017 does.
    private func nextDecryptedChunk(timeout: TimeInterval?) async throws -> [UInt8] {
        if reader == nil {
            let salt = try await conn.readExactly(cipher.saltLength, timeout: timeout ?? 10)
            if cipher.is2022Edition {
                return try await open2022ResponseHeaderAndFirstPayload(salt: salt, timeout: timeout)
            }
            reader = ShadowsocksChunkCrypto(cipher: cipher, key: shadowsocksDeriveSubkey(masterKey: masterKey, salt: salt, cipher: cipher))
        }
        do {
            return try await reader!.openChunk(from: conn, timeout: timeout)
        } catch ProxyError.connectionClosed {
            return [] // clean end of stream, wherever it happened to land in the chunk framing
        }
    }

    /// 2022 edition's response starts with one fixed-length header chunk
    /// (`type + timestamp + echoed request salt + length`) that doubles as
    /// the *first* length-chunk -- validates it (server-stream type, replay
    /// timestamp tolerance, salt echo), sets `reader` for every later
    /// ordinary chunk, then reads+opens the one payload chunk this header
    /// already announced the length of.
    private func open2022ResponseHeaderAndFirstPayload(salt: [UInt8], timeout: TimeInterval?) async throws -> [UInt8] {
        let subkey = shadowsocks2022DeriveSessionSubkey(psk: masterKey, salt: salt)
        let newReader = ShadowsocksChunkCrypto(cipher: cipher, key: subkey)

        let headerPlainLength = 1 + 8 + cipher.saltLength + 2
        let sealedHeader = try await conn.readExactly(headerPlainLength + cipher.tagLength, timeout: timeout ?? 10)
        let headerPlain = try newReader.openRaw(sealedHeader)

        let type = headerPlain[0]
        guard type == 1 else { throw Shadowsocks2022HeaderError.unexpectedHeaderType(type) }

        let timestamp = headerPlain[1..<9].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let now = UInt64(Date().timeIntervalSince1970)
        let drift = now > timestamp ? now - timestamp : timestamp - now
        guard drift <= 30 else { throw Shadowsocks2022HeaderError.timestampOutOfRange }

        let echoedSalt = Array(headerPlain[9..<(9 + cipher.saltLength)])
        guard echoedSalt == requestSalt else { throw Shadowsocks2022HeaderError.saltMismatch }

        let lengthOffset = 9 + cipher.saltLength
        let firstPayloadLength = Int(headerPlain[lengthOffset]) << 8 | Int(headerPlain[lengthOffset + 1])

        reader = newReader
        let sealedPayload = try await conn.readExactly(firstPayloadLength + cipher.tagLength, timeout: timeout)
        return try newReader.openRaw(sealedPayload)
    }

    public func close() { conn.close() }
}
