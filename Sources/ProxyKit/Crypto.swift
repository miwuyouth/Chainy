// Crypto.swift
//
// Generic cryptographic/checksum primitives shared across proxy protocols.
// Nothing here is VMess-specific: MD5/SHA256/HMAC and AES-GCM are exactly
// what Shadowsocks' AEAD ciphers need too, CRC32/FNV1a are generic
// checksums, and AES-128 raw-block encryption fills the one gap CryptoKit
// deliberately leaves open (no raw ECB, since it's insecure for general use).
//
// Each primitive is cross-checked against a published, independent test
// vector in ProxyKitTests -- not just internal self-consistency.

import Foundation
import CryptoKit
import CommonCrypto

public func md5(_ data: [UInt8]) -> [UInt8] { Array(Insecure.MD5.hash(data: Data(data))) }
public func sha256(_ data: [UInt8]) -> [UInt8] { Array(SHA256.hash(data: Data(data))) }
/// SHA-1 -- cryptographically broken for signatures, but still exactly what
/// RFC 6455's WebSocket handshake specifies for `Sec-WebSocket-Accept`
/// (`base64(SHA1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`), which is a
/// protocol-conformance requirement, not a security boundary -- see
/// `WSConn.swift`. `Insecure.SHA1` is CryptoKit's own name for this, the same
/// "clearly labeled insecure, but a real spec sometimes still requires it"
/// rationale as `Insecure.MD5` above.
public func sha1(_ data: [UInt8]) -> [UInt8] { Array(Insecure.SHA1.hash(data: Data(data))) }

/// SHA-224 (truncated SHA-256, RFC 3874) -- not exposed by CryptoKit at all
/// (its `SHA256`/`SHA384`/`SHA512` types have no `SHA224` sibling), so this
/// reaches for CommonCrypto instead, the same way `AES128` above reaches for
/// a hand-rolled implementation to fill a CryptoKit gap. Needed only for
/// Trojan's `hex(SHA224(password))` connection header. Cross-checked against
/// NIST's own SHA-224 test vector in ProxyKitTests.
public func sha224(_ data: [UInt8]) -> [UInt8] {
    var digest = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
    CC_SHA224(data, CC_LONG(data.count), &digest)
    return digest
}

/// Generic (pluggable-hash) HMAC. Used directly by protocols with a plain
/// single-level HMAC need, and as the building block for VMess's nested KDF
/// (which repeatedly re-wraps this with itself as the "hash function").
/// Every level uses SHA256-sized parameters (block size 64, output size 32),
/// matching Go's crypto/hmac behavior when it is fed another HMAC
/// construction as its "hash function".
public func genericHMAC(key: [UInt8], message: [UInt8], hash: ([UInt8]) -> [UInt8]) -> [UInt8] {
    let blockSize = 64
    var k = key
    if k.count > blockSize { k = hash(k) }
    if k.count < blockSize { k.append(contentsOf: [UInt8](repeating: 0, count: blockSize - k.count)) }
    let ipad = k.map { $0 ^ 0x36 }
    let opad = k.map { $0 ^ 0x5c }
    let inner = hash(ipad + message)
    return hash(opad + inner)
}

// CRC32 (IEEE).
public let crc32Table: [UInt32] = {
    (0..<256).map { i -> UInt32 in
        var c = UInt32(i)
        for _ in 0..<8 { c = (c & 1 != 0) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1) }
        return c
    }
}()
public func crc32(_ data: [UInt8]) -> UInt32 {
    var c: UInt32 = 0xFFFFFFFF
    for b in data { c = crc32Table[Int((c ^ UInt32(b)) & 0xff)] ^ (c >> 8) }
    return c ^ 0xFFFFFFFF
}

// FNV-1a 32-bit.
public func fnv1a32(_ data: [UInt8]) -> UInt32 {
    var h: UInt32 = 2166136261
    for b in data {
        h ^= UInt32(b)
        h = h &* 16777619
    }
    return h
}

// MARK: - Minimal pure-Swift AES-128 (encrypt-only, single block, ECB)
//
// CryptoKit deliberately doesn't expose raw ECB (it's insecure for general
// use beyond a single, already-unique-per-use block), so this textbook
// FIPS-197 forward cipher fills that one gap. Cross-checked against the
// official FIPS-197 Appendix B vector and NIST SP 800-38A vectors in
// ProxyKitTests.

public enum AES128 {
    public static let sbox: [UInt8] = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    ]
    public static let rcon: [UInt8] = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

    public static func xtime(_ a: UInt8) -> UInt8 {
        let shifted = a << 1
        return (a & 0x80 != 0) ? (shifted ^ 0x1B) : shifted
    }

    public static func keyExpansion(_ key: [UInt8]) -> [[UInt8]] {
        var w = [[UInt8]](repeating: [0, 0, 0, 0], count: 44)
        for i in 0..<4 { w[i] = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]] }
        for i in 4..<44 {
            var temp = w[i-1]
            if i % 4 == 0 {
                temp = [temp[1], temp[2], temp[3], temp[0]].map { sbox[Int($0)] }
                temp[0] ^= rcon[i/4 - 1]
            }
            w[i] = (0..<4).map { w[i-4][$0] ^ temp[$0] }
        }
        return w
    }

    /// Encrypts exactly one 16-byte block with AES-128 (ECB, no padding).
    public static func encryptBlock(_ block: [UInt8], key: [UInt8]) -> [UInt8] {
        precondition(block.count == 16 && key.count == 16)
        let w = keyExpansion(key)
        var state = block // state[r + 4c] column-major, per FIPS-197

        func addRoundKey(_ round: Int) {
            for c in 0..<4 {
                for r in 0..<4 { state[r + 4*c] ^= w[round*4 + c][r] }
            }
        }
        func subBytes() { for i in 0..<16 { state[i] = sbox[Int(state[i])] } }
        func shiftRows() {
            var s = state
            for r in 1..<4 {
                for c in 0..<4 { s[r + 4*c] = state[r + 4*((c + r) % 4)] }
            }
            state = s
        }
        func mixColumns() {
            var s = state
            for c in 0..<4 {
                let a0 = state[0+4*c], a1 = state[1+4*c], a2 = state[2+4*c], a3 = state[3+4*c]
                s[0+4*c] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3
                s[1+4*c] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3
                s[2+4*c] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)
                s[3+4*c] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3)
            }
            state = s
        }

        addRoundKey(0)
        for round in 1..<10 {
            subBytes(); shiftRows(); mixColumns(); addRoundKey(round)
        }
        subBytes(); shiftRows(); addRoundKey(10)
        return state
    }
}

// MARK: - AES-128-GCM wrapper (CryptoKit)
//
// Used by VMess's AEAD header framing today; Shadowsocks' AEAD ciphers
// (AES-256-GCM in particular) will want the same seal/open shape later.

public func aesGCMSeal(key: [UInt8], nonce: [UInt8], plaintext: [UInt8], aad: [UInt8]) -> [UInt8] {
    let sealed = try! AES.GCM.seal(
        plaintext,
        using: SymmetricKey(data: key),
        nonce: try! AES.GCM.Nonce(data: nonce),
        authenticating: aad
    )
    return Array(sealed.ciphertext) + Array(sealed.tag) // no nonce prefix on the wire
}

/// A sealed AEAD blob shorter than its own 16-byte authentication tag --
/// can't be a genuine sealed box no matter the key, so `aesGCMOpen`/
/// `chachaPolyOpen` reject it outright rather than let `sealed.count - 16`
/// go negative into `Array.prefix`, which traps (a Swift fatal error, not a
/// catchable one) instead of throwing. Reachable with attacker-controlled
/// input before any authentication happens -- e.g. a VMess body chunk's
/// on-the-wire length prefix is read straight off the socket and handed to
/// `aesGCMOpen` with only a `> 0` floor, so a malicious/compromised server
/// (or an on-path attacker able to inject bytes into that stream) sending a
/// 1-15 byte chunk used to crash the whole process.
public enum CryptoError: Error, Equatable {
    case ciphertextTooShort
}

public func aesGCMOpen(key: [UInt8], nonce: [UInt8], sealed: [UInt8], aad: [UInt8]) throws -> [UInt8] {
    guard sealed.count >= 16 else { throw CryptoError.ciphertextTooShort }
    let tag = Array(sealed.suffix(16))
    let ciphertext = Array(sealed.prefix(sealed.count - 16))
    let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: nonce), ciphertext: ciphertext, tag: tag)
    return Array(try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad))
}

// MARK: - ChaCha20-Poly1305 (IETF, RFC 8439) wrapper (CryptoKit)
//
// Same seal/open shape as the AES-GCM pair above. Shadowsocks'
// chacha20-ietf-poly1305 cipher is exactly RFC 8439 ChaCha20-Poly1305 with a
// 12-byte nonce, which is precisely what CryptoKit's `ChaChaPoly` implements.

public func chachaPolySeal(key: [UInt8], nonce: [UInt8], plaintext: [UInt8], aad: [UInt8]) -> [UInt8] {
    let sealed = try! ChaChaPoly.seal(
        plaintext,
        using: SymmetricKey(data: key),
        nonce: try! ChaChaPoly.Nonce(data: nonce),
        authenticating: aad
    )
    return Array(sealed.ciphertext) + Array(sealed.tag)
}

public func chachaPolyOpen(key: [UInt8], nonce: [UInt8], sealed: [UInt8], aad: [UInt8]) throws -> [UInt8] {
    guard sealed.count >= 16 else { throw CryptoError.ciphertextTooShort }
    let tag = Array(sealed.suffix(16))
    let ciphertext = Array(sealed.prefix(sealed.count - 16))
    let box = try ChaChaPoly.SealedBox(nonce: try ChaChaPoly.Nonce(data: nonce), ciphertext: ciphertext, tag: tag)
    return Array(try ChaChaPoly.open(box, using: SymmetricKey(data: key), authenticating: aad))
}

// MARK: - HKDF-SHA1
//
// Shadowsocks' AEAD per-session subkey derivation is specifically
// HKDF-SHA1(IKM: master key, salt: per-connection salt, info: "ss-subkey"),
// mandated by the spec regardless of SHA-1's weaknesses in other contexts
// (this is HKDF's extract-and-expand construction, not relying on SHA-1
// collision resistance). Cross-checked against RFC 5869's own SHA-1 test
// vector in ProxyKitTests.

public func hkdfSHA1(ikm: [UInt8], salt: [UInt8], info: [UInt8], outputByteCount: Int) -> [UInt8] {
    let key = HKDF<Insecure.SHA1>.deriveKey(
        inputKeyMaterial: SymmetricKey(data: ikm),
        salt: Data(salt),
        info: Data(info),
        outputByteCount: outputByteCount
    )
    return key.withUnsafeBytes { Array($0) }
}
