import XCTest
import ProxyKit
@testable import ShadowsocksCore

final class ShadowsocksCoreTests: XCTestCase {

    // MARK: - Key derivation, against independently-computed vectors
    // (Python's hashlib.md5, chained exactly as OpenSSL's EVP_BytesToKey does)

    func testEVPBytesToKeyIndependentVectors() {
        let password = "test-password"
        XCTAssertEqual(evpBytesToKey(password: password, keyLength: 16).map { String(format: "%02x", $0) }.joined(),
                        "dfb450efddbb5387197c84460623675b")
        XCTAssertEqual(evpBytesToKey(password: password, keyLength: 32).map { String(format: "%02x", $0) }.joined(),
                        "dfb450efddbb5387197c84460623675b69f2cebcd8ef520a3dfddef7c3d540b2")
    }

    /// Full pipeline, end-to-end, against an independently computed vector
    /// (Python: hashlib.md5 chain -> cryptography's HKDF-SHA1 -> AESGCM),
    /// not just each stage in isolation -- this is what would break if any
    /// of master-key derivation, subkey derivation, or the nonce sequence
    /// disagreed with a real implementation even slightly.
    func testShadowsocksSubkeyAndFirstChunkEndToEndVector() throws {
        let password = "correct-horse-battery-staple"
        let masterKey = evpBytesToKey(password: password, keyLength: 32)
        XCTAssertEqual(masterKey.map { String(format: "%02x", $0) }.joined(),
                        "d4bda60d8d790aa9cde7a92177bd0bc64320fc7bd32eed670f0854befd99ff79")

        let salt = (0..<32).map { UInt8($0) } // deterministic salt: 0x00, 0x01, ... 0x1f
        let subkey = shadowsocksDeriveSubkey(masterKey: masterKey, salt: salt, cipher: .aes256Gcm)
        XCTAssertEqual(subkey.map { String(format: "%02x", $0) }.joined(),
                        "19291cc53bda4768cbc261256cfb2d0f5e0260ad7ff788fc7b3c45dd8bb45dd0")

        // Nonce starts all-zero; the length chunk is sealed with nonce=0,
        // then the nonce increments (little-endian, byte 0 -> 1) before the
        // payload chunk is sealed.
        let plaintext = Array("hello shadowsocks".utf8)
        let sealedLength = aesGCMSeal(key: subkey, nonce: [UInt8](repeating: 0, count: 12),
                                       plaintext: UInt16(plaintext.count).bigEndianBytes, aad: [])
        let sealedPayload = aesGCMSeal(key: subkey, nonce: [1] + [UInt8](repeating: 0, count: 11),
                                        plaintext: plaintext, aad: [])
        let fullChunk = sealedLength + sealedPayload
        XCTAssertEqual(fullChunk.map { String(format: "%02x", $0) }.joined(),
                        "c9a1e72327b40b0c32b81415203ebd5d26d42955c5cca04a3cf3fef9cbf54a0c45fb637c3347567bb2068f387aff63f9253db4")

        // And our own ShadowsocksChunkCrypto, used exactly as ShadowsocksSession does, must produce the same bytes.
        let writer = ShadowsocksChunkCrypto(cipher: .aes256Gcm, key: subkey)
        XCTAssertEqual(writer.sealChunk(plaintext), fullChunk)
    }

    // MARK: - Chunk framing: round trip, chunking, and nonce-carry regression

    private final class FakeByteSource: ByteStreamSource {
        private var buffer: [UInt8]
        init(_ buffer: [UInt8]) { self.buffer = buffer }
        func readExactly(_ n: Int, timeout: TimeInterval?) async throws -> [UInt8] {
            guard buffer.count >= n else { throw ProxyError.connectionClosed }
            let result = Array(buffer.prefix(n))
            buffer.removeFirst(n)
            return result
        }
    }

    func testChunkCryptoRoundTrip() async throws {
        let key = (0..<32).map { UInt8($0) }
        let writer = ShadowsocksChunkCrypto(cipher: .aes256Gcm, key: key)
        let reader = ShadowsocksChunkCrypto(cipher: .aes256Gcm, key: key)

        let sealed = writer.sealChunk(Array("first chunk".utf8))
        let opened = try await reader.openChunk(from: FakeByteSource(sealed), timeout: nil)
        XCTAssertEqual(opened, Array("first chunk".utf8))
    }

    func testChunkCryptoRoundTripAcrossNonceByteCarry() async throws {
        // The nonce's low byte wraps 0xFF -> 0x00 (carrying into the next
        // byte) right after the 256th AEAD operation. Each chunk performs
        // two operations (length, then payload), so run enough chunks to
        // cross that boundary on both, and confirm decryption still lines
        // up -- this is exactly what would silently desync if the carry
        // logic (or its direction) were wrong.
        let key = (0..<32).map { UInt8($0) }
        let writer = ShadowsocksChunkCrypto(cipher: .aes128Gcm, key: Array(key.prefix(16)))
        let reader = ShadowsocksChunkCrypto(cipher: .aes128Gcm, key: Array(key.prefix(16)))

        var wire: [UInt8] = []
        var expectedChunks: [[UInt8]] = []
        for i in 0..<257 {
            let plaintext = Array("chunk-\(i)".utf8)
            wire += writer.sealChunk(plaintext)
            expectedChunks.append(plaintext)
        }

        let source = FakeByteSource(wire)
        for expected in expectedChunks {
            let opened = try await reader.openChunk(from: source, timeout: nil)
            XCTAssertEqual(opened, expected)
        }
    }

    // MARK: - 2022 edition: PSK parsing + session subkey derivation
    //
    // BLAKE3 itself is verified bit-perfect against the official test
    // vectors in `BLAKE3Tests` (ProxyKitTests) -- these just check the thin
    // wrapper around it (PSK decode/length validation, and that
    // `shadowsocks2022DeriveSessionSubkey` is a real function of both its
    // inputs, not e.g. accidentally ignoring the salt). The real end-to-end
    // wire-format cross-check against an actual server lives in
    // `Tests/InteropTests` (real xray-core), same as every other protocol here.

    func testParsePSKAcceptsStandardBase64OfExactLength() throws {
        let raw = (0..<32).map { UInt8($0) }
        let password = Data(raw).base64EncodedString()
        let psk = try shadowsocks2022ParsePSK(password: password, cipher: .aead2022Blake3Aes256Gcm)
        XCTAssertEqual(psk, raw)
    }

    func testParsePSKAcceptsURLSafeUnpaddedBase64() throws {
        let raw = (0..<16).map { UInt8($0 + 1) }
        var password = Data(raw).base64EncodedString()
        password = password.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        while password.hasSuffix("=") { password.removeLast() }
        let psk = try shadowsocks2022ParsePSK(password: password, cipher: .aead2022Blake3Aes128Gcm)
        XCTAssertEqual(psk, raw)
    }

    func testParsePSKRejectsInvalidBase64() {
        XCTAssertThrowsError(try shadowsocks2022ParsePSK(password: "not base64 at all!!", cipher: .aead2022Blake3Aes128Gcm)) { error in
            XCTAssertEqual(error as? ShadowsocksPSKError, .invalidBase64)
        }
    }

    func testParsePSKRejectsWrongLength() {
        let tooShort = Data((0..<8).map { UInt8($0) }).base64EncodedString()
        XCTAssertThrowsError(try shadowsocks2022ParsePSK(password: tooShort, cipher: .aead2022Blake3Aes256Gcm)) { error in
            XCTAssertEqual(error as? ShadowsocksPSKError, .wrongLength(expected: 32, got: 8))
        }
    }

    func testSessionSubkeyIsDeterministicAndDependsOnBothInputs() {
        let psk = (0..<32).map { UInt8($0) }
        let saltA = (0..<32).map { UInt8($0 + 100) }
        let saltB = (0..<32).map { UInt8($0 + 200) }

        let subkeyA1 = shadowsocks2022DeriveSessionSubkey(psk: psk, salt: saltA)
        let subkeyA2 = shadowsocks2022DeriveSessionSubkey(psk: psk, salt: saltA)
        let subkeyB = shadowsocks2022DeriveSessionSubkey(psk: psk, salt: saltB)

        XCTAssertEqual(subkeyA1.count, psk.count)
        XCTAssertEqual(subkeyA1, subkeyA2, "same psk+salt must derive the same subkey every time")
        XCTAssertNotEqual(subkeyA1, subkeyB, "a different salt must derive a different subkey")
    }
}
