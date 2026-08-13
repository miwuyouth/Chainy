import XCTest
@testable import ProxyKit

final class ProxyKitTests: XCTestCase {

    // MARK: - Hash / checksum primitives, against well-known published vectors

    func testMD5KnownVector() {
        // RFC 1321 test vector.
        XCTAssertEqual(md5(Array("abc".utf8)).map { String(format: "%02x", $0) }.joined(),
                        "900150983cd24fb0d6963f7d28e17f72")
    }

    func testSHA224KnownVectors() {
        // NIST FIPS 180-4 test vectors (empty string, and "abc").
        XCTAssertEqual(sha224([]).map { String(format: "%02x", $0) }.joined(),
                        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")
        XCTAssertEqual(sha224(Array("abc".utf8)).map { String(format: "%02x", $0) }.joined(),
                        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")
    }

    func testCRC32KnownVector() {
        // The canonical CRC-32/ISO-HDLC ("check value") test vector.
        XCTAssertEqual(crc32(Array("123456789".utf8)), 0xCBF43926)
    }

    func testFNV1a32KnownVectors() {
        // Reference vectors from the FNV test suite (Landon Curt Noll).
        XCTAssertEqual(fnv1a32([]), 0x811c9dc5)
        XCTAssertEqual(fnv1a32(Array("a".utf8)), 0xe40c292c)
        XCTAssertEqual(fnv1a32(Array("123456789".utf8)), 0xbb86b11c)
    }

    func testAES128FIPS197Vector() {
        // FIPS-197 Appendix B: the official AES-128 forward-cipher test vector.
        let key: [UInt8] = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]
        let plaintext: [UInt8] = [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff]
        let expected: [UInt8] = [0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a]
        XCTAssertEqual(AES128.encryptBlock(plaintext, key: key), expected)
    }

    func testAES128NISTSP80038AMultiBlockVectors() {
        // NIST SP 800-38A Appendix F.1.1, AES-128-ECB Encrypt: four
        // independent plaintext/ciphertext pairs under one key, cross-checked
        // independently via Python's `cryptography` package before adding.
        let key: [UInt8] = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]
        let vectors: [(pt: [UInt8], ct: [UInt8])] = [
            ([0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a],
             [0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97]),
            ([0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51],
             [0xf5,0xd3,0xd5,0x85,0x03,0xb9,0x69,0x9d,0xe7,0x85,0x89,0x5a,0x96,0xfd,0xba,0xaf]),
            ([0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef],
             [0x43,0xb1,0xcd,0x7f,0x59,0x8e,0xce,0x23,0x88,0x1b,0x00,0xe3,0xed,0x03,0x06,0x88]),
            ([0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10],
             [0x7b,0x0c,0x78,0x5e,0x27,0xe8,0xad,0x3f,0x82,0x23,0x20,0x71,0x04,0x72,0x5d,0xd4]),
        ]
        for (i, v) in vectors.enumerated() {
            XCTAssertEqual(AES128.encryptBlock(v.pt, key: key), v.ct, "block \(i)")
        }
    }

    // MARK: - AES-128-GCM wrapper

    func testAESGCMSealOpenRoundTrip() throws {
        let key = (0..<16).map { UInt8($0) }
        let nonce = (0..<12).map { UInt8($0 * 2) }
        let aad = Array("some-aad".utf8)
        let plaintext = Array("hello vmess".utf8)

        let sealed = aesGCMSeal(key: key, nonce: nonce, plaintext: plaintext, aad: aad)
        // ciphertext + 16-byte GCM tag, no nonce prefixed onto the wire.
        XCTAssertEqual(sealed.count, plaintext.count + 16)

        let opened = try aesGCMOpen(key: key, nonce: nonce, sealed: sealed, aad: aad)
        XCTAssertEqual(opened, plaintext)
    }

    func testAESGCMOpenRejectsTamperedCiphertext() {
        let key = (0..<16).map { UInt8($0) }
        let nonce = (0..<12).map { UInt8($0 * 2) }
        var sealed = aesGCMSeal(key: key, nonce: nonce, plaintext: Array("hello".utf8), aad: [])
        sealed[0] ^= 0xff
        XCTAssertThrowsError(try aesGCMOpen(key: key, nonce: nonce, sealed: sealed, aad: []))
    }

    func testChaChaPolySealOpenRoundTrip() throws {
        let key = (0..<32).map { UInt8($0) }
        let nonce = (0..<12).map { UInt8($0 * 2) }
        let aad = Array("some-aad".utf8)
        let plaintext = Array("hello shadowsocks".utf8)

        let sealed = chachaPolySeal(key: key, nonce: nonce, plaintext: plaintext, aad: aad)
        XCTAssertEqual(sealed.count, plaintext.count + 16)

        let opened = try chachaPolyOpen(key: key, nonce: nonce, sealed: sealed, aad: aad)
        XCTAssertEqual(opened, plaintext)
    }

    func testChaChaPolyOpenRejectsTamperedCiphertext() {
        let key = (0..<32).map { UInt8($0) }
        let nonce = (0..<12).map { UInt8($0 * 2) }
        var sealed = chachaPolySeal(key: key, nonce: nonce, plaintext: Array("hello".utf8), aad: [])
        sealed[0] ^= 0xff
        XCTAssertThrowsError(try chachaPolyOpen(key: key, nonce: nonce, sealed: sealed, aad: []))
    }

    /// A sealed blob shorter than its own 16-byte tag used to crash the
    /// process (`Array.prefix` traps on the resulting negative length)
    /// instead of throwing -- reachable with attacker-controlled input
    /// before any authentication happens, e.g. a VMess body chunk's
    /// on-the-wire length prefix handed straight to `aesGCMOpen`.
    func testAESGCMOpenThrowsInsteadOfCrashingOnUndersizedInput() {
        let key = (0..<16).map { UInt8($0) }
        let nonce = (0..<12).map { UInt8($0 * 2) }
        for length in 0..<16 {
            let sealed = (0..<length).map { UInt8($0) }
            XCTAssertThrowsError(try aesGCMOpen(key: key, nonce: nonce, sealed: sealed, aad: []))
        }
    }

    func testChaChaPolyOpenThrowsInsteadOfCrashingOnUndersizedInput() {
        let key = (0..<32).map { UInt8($0) }
        let nonce = (0..<12).map { UInt8($0 * 2) }
        for length in 0..<16 {
            let sealed = (0..<length).map { UInt8($0) }
            XCTAssertThrowsError(try chachaPolyOpen(key: key, nonce: nonce, sealed: sealed, aad: []))
        }
    }

    // MARK: - HKDF-SHA1

    func testHKDFSHA1AgainstRFC5869TestCase4() {
        // RFC 5869 Appendix A.4: "Basic test case with SHA-1". Independently
        // re-derived via Python's `cryptography` package before adding, since
        // this is exactly the KDF Shadowsocks uses for its per-connection subkey.
        let ikm = [UInt8](repeating: 0x0b, count: 11)
        let salt: [UInt8] = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c]
        let info: [UInt8] = [0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9]
        let expected = "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896"
        let got = hkdfSHA1(ikm: ikm, salt: salt, info: info, outputByteCount: 42).map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(got, expected)
    }

    // MARK: - ProxyAddress's SOCKS5-style wire encoding (RFC 1928: 1=IPv4, 3=domain, 4=IPv6),
    // shared verbatim by Shadowsocks and (eventually) a SOCKS5 client.

    func testSocks5EncodedAddressWireFormat() throws {
        XCTAssertEqual(try ProxyAddress.parse("127.0.0.1").socks5Encoded, [0x01, 127, 0, 0, 1])

        let ipv6Encoded = try ProxyAddress.parse("::1").socks5Encoded
        XCTAssertEqual(ipv6Encoded.first, 0x04)
        XCTAssertEqual(ipv6Encoded.count, 17)

        let domainEncoded = try ProxyAddress.parse("example.com").socks5Encoded
        XCTAssertEqual(domainEncoded[0], 0x03)
        XCTAssertEqual(domainEncoded[1], UInt8("example.com".utf8.count))
        XCTAssertEqual(Array(domainEncoded[2...]), Array("example.com".utf8))
    }

    // MARK: - "host:port" parsing

    func testParseHostPort() {
        XCTAssertTrue(parseHostPort("example.com:8080", defaultPort: 1) == ("example.com", 8080))
        XCTAssertTrue(parseHostPort("example.com", defaultPort: 80) == ("example.com", 80))
        XCTAssertTrue(parseHostPort("[::1]:8080", defaultPort: 1) == ("::1", 8080))
        XCTAssertTrue(parseHostPort("[::1]", defaultPort: 443) == ("::1", 443))
        XCTAssertTrue(parseHostPort("127.0.0.1:26182", defaultPort: 1) == ("127.0.0.1", 26182))
    }

    func testParseHostPortEdgeCases() {
        // Empty string: no colon, whole thing is "the host", default port used.
        XCTAssertTrue(parseHostPort("", defaultPort: 80) == ("", 80))
        // Port 0 is syntactically valid UInt16 and shouldn't be treated as "absent".
        XCTAssertTrue(parseHostPort("example.com:0", defaultPort: 80) == ("example.com", 0))
        // A non-numeric "port" fails UInt16 parsing, so this is documented,
        // intentional fallback behavior: the whole string becomes the host
        // (which will then simply fail to resolve/connect, rather than
        // silently guessing a different split).
        XCTAssertTrue(parseHostPort("example.com:notaport", defaultPort: 80) == ("example.com:notaport", 80))
        // Out-of-range port (> 65535) also fails UInt16 parsing -> same fallback.
        XCTAssertTrue(parseHostPort("example.com:99999", defaultPort: 80) == ("example.com:99999", 80))
        // A bracket-less IPv6 literal has more than one colon -- splitting on
        // the *last* one regardless (as this used to) would misparse the
        // final hextet as a port whenever it happens to parse as one,
        // silently truncating the address. No brackets means no port to
        // extract at all, so the whole literal falls back to being "the
        // host" instead, same as the non-numeric-port case above.
        XCTAssertTrue(parseHostPort("::1", defaultPort: 443) == ("::1", 443))
        XCTAssertTrue(parseHostPort("2001:db8::1", defaultPort: 443) == ("2001:db8::1", 443))
        XCTAssertTrue(parseHostPort("fe80::5", defaultPort: 443) == ("fe80::5", 443))
    }

    // MARK: - ProxyAddress: the parsing (IPv4/IPv6 literal vs domain) shared
    // by every protocol. Wire *encoding* (which type-tag bytes each protocol
    // uses) is protocol-specific and tested in that protocol's own test target
    // (see VMessCoreTests' `.vmessEncoded` tests).

    func testProxyAddressParsesIPv4AndIPv6Literals() {
        guard case .ipv4(let b) = ProxyAddress.parse("127.0.0.1") else {
            return XCTFail("expected ipv4")
        }
        XCTAssertEqual(b, [127, 0, 0, 1])

        guard case .ipv6(let b6) = ProxyAddress.parse("::1") else {
            return XCTFail("expected ipv6")
        }
        XCTAssertEqual(b6, [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1])

        guard case .domain(let d) = ProxyAddress.parse("example.com") else {
            return XCTFail("expected domain")
        }
        XCTAssertEqual(d, "example.com")
    }

    func testProxyAddressRejectsMalformedLiteralsAsDomainsNotCrashes() {
        // None of these are valid IPv4/IPv6 literals; inet_pton must reject
        // them cleanly and we fall back to treating them as a domain name
        // (which will simply fail DNS resolution later, rather than being
        // misparsed as some other address family).
        for host in ["999.999.999.999", "1.2.3", "1.2.3.4.5", "not:a:valid:ipv6:at:all:::", "", "  "] {
            guard case .domain(let d) = ProxyAddress.parse(host) else {
                return XCTFail("expected '\(host)' to fall back to .domain")
            }
            XCTAssertEqual(d, host)
        }
    }

    // MARK: - Length-prefixed domain encoding, shared by VMess and (later) SOCKS5

    func testLengthPrefixedDomainAt255BytesEncodesOK() throws {
        let host = String(repeating: "a", count: 255)
        let encoded = try ProxyAddress.lengthPrefixedDomain(host)
        XCTAssertEqual(encoded[0], 255)
        XCTAssertEqual(Array(encoded[1...]), Array(host.utf8))
    }

    func testLengthPrefixedDomainOver255BytesThrowsInsteadOfCrashing() {
        // This used to be `UInt8(bytes.count)` at each call site, which traps
        // (crashes the whole process) once count > 255 instead of raising a
        // catchable error.
        let host = String(repeating: "a", count: 256)
        XCTAssertThrowsError(try ProxyAddress.lengthPrefixedDomain(host)) { error in
            XCTAssertEqual(error as? ProxyAddressError, .domainTooLong)
        }
    }
}
