import XCTest
import ProxyKit
@testable import VMessCore

final class VMessCoreTests: XCTestCase {

    // MARK: - VMess's own KDF, against an official upstream vector

    func testVMessKDFAgainstV2RayCoreOfficialVector() {
        // Taken verbatim from v2fly/v2ray-core proxy/vmess/aead/kdf_test.go
        // (TestKDFValue), so this validates our nested-HMAC construction
        // against the upstream reference implementation, not just itself.
        let key = Array("Demo Key for KDF Value Test".utf8)
        let path = [
            Array("Demo Path for KDF Value Test".utf8),
            Array("Demo Path for KDF Value Test2".utf8),
            Array("Demo Path for KDF Value Test3".utf8),
        ]
        let expected = "53e9d7e1bd7bd25022b71ead07d8a596efc8a845c7888652fd684b4903dc8892"
        let got = vmessKDF(key: key, path: path).map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(got, expected)
    }

    // MARK: - Parsing helpers

    func testParseUUID() {
        let bytes = parseUUID("0398d470-bc09-4cd5-889d-3ae4c569b6da")
        XCTAssertEqual(bytes, [0x03,0x98,0xd4,0x70,0xbc,0x09,0x4c,0xd5,0x88,0x9d,0x3a,0xe4,0xc5,0x69,0xb6,0xda])
    }

    func testParseUUIDIsCaseInsensitive() {
        // Server configs / user input can plausibly come in with uppercase hex.
        XCTAssertEqual(parseUUID("0398D470-BC09-4CD5-889D-3AE4C569B6DA"),
                        parseUUID("0398d470-bc09-4cd5-889d-3ae4c569b6da"))
    }

    // MARK: - VMess's own address wire encoding (type-tag bytes 1/2/3).
    // The underlying ipv4/ipv6/domain *detection* is ProxyKit's ProxyAddress
    // and is tested in ProxyKitTests; this only covers the VMess-specific
    // `.vmessEncoded` mapping on top of it.

    func testVMessEncodedAddressWireFormat() throws {
        XCTAssertEqual(try ProxyAddress.parse("127.0.0.1").vmessEncoded, [0x01, 127, 0, 0, 1])

        let ipv6Encoded = try ProxyAddress.parse("::1").vmessEncoded
        XCTAssertEqual(ipv6Encoded.first, 0x03)
        XCTAssertEqual(ipv6Encoded.count, 17) // 1 type byte + 16 address bytes

        let domainEncoded = try ProxyAddress.parse("example.com").vmessEncoded
        XCTAssertEqual(domainEncoded[0], 0x02)
        XCTAssertEqual(domainEncoded[1], UInt8("example.com".utf8.count))
        XCTAssertEqual(Array(domainEncoded[2...]), Array("example.com".utf8))
    }

    // MARK: - Full AEAD header seal/open round trip (mirrors v2ray-core's own encrypt_test.go)

    func testSealOpenVMessAEADHeaderRoundTrip() throws {
        let key = vmessKDF16(key: Array("Demo Key for Auth ID Test".utf8), path: [Array("Demo Path for Auth ID Test".utf8)])
        let header = Array("Test Header".utf8)

        let sealed = sealVMessAEADHeader(key: key, data: header)
        let authID = Array(sealed.prefix(16))
        let remainder = Array(sealed.dropFirst(16))

        let recovered = try openVMessAEADHeader(key: key, authID: authID, remainder: remainder)
        XCTAssertEqual(recovered, header)
    }

    func testOpenVMessAEADHeaderRejectsAnySingleByteCorruption() {
        // Mirrors v2ray-core's TestOpenVMessAEADHeader4: flipping any byte
        // of the sealed blob must make it fail closed, never silently
        // decode to the wrong plaintext.
        let key = vmessKDF16(key: Array("Demo Key for Auth ID Test".utf8), path: [Array("Demo Path for Auth ID Test".utf8)])
        let header = Array("Test Header".utf8)
        let sealedOriginal = sealVMessAEADHeader(key: key, data: header)

        for i in 0..<min(sealedOriginal.count, 64) {
            var sealed = sealedOriginal
            sealed[i] ^= 0xff
            let authID = Array(sealed.prefix(16))
            let remainder = Array(sealed.dropFirst(16))
            XCTAssertThrowsError(try openVMessAEADHeader(key: key, authID: authID, remainder: remainder), "byte \(i)")
        }
    }

    // MARK: - Request builder self-consistency (no network)

    func testVMessRequestBuildIsStructurallyValidAndSelfDecodable() throws {
        let uuid = parseUUID("0398d470-bc09-4cd5-889d-3ae4c569b6da")
        let target = VMessTarget(host: "example.com", port: 80)
        let request = try VMessRequest.build(uuid: uuid, target: target)

        // authID(16) + sealedLength(18) + nonce(8) + sealedHeader(>= tag-only 16)
        XCTAssertGreaterThanOrEqual(request.wireBytes.count, 16 + 18 + 8 + 16)
        XCTAssertEqual(request.requestBodyKey.count, 16)
        XCTAssertEqual(request.requestBodyIV.count, 16)

        // Decrypt our own header the same way a real vmess server would, and
        // check the fields we expect to see: Ver=1, requestBodyIV/Key match,
        // command=TCP, target address/port match.
        let cmdKey = md5(uuid + cmdKeyMagic)
        let authID = Array(request.wireBytes.prefix(16))
        let remainder = Array(request.wireBytes.dropFirst(16))
        let plain = try openVMessAEADHeader(key: cmdKey, authID: authID, remainder: remainder)

        XCTAssertEqual(plain[0], 1) // Ver
        XCTAssertEqual(Array(plain[1..<17]), request.requestBodyIV)
        XCTAssertEqual(Array(plain[17..<33]), request.requestBodyKey)
        XCTAssertEqual(plain[33], request.responseHeaderByte)
        XCTAssertEqual(plain[37], VMessRequest.commandTCP)
        let port = UInt16(plain[38]) << 8 | UInt16(plain[39])
        XCTAssertEqual(port, 80)
        XCTAssertEqual(plain[40], 0x02) // AddressType domain
        XCTAssertEqual(plain[41], UInt8("example.com".utf8.count)) // domain length prefix
        XCTAssertEqual(Array(plain[42..<(42 + "example.com".utf8.count)]), Array("example.com".utf8))
    }

    /// `command:` defaults to `commandTCP` (every existing call site that
    /// never passes it keeps building the exact same bytes as before), and
    /// passing `commandUDP` explicitly lands at the same byte offset (37)
    /// the TCP test above already asserts on -- everything else about the
    /// header (KDF, AEAD sealing, address/port encoding) is unaffected by
    /// which command is requested.
    func testVMessRequestBuildCommandByteDefaultsToTCPAndCanBeSetToUDP() throws {
        let uuid = parseUUID("0398d470-bc09-4cd5-889d-3ae4c569b6da")
        let cmdKey = md5(uuid + cmdKeyMagic)
        let target = VMessTarget(host: "example.com", port: 80)

        let defaultRequest = try VMessRequest.build(uuid: uuid, target: target)
        let defaultPlain = try openVMessAEADHeader(
            key: cmdKey, authID: Array(defaultRequest.wireBytes.prefix(16)), remainder: Array(defaultRequest.wireBytes.dropFirst(16))
        )
        XCTAssertEqual(defaultPlain[37], VMessRequest.commandTCP)

        let udpRequest = try VMessRequest.build(uuid: uuid, target: target, command: VMessRequest.commandUDP)
        let udpPlain = try openVMessAEADHeader(
            key: cmdKey, authID: Array(udpRequest.wireBytes.prefix(16)), remainder: Array(udpRequest.wireBytes.dropFirst(16))
        )
        XCTAssertEqual(udpPlain[37], VMessRequest.commandUDP)
        XCTAssertNotEqual(VMessRequest.commandUDP, VMessRequest.commandTCP)
    }

    func testVMessRequestBuildSupportsIPv4AndIPv6Targets() throws {
        let uuid = parseUUID("0398d470-bc09-4cd5-889d-3ae4c569b6da")
        let cmdKey = md5(uuid + cmdKeyMagic)

        for (host, expectedTypeByte, expectedAddrBytes) in [
            ("127.0.0.1", UInt8(0x01), [UInt8]([127, 0, 0, 1])),
            ("::1", UInt8(0x03), [UInt8]([0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1])),
        ] {
            let request = try VMessRequest.build(uuid: uuid, target: VMessTarget(host: host, port: 443))
            let authID = Array(request.wireBytes.prefix(16))
            let remainder = Array(request.wireBytes.dropFirst(16))
            let plain = try openVMessAEADHeader(key: cmdKey, authID: authID, remainder: remainder)

            let port = UInt16(plain[38]) << 8 | UInt16(plain[39])
            XCTAssertEqual(port, 443, "host \(host)")
            XCTAssertEqual(plain[40], expectedTypeByte, "host \(host)")
            XCTAssertEqual(Array(plain[41..<(41 + expectedAddrBytes.count)]), expectedAddrBytes, "host \(host)")
        }
    }

    func testVMessRequestBuildIsSelfDecodableAcrossManyRandomPaddingLengths() throws {
        // paddingLen is randomized 0...15 on every call (it's the 4-bit P
        // field packed alongside Security in one byte); running this many
        // times exercises both boundaries (0 padding, 15 padding) and
        // everything in between, plus a fresh random key/IV/responseHeaderByte
        // each time, instead of relying on one lucky roll.
        let uuid = parseUUID("0398d470-bc09-4cd5-889d-3ae4c569b6da")
        let cmdKey = md5(uuid + cmdKeyMagic)
        let target = VMessTarget(host: "example.com", port: 8443)

        for _ in 0..<200 {
            let request = try VMessRequest.build(uuid: uuid, target: target)
            let authID = Array(request.wireBytes.prefix(16))
            let remainder = Array(request.wireBytes.dropFirst(16))
            let plain = try openVMessAEADHeader(key: cmdKey, authID: authID, remainder: remainder)

            XCTAssertEqual(plain[0], 1)
            XCTAssertEqual(Array(plain[1..<17]), request.requestBodyIV)
            XCTAssertEqual(Array(plain[17..<33]), request.requestBodyKey)
            XCTAssertEqual(plain[33], request.responseHeaderByte)
            XCTAssertEqual(plain[40], 0x02)
            XCTAssertEqual(plain[41], UInt8("example.com".utf8.count))
            // Whatever padding was rolled, the FNV1a-32 checksum (last 4 bytes)
            // must cover everything before it -- this is what would break if
            // the padding length and the actual padding bytes written ever
            // drifted apart.
            let withoutChecksum = plain.dropLast(4)
            XCTAssertEqual(fnv1a32(Array(withoutChecksum)).bigEndianBytes, Array(plain.suffix(4)))
        }
    }

    // MARK: - Response header decode, against an in-memory fake connection

    private final class FakeByteSource: ByteStreamSource {
        private var buffer: [UInt8]
        init(_ buffer: [UInt8]) { self.buffer = buffer }
        func readExactly(_ n: Int, timeout: TimeInterval?) async throws -> [UInt8] {
            guard buffer.count >= n else { throw VMessError.malformedResponse }
            let result = Array(buffer.prefix(n))
            buffer.removeFirst(n)
            return result
        }
    }

    /// Simulates a server that never answers (e.g. a VMess server silently
    /// dropping a connection with a bad AuthID/UUID -- by design, to resist
    /// active probing). Honors `timeout` itself so this test stays fast and
    /// needs no real socket, while still proving `decodeResponseHeader`
    /// surfaces a timeout instead of hanging forever.
    private final class HangingByteSource: ByteStreamSource {
        func readExactly(_ n: Int, timeout: TimeInterval?) async throws -> [UInt8] {
            try await Task.sleep(nanoseconds: UInt64((timeout ?? 3600) * 1_000_000_000))
            throw ProxyError.timedOut
        }
    }

    func testDecodeResponseHeaderTimesOutInsteadOfHangingForever() async {
        let requestBodyKey = (0..<16).map { UInt8($0) }
        let requestBodyIV = (0..<16).map { UInt8($0 &+ 1) }
        do {
            _ = try await decodeResponseHeader(requestBodyKey: requestBodyKey, requestBodyIV: requestBodyIV,
                                                responseHeaderByte: 0x42, connection: HangingByteSource(), timeout: 0.05)
            XCTFail("expected timedOut")
        } catch ProxyError.timedOut {
            // expected: this is the exact failure mode a wrong UUID produces
            // against a real server (verified live in Scripts/integration_test.sh).
        } catch {
            XCTFail("expected timedOut, got \(error)")
        }
    }

    /// Builds a valid AEAD response block the same way a real vmess server would,
    /// given the client's requestBodyKey/IV and the responseHeaderByte it sent.
    private func makeServerResponseHeaderBytes(requestBodyKey: [UInt8], requestBodyIV: [UInt8], responseHeaderByte: UInt8, optionByte: UInt8) -> [UInt8] {
        let responseBodyKey = Array(sha256(requestBodyKey).prefix(16))
        let responseBodyIV = Array(sha256(requestBodyIV).prefix(16))

        let header: [UInt8] = [responseHeaderByte, optionByte, 0, 0]

        let lengthKey = vmessKDF16(key: responseBodyKey, path: [Array("AEAD Resp Header Len Key".utf8)])
        let lengthNonce = Array(vmessKDF(key: responseBodyIV, path: [Array("AEAD Resp Header Len IV".utf8)]).prefix(12))
        let sealedLength = aesGCMSeal(key: lengthKey, nonce: lengthNonce, plaintext: UInt16(header.count).bigEndianBytes, aad: [])

        let headerKey = vmessKDF16(key: responseBodyKey, path: [Array("AEAD Resp Header Key".utf8)])
        let headerNonce = Array(vmessKDF(key: responseBodyIV, path: [Array("AEAD Resp Header IV".utf8)]).prefix(12))
        let sealedHeader = aesGCMSeal(key: headerKey, nonce: headerNonce, plaintext: header, aad: [])

        return sealedLength + sealedHeader
    }

    func testDecodeResponseHeaderSuccess() async throws {
        let requestBodyKey = (0..<16).map { UInt8($0) }
        let requestBodyIV = (0..<16).map { UInt8($0 &+ 1) }
        let responseHeaderByte: UInt8 = 0x42

        let wire = makeServerResponseHeaderBytes(requestBodyKey: requestBodyKey, requestBodyIV: requestBodyIV,
                                                  responseHeaderByte: responseHeaderByte, optionByte: 7)
        let source = FakeByteSource(wire)
        let header = try await decodeResponseHeader(requestBodyKey: requestBodyKey, requestBodyIV: requestBodyIV,
                                                      responseHeaderByte: responseHeaderByte, connection: source)
        XCTAssertEqual(header.optionByte, 7)
    }

    func testDecodeResponseHeaderRejectsWrongResponseHeaderByte() async {
        let requestBodyKey = (0..<16).map { UInt8($0) }
        let requestBodyIV = (0..<16).map { UInt8($0 &+ 1) }

        let wire = makeServerResponseHeaderBytes(requestBodyKey: requestBodyKey, requestBodyIV: requestBodyIV,
                                                  responseHeaderByte: 0x42, optionByte: 0)
        let source = FakeByteSource(wire)
        do {
            _ = try await decodeResponseHeader(requestBodyKey: requestBodyKey, requestBodyIV: requestBodyIV,
                                                responseHeaderByte: 0x43, connection: source) // wrong byte on purpose
            XCTFail("expected responseHeaderMismatch")
        } catch VMessError.responseHeaderMismatch {
            // expected
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    func testDecodeResponseHeaderRejectsTruncatedData() async {
        let requestBodyKey = (0..<16).map { UInt8($0) }
        let requestBodyIV = (0..<16).map { UInt8($0 &+ 1) }
        let source = FakeByteSource([0x01, 0x02, 0x03]) // far too short

        do {
            _ = try await decodeResponseHeader(requestBodyKey: requestBodyKey, requestBodyIV: requestBodyIV,
                                                responseHeaderByte: 0x42, connection: source)
            XCTFail("expected an error")
        } catch {
            // any thrown error is correct here; the point is it must not crash or hang
        }
    }

    // MARK: - AEAD body chunk seal/open round trip (Security: AES-128-GCM)

    func testSealOpenVMessBodyChunkRoundTrip() throws {
        let key = (0..<16).map { UInt8($0) }
        let iv = (0..<16).map { UInt8($0 &+ 1) }
        let plaintext = Array("hello vmess body".utf8)

        let framed = sealVMessBodyChunk(key: key, iv: iv, counter: 0, plaintext: plaintext)
        let length = Int(framed[0]) << 8 | Int(framed[1])
        XCTAssertEqual(length, framed.count - 2)
        XCTAssertEqual(length, plaintext.count + 16) // ciphertext + GCM tag, no extra overhead

        let recovered = try openVMessBodyChunkPayload(key: key, iv: iv, counter: 0, sealed: Array(framed.dropFirst(2)))
        XCTAssertEqual(recovered, plaintext)
    }

    func testVMessBodyChunkCounterAdvancesTheNonceSoRepeatedPlaintextSealsDifferently() throws {
        // Two chunks with identical plaintext must not produce identical
        // ciphertext -- if they did, the per-chunk counter wouldn't actually
        // be reaching the nonce, which would mean nonce reuse (catastrophic
        // for GCM: it breaks confidentiality and authentication both).
        let key = (0..<16).map { UInt8($0) }
        let iv = (0..<16).map { UInt8($0 &+ 1) }
        let plaintext = Array("same plaintext twice".utf8)

        let first = sealVMessBodyChunk(key: key, iv: iv, counter: 0, plaintext: plaintext)
        let second = sealVMessBodyChunk(key: key, iv: iv, counter: 1, plaintext: plaintext)
        XCTAssertNotEqual(first, second)

        XCTAssertEqual(try openVMessBodyChunkPayload(key: key, iv: iv, counter: 0, sealed: Array(first.dropFirst(2))), plaintext)
        XCTAssertEqual(try openVMessBodyChunkPayload(key: key, iv: iv, counter: 1, sealed: Array(second.dropFirst(2))), plaintext)
    }

    func testOpenVMessBodyChunkRejectsWrongCounter() {
        let key = (0..<16).map { UInt8($0) }
        let iv = (0..<16).map { UInt8($0 &+ 1) }
        let framed = sealVMessBodyChunk(key: key, iv: iv, counter: 5, plaintext: Array("payload".utf8))
        XCTAssertThrowsError(try openVMessBodyChunkPayload(key: key, iv: iv, counter: 6, sealed: Array(framed.dropFirst(2))))
    }

    func testOpenVMessBodyChunkRejectsTamperedCiphertext() {
        let key = (0..<16).map { UInt8($0) }
        let iv = (0..<16).map { UInt8($0 &+ 1) }
        let framedOriginal = sealVMessBodyChunk(key: key, iv: iv, counter: 0, plaintext: Array("payload".utf8))

        for i in 2..<framedOriginal.count { // skip the 2-byte length prefix itself
            var framed = framedOriginal
            framed[i] ^= 0xff
            XCTAssertThrowsError(try openVMessBodyChunkPayload(key: key, iv: iv, counter: 0, sealed: Array(framed.dropFirst(2))), "byte \(i)")
        }
    }

    func testDecodeResponseHeaderRejectsWrongKeys() async {
        // Simulates a MITM / mismatched session: sealing with one requestBodyKey/IV
        // pair but decoding with another must fail closed, not silently succeed.
        let realKey = (0..<16).map { UInt8($0) }
        let realIV = (0..<16).map { UInt8($0 &+ 1) }
        let wrongKey = (0..<16).map { UInt8($0 &+ 99) }

        let wire = makeServerResponseHeaderBytes(requestBodyKey: realKey, requestBodyIV: realIV,
                                                  responseHeaderByte: 0x42, optionByte: 0)
        let source = FakeByteSource(wire)
        do {
            _ = try await decodeResponseHeader(requestBodyKey: wrongKey, requestBodyIV: realIV,
                                                responseHeaderByte: 0x42, connection: source)
            XCTFail("expected an authentication error")
        } catch {
            // expected: GCM tag check must fail
        }
    }
}
