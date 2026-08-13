import XCTest
import ProxyKit
@testable import TrojanCore

final class TrojanCoreTests: XCTestCase {

    // MARK: - hex(SHA224(password))

    /// Cross-checked against NIST's own SHA-224 test vector for the empty
    /// string (FIPS 180-4), the same way `sha224` itself is verified in
    /// ProxyKitTests -- this just confirms the hex-encoding wrapper on top
    /// of it doesn't introduce e.g. uppercase/byte-order mistakes.
    func testPasswordHexMatchesKnownSHA224Vector() {
        XCTAssertEqual(trojanPasswordHex(""), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")
    }

    func testPasswordHexIsLowercase56Characters() {
        let hex = trojanPasswordHex("hunter2")
        XCTAssertEqual(hex.count, 56)
        XCTAssertEqual(hex, hex.lowercased())
        XCTAssertTrue(hex.allSatisfy(\.isHexDigit))
    }

    // MARK: - Request header framing

    func testRequestHeaderShapeForDomainTarget() throws {
        let header = try trojanRequestHeader(password: "hunter2", target: .domain("example.com"), targetPort: 443)

        let passwordHex = trojanPasswordHex("hunter2")
        var expected = Array(passwordHex.utf8)
        expected += [0x0D, 0x0A]               // CRLF
        expected += [0x01]                      // CMD = Connect
        expected += [0x03, 11] + Array("example.com".utf8) // ATYP=domain, length-prefixed
        expected += [0x01, 0xBB]                // port 443 big-endian
        expected += [0x0D, 0x0A]               // CRLF

        XCTAssertEqual(header, expected)
    }

    func testRequestHeaderShapeForIPv4Target() throws {
        let header = try trojanRequestHeader(password: "p", target: .ipv4([127, 0, 0, 1]), targetPort: 80)

        var expected = Array(trojanPasswordHex("p").utf8)
        expected += [0x0D, 0x0A]
        expected += [0x01, 0x01, 127, 0, 0, 1] // CMD, ATYP=ipv4, address
        expected += [0x00, 0x50]                // port 80 big-endian
        expected += [0x0D, 0x0A]
        XCTAssertEqual(header, expected)
    }

    func testDifferentPasswordsProduceDifferentHeaders() throws {
        let a = try trojanRequestHeader(password: "one", target: .domain("x.test"), targetPort: 1)
        let b = try trojanRequestHeader(password: "two", target: .domain("x.test"), targetPort: 1)
        XCTAssertNotEqual(a, b)
    }

    /// `command:` defaults to `TrojanCommand.connect` (every existing call
    /// site that never passes it keeps building the exact same header as
    /// before), and passing `.udpAssociate` changes only the CMD byte --
    /// everything else in the header (password hex, CRLFs, ATYP+address+port)
    /// is unaffected.
    func testRequestHeaderCommandByteDefaultsToConnectAndCanBeSetToUDPAssociate() throws {
        let defaultHeader = try trojanRequestHeader(password: "p", target: .ipv4([127, 0, 0, 1]), targetPort: 80)
        XCTAssertEqual(defaultHeader[56 + 2], TrojanCommand.connect) // after 56-hex-char password + CRLF

        let udpHeader = try trojanRequestHeader(password: "p", target: .ipv4([127, 0, 0, 1]), targetPort: 80, command: TrojanCommand.udpAssociate)
        XCTAssertEqual(udpHeader[56 + 2], TrojanCommand.udpAssociate)
        XCTAssertNotEqual(TrojanCommand.udpAssociate, TrojanCommand.connect)

        var udpHeaderWithConnectCommand = udpHeader
        udpHeaderWithConnectCommand[56 + 2] = TrojanCommand.connect
        XCTAssertEqual(udpHeaderWithConnectCommand, defaultHeader)
    }

    // MARK: - UDP relay per-packet framing

    func testUDPFrameRoundTripWithIPv4Target() async throws {
        let frame = try trojanUDPFrame(target: .ipv4([8, 8, 8, 8]), targetPort: 53, payload: Array("dns query".utf8))
        let source = FakeByteSource(frame)
        let decoded = try await readTrojanUDPFrame(from: source, timeout: nil)
        XCTAssertEqual(decoded.target, .ipv4([8, 8, 8, 8]))
        XCTAssertEqual(decoded.targetPort, 53)
        XCTAssertEqual(decoded.payload, Array("dns query".utf8))
    }

    func testUDPFrameRoundTripWithIPv6Target() async throws {
        let addr6 = (0..<16).map { UInt8($0) }
        let frame = try trojanUDPFrame(target: .ipv6(addr6), targetPort: 443, payload: [0x01, 0x02, 0x03])
        let decoded = try await readTrojanUDPFrame(from: FakeByteSource(frame), timeout: nil)
        XCTAssertEqual(decoded.target, .ipv6(addr6))
        XCTAssertEqual(decoded.targetPort, 443)
        XCTAssertEqual(decoded.payload, [0x01, 0x02, 0x03])
    }

    func testUDPFrameRoundTripWithDomainTargetAndEmptyPayload() async throws {
        let frame = try trojanUDPFrame(target: .domain("example.com"), targetPort: 80, payload: [])
        let decoded = try await readTrojanUDPFrame(from: FakeByteSource(frame), timeout: nil)
        XCTAssertEqual(decoded.target, .domain("example.com"))
        XCTAssertEqual(decoded.targetPort, 80)
        XCTAssertEqual(decoded.payload, [])
    }

    /// Two frames back-to-back on the same stream -- confirms one open
    /// session really can relay to two different destinations in sequence,
    /// each self-delimited by its own length, with no leftover bytes
    /// bleeding into the next frame's decode.
    func testTwoBackToBackFramesToDifferentTargetsDecodeIndependently() async throws {
        let frameA = try trojanUDPFrame(target: .domain("a.example"), targetPort: 1, payload: Array("first".utf8))
        let frameB = try trojanUDPFrame(target: .domain("b.example"), targetPort: 2, payload: Array("second".utf8))
        let source = FakeByteSource(frameA + frameB)

        let decodedA = try await readTrojanUDPFrame(from: source, timeout: nil)
        XCTAssertEqual(decodedA.target, .domain("a.example"))
        XCTAssertEqual(decodedA.payload, Array("first".utf8))

        let decodedB = try await readTrojanUDPFrame(from: source, timeout: nil)
        XCTAssertEqual(decodedB.target, .domain("b.example"))
        XCTAssertEqual(decodedB.payload, Array("second".utf8))
    }

    func testUDPFrameTruncatedThrowsInsteadOfCrashing() async throws {
        let frame = try trojanUDPFrame(target: .ipv4([1, 2, 3, 4]), targetPort: 1, payload: Array("hello".utf8))
        let truncated = Array(frame.prefix(frame.count - 3))
        do {
            _ = try await readTrojanUDPFrame(from: FakeByteSource(truncated), timeout: nil)
            XCTFail("expected an error")
        } catch {
            // expected -- FakeByteSource throws ProxyError.connectionClosed once it runs out
        }
    }

    func testUDPFrameCorruptedCRLFThrowsMissingCRLF() async throws {
        var frame = try trojanUDPFrame(target: .ipv4([1, 2, 3, 4]), targetPort: 1, payload: Array("hello".utf8))
        // The first CRLF sits right after ATYP(1)+addr(4)+port(2)+length(2) = 9 bytes in.
        frame[9] = 0x41 // 'A', not 0x0D
        do {
            _ = try await readTrojanUDPFrame(from: FakeByteSource(frame), timeout: nil)
            XCTFail("expected missingCRLF")
        } catch TrojanUDPError.missingCRLF {
            // expected
        }
    }
}

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
