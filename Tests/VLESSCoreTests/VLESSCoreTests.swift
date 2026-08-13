import XCTest
import ProxyKit
@testable import VLESSCore

final class VLESSCoreTests: XCTestCase {

    // MARK: - UUID parsing

    func testParseVLESSUUID() {
        let bytes = parseVLESSUUID("0398d470-bc09-4cd5-889d-3ae4c569b6da")
        XCTAssertEqual(bytes, [0x03,0x98,0xd4,0x70,0xbc,0x09,0x4c,0xd5,0x88,0x9d,0x3a,0xe4,0xc5,0x69,0xb6,0xda])
    }

    func testParseVLESSUUIDIsCaseInsensitive() {
        // Server configs / user input can plausibly come in with uppercase hex.
        XCTAssertEqual(parseVLESSUUID("0398D470-BC09-4CD5-889D-3AE4C569B6DA"),
                        parseVLESSUUID("0398d470-bc09-4cd5-889d-3ae4c569b6da"))
    }

    // MARK: - Request header framing
    //
    // Verified against Xray-core's proxy/vless/encoding request format:
    // Version(1) + UUID(16) + AddonsLen(1) + Command(1) + Port(2 BE) +
    // ATYP(1) + Address.

    func testRequestHeaderShapeForDomainTarget() throws {
        let uuid = parseVLESSUUID("0398d470-bc09-4cd5-889d-3ae4c569b6da")
        let header = try vlessRequestHeader(uuid: uuid, target: VLESSTarget(host: "example.com", port: 443))

        var expected: [UInt8] = [0x00]                 // Version
        expected += uuid                                 // 16-byte UUID, sent as-is (no hashing, unlike VMess)
        expected += [0x00]                                // Addons length (none)
        expected += [0x01]                                // Command = TCP
        expected += [0x01, 0xBB]                          // Port 443, big-endian
        expected += [0x02, 11] + Array("example.com".utf8) // ATYP=domain, length-prefixed

        XCTAssertEqual(header, expected)
    }

    func testRequestHeaderShapeForIPv4Target() throws {
        let uuid = parseVLESSUUID("0398d470-bc09-4cd5-889d-3ae4c569b6da")
        let header = try vlessRequestHeader(uuid: uuid, target: VLESSTarget(host: "127.0.0.1", port: 80))

        var expected: [UInt8] = [0x00]
        expected += uuid
        expected += [0x00, 0x01]                          // Addons length, Command
        expected += [0x00, 0x50]                          // Port 80, big-endian
        expected += [0x01, 127, 0, 0, 1]                  // ATYP=ipv4, address

        XCTAssertEqual(header, expected)
    }

    func testRequestHeaderShapeForIPv6Target() throws {
        let uuid = parseVLESSUUID("0398d470-bc09-4cd5-889d-3ae4c569b6da")
        let header = try vlessRequestHeader(uuid: uuid, target: VLESSTarget(host: "::1", port: 8080))

        // 1 (Ver) + 16 (UUID) + 1 (AddonsLen) + 1 (Cmd) + 2 (Port) + 1 (ATYP) + 16 (IPv6 address)
        XCTAssertEqual(header.count, 1 + 16 + 1 + 1 + 2 + 1 + 16)
        XCTAssertEqual(header[17], 0x00) // Addons length
        XCTAssertEqual(header[18], 0x01) // Command = TCP
        XCTAssertEqual(Array(header[19..<21]), [0x1F, 0x90]) // Port 8080, big-endian
        XCTAssertEqual(header[21], 0x03) // ATYP = IPv6
    }

    /// `command:` defaults to `VLESSCommand.tcp` (every existing call site
    /// that never passes it keeps building the exact same header as
    /// before), and passing `VLESSCommand.udp` lands at the same offset
    /// (18, per `testRequestHeaderShapeForIPv4Target`'s own byte layout)
    /// with everything else in the header unaffected.
    func testRequestHeaderCommandByteDefaultsToTCPAndCanBeSetToUDP() throws {
        let uuid = parseVLESSUUID("0398d470-bc09-4cd5-889d-3ae4c569b6da")
        let target = VLESSTarget(host: "127.0.0.1", port: 80)

        let defaultHeader = try vlessRequestHeader(uuid: uuid, target: target)
        XCTAssertEqual(defaultHeader[18], VLESSCommand.tcp)

        let udpHeader = try vlessRequestHeader(uuid: uuid, target: target, command: VLESSCommand.udp)
        XCTAssertEqual(udpHeader[18], VLESSCommand.udp)
        XCTAssertNotEqual(VLESSCommand.udp, VLESSCommand.tcp)

        // Only the command byte differs -- everything else in the header is identical.
        var udpHeaderWithTCPCommand = udpHeader
        udpHeaderWithTCPCommand[18] = VLESSCommand.tcp
        XCTAssertEqual(udpHeaderWithTCPCommand, defaultHeader)
    }

    func testDifferentUUIDsProduceDifferentHeaders() throws {
        let target = VLESSTarget(host: "x.test", port: 1)
        let a = try vlessRequestHeader(uuid: parseVLESSUUID("0398d470-bc09-4cd5-889d-3ae4c569b6da"), target: target)
        let b = try vlessRequestHeader(uuid: parseVLESSUUID("11111111-1111-1111-1111-111111111111"), target: target)
        XCTAssertNotEqual(a, b)
    }
}
