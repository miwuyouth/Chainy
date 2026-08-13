import XCTest
import ProxyKit
import ShadowsocksCore
import ChainCore

// MARK: - Minimal in-process fake Shadowsocks UDP relay server
//
// Real Shadowsocks UDP relay servers are dumb: given a packet, decrypt it,
// read the embedded ATYP+addr+port, and `sendto(payload, addr:port)` --
// never re-encrypting or inspecting `payload`. This fake reproduces exactly
// that behavior over a real loopback `UDPListener`/`UDPConn` (the same
// ProxyKit primitives `ShadowsocksUDPRelay`'s production path uses), so
// these tests prove real, independent-process-shaped crypto/framing
// round-trips -- not just that in-memory function calls agree with
// themselves (see `ShadowsocksUDPRelayTests` for the fake-transport version
// of that).
//
// `forwardTo == nil` makes this the *terminal* hop: it treats its decrypted
// payload as if the real target echoed it straight back, wrapping the
// "reply" the same way a real target's answer would be. `forwardTo` set
// makes it a *relay* hop: it forwards the raw decrypted payload on to
// another (possibly fake, possibly this same kind of) server, and relays
// back whatever comes back from there, untouched, wrapped in its own fresh
// envelope -- exactly how a real server chains, with zero awareness it's
// "chaining" at all.
private final class FakeShadowsocksUDPServer {
    private let password: String
    private let cipher: ShadowsocksCipher
    private let forwardTo: (host: String, port: UInt16)?
    private let listener: UDPListener
    private var forwardConn: UDPConn?

    init(password: String, cipher: ShadowsocksCipher, forwardTo: (host: String, port: UInt16)? = nil) throws {
        self.password = password
        self.cipher = cipher
        self.forwardTo = forwardTo
        listener = try UDPListener()
    }

    func start() async throws -> UInt16 {
        try await listener.start(
            onAccept: { [weak self] conn in
                guard let self else { return }
                Task { await self.acceptLoop(conn) }
            },
            onFailure: { _ in }
        )
        return listener.port!
    }

    func stop() { listener.cancel() }

    private func acceptLoop(_ client: UDPConn) async {
        do {
            try await client.connect(timeout: nil)
            while true {
                let packet = try await client.receiveDatagram(timeout: nil)
                if packet.isEmpty { return }
                let opened = try shadowsocksOpenUDPPacket(password: password, cipher: cipher, packet: packet)

                if let forwardTo {
                    if forwardConn == nil {
                        let fc = UDPConn(host: forwardTo.host, port: forwardTo.port)
                        try await fc.connect(timeout: nil)
                        forwardConn = fc
                        Task { [weak self] in await self?.relayForwardReplies(back: client) }
                    }
                    try await forwardConn?.send(opened.payload, timeout: nil)
                } else {
                    // Terminal hop: simulate the real target echoing the
                    // payload straight back.
                    let reply = try shadowsocksSealUDPPacket(password: password, cipher: cipher, targetHost: opened.address, targetPort: opened.port, payload: opened.payload)
                    try await client.send(reply, timeout: nil)
                }
            }
        } catch {
            return
        }
    }

    private func relayForwardReplies(back client: UDPConn) async {
        guard let forwardConn, let forwardTo else { return }
        do {
            while true {
                let raw = try await forwardConn.receiveDatagram(timeout: nil)
                if raw.isEmpty { return }
                // Wrap the raw (opaque -- already a complete packet from the
                // next hop's own point of view) reply bytes as our own reply
                // "from" whichever address we forwarded to.
                let wrapped = try shadowsocksSealUDPPacket(password: password, cipher: cipher, targetHost: ProxyAddress.parse(forwardTo.host), targetPort: forwardTo.port, payload: raw)
                try await client.send(wrapped, timeout: nil)
            }
        } catch {
            return
        }
    }
}

final class ChainCoreUDPRelayLiveSocketTests: XCTestCase {
    func testSingleHopRoundTripOverRealLoopbackSockets() async throws {
        let server = try FakeShadowsocksUDPServer(password: "single-hop-pw", cipher: .aes256Gcm)
        let port = try await server.start()
        defer { server.stop() }

        let hop = ProxyHop(host: "127.0.0.1", port: port, protocolConfig: .shadowsocks(password: "single-hop-pw", cipher: .aes256Gcm))
        let relay = try await ShadowsocksUDPRelay.open(hops: [hop])
        defer { relay.close() }

        try await relay.send(targetHost: "9.9.9.9", targetPort: 53, payload: Array("hello".utf8))
        let result = try await relay.receive(timeout: 5)

        XCTAssertEqual(result.fromHost, "9.9.9.9")
        XCTAssertEqual(result.fromPort, 53)
        XCTAssertEqual(result.payload, Array("hello".utf8))
    }

    func testTwoHopChainRoundTripOverRealLoopbackSockets() async throws {
        // Start the terminal hop first so the relay hop can be told its
        // real, already-bound port.
        let hop1Server = try FakeShadowsocksUDPServer(password: "hop1-pw", cipher: .aes128Gcm)
        let hop1Port = try await hop1Server.start()
        defer { hop1Server.stop() }

        let hop0Server = try FakeShadowsocksUDPServer(password: "hop0-pw", cipher: .aes256Gcm, forwardTo: (host: "127.0.0.1", port: hop1Port))
        let hop0Port = try await hop0Server.start()
        defer { hop0Server.stop() }

        let hops = [
            ProxyHop(host: "127.0.0.1", port: hop0Port, protocolConfig: .shadowsocks(password: "hop0-pw", cipher: .aes256Gcm)),
            ProxyHop(host: "127.0.0.1", port: hop1Port, protocolConfig: .shadowsocks(password: "hop1-pw", cipher: .aes128Gcm)),
        ]
        let relay = try await ShadowsocksUDPRelay.open(hops: hops)
        defer { relay.close() }

        try await relay.send(targetHost: "real-target.example", targetPort: 443, payload: Array("through two hops".utf8))
        let result = try await relay.receive(timeout: 5)

        XCTAssertEqual(result.fromHost, "real-target.example")
        XCTAssertEqual(result.fromPort, 443)
        XCTAssertEqual(result.payload, Array("through two hops".utf8))
    }
}
