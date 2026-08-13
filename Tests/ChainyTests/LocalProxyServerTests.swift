import XCTest
import ChainCore
import ProxyKit
import SOCKS5Core
import ShadowsocksCore
@testable import VMessCore
@testable import Chainy

/// End-to-end coverage for the local SOCKS5 listener, driven entirely
/// through the public `AppStore` API a real screen would call
/// (`connect()`/`disconnect()`/`setActiveChain(_:)`), with a real client
/// (`SOCKS5Session.open`, playing the role a browser/curl would) dialing a
/// real local listener that relays through a real one-hop chain to a small
/// in-process fake upstream SOCKS5 "internet".
@MainActor
final class LocalProxyServerTests: XCTestCase {
    /// A minimal SOCKS5 server built from the same production primitives
    /// (`TCPListener`, `SOCKS5Server.acceptConnect`) the local listener
    /// itself uses -- stands in for "the internet": accepts one CONNECT per
    /// connection (to *whatever* destination is asked, no real DNS/dial),
    /// records it, then echoes back everything it's sent. Small version of
    /// `ChainCoreLiveSocketTests`' server-side test double, single-hop only.
    @MainActor
    private final class FakeEchoUpstream {
        private let listener: TCPListener
        private(set) var receivedRequests: [SOCKS5IncomingRequest] = []

        init() throws { listener = try TCPListener(port: 0) }

        func start() async throws -> UInt16 {
            try await listener.start(
                onAccept: { [weak self] conn in self?.handle(conn) },
                onFailure: { _ in }
            )
            return listener.port!
        }

        func stop() { listener.cancel() }

        private func handle(_ conn: TCPConn) {
            Task { [weak self] in
                guard let self else { return }
                do {
                    try await conn.connect()
                    let request = try await SOCKS5Server.acceptConnect(over: conn)
                    self.receivedRequests.append(request)
                    while true {
                        let chunk = try await conn.readAvailable(timeout: nil)
                        if chunk.isEmpty { break }
                        try await conn.send(chunk)
                    }
                } catch {
                    // connection torn down mid-test -- nothing more to do
                }
                conn.close()
            }
        }
    }

    private func makeStore() -> AppStore {
        AppStore(directoryURL: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true))
    }

    private func freeEphemeralPort() async throws -> UInt16 {
        let probe = try TCPListener(port: 0)
        try await probe.start(onAccept: { _ in }, onFailure: { _ in })
        let port = try XCTUnwrap(probe.port)
        probe.cancel()
        return port
    }

    /// Runs `body` with UserDefaults' "localProxyPort" (what `AppStore`
    /// reads via `@AppStorage` in the real Settings screen) temporarily set
    /// to `port`, restoring whatever was there before -- so exercising the
    /// real `connect()` code path in tests never permanently changes the
    /// developer's own real app preference.
    private func withLocalProxyPort(_ port: UInt16, perform body: () async throws -> Void) async rethrows {
        let key = "localProxyPort"
        let previous = UserDefaults.standard.object(forKey: key)
        UserDefaults.standard.set(Int(port), forKey: key)
        defer {
            if let previous { UserDefaults.standard.set(previous, forKey: key) }
            else { UserDefaults.standard.removeObject(forKey: key) }
        }
        try await body()
    }

    private func oneHopChain(name: String, upstreamPort: UInt16) -> NamedProxyChain {
        NamedProxyChain(
            name: name,
            hops: [ProxyHop(host: "127.0.0.1", port: upstreamPort, protocolConfig: .socks5(auth: .none))]
        )
    }

    // MARK: - Happy path

    func testConnectRelaysArbitraryPerConnectionDestination() async throws {
        let upstream = try FakeEchoUpstream()
        let upstreamPort = try await upstream.start()
        defer { upstream.stop() }

        let store = makeStore()
        let chain = oneHopChain(name: "Test Chain", upstreamPort: upstreamPort)
        store.addChain(chain)
        store.setActiveChain(chain.id)

        let localPort = try await freeEphemeralPort()
        try await withLocalProxyPort(localPort) {
            await store.connect()
            XCTAssertTrue(store.isProxyRunning)
            XCTAssertEqual(store.proxyListenPort, localPort)

            let client = try await SOCKS5Session.open(
                server: SOCKS5ServerConfig(host: "127.0.0.1", port: localPort, auth: .none),
                targetHost: .domain("browser-requested.example"),
                targetPort: 8443
            )
            let payload = Array("hello through the local proxy".utf8)
            try await client.send(payload)
            let echoed = try await client.receive()
            client.close()

            XCTAssertEqual(echoed, payload)
            XCTAssertEqual(upstream.receivedRequests, [SOCKS5IncomingRequest(host: "browser-requested.example", port: 8443)])

            store.disconnect()
        }
    }

    // MARK: - Connections panel tracking

    /// `AppStore.liveConnections`/`closedConnections` (polled from
    /// `LocalProxyServer.snapshotConnections()` on the same once-a-second
    /// cadence as the throughput sample) is what the Connections panel
    /// lists -- exercises that whole pipeline through the real relay path,
    /// not just `LocalProxyServer`'s bookkeeping in isolation: destination/
    /// chain name/byte counts while live, then the same connection moving
    /// into the closed history with a final snapshot once it ends.
    func testConnectionsPanelTracksLiveThenClosedConnection() async throws {
        let upstream = try FakeEchoUpstream()
        let upstreamPort = try await upstream.start()
        defer { upstream.stop() }

        let store = makeStore()
        let chain = oneHopChain(name: "Tracked Chain", upstreamPort: upstreamPort)
        store.addChain(chain)
        store.setActiveChain(chain.id)

        let localPort = try await freeEphemeralPort()
        try await withLocalProxyPort(localPort) {
            await store.connect()

            let client = try await SOCKS5Session.open(
                server: SOCKS5ServerConfig(host: "127.0.0.1", port: localPort, auth: .none),
                targetHost: .domain("tracked-destination.example"),
                targetPort: 9443
            )
            try await client.send(Array("hello through the tracked connection".utf8))
            _ = try await client.receive()

            // Wait for AppStore's once-a-second sampling tick to publish it.
            var live: ConnectionInfo?
            for _ in 0..<40 where live == nil {
                live = store.liveConnections.first
                if live == nil { try await Task.sleep(nanoseconds: 100_000_000) }
            }
            let liveConnection = try XCTUnwrap(live)
            XCTAssertEqual(liveConnection.kind, .tcp)
            XCTAssertEqual(liveConnection.destination, "tracked-destination.example:9443")
            XCTAssertEqual(liveConnection.chainName, "Tracked Chain")
            XCTAssertGreaterThan(liveConnection.uploadBytes, 0)
            XCTAssertGreaterThan(liveConnection.downloadBytes, 0)
            XCTAssertNil(liveConnection.endedAt)

            client.close()

            var closed: ConnectionInfo?
            for _ in 0..<40 where closed == nil {
                closed = store.closedConnections.first { $0.id == liveConnection.id }
                if closed == nil { try await Task.sleep(nanoseconds: 100_000_000) }
            }
            let closedConnection = try XCTUnwrap(closed)
            XCTAssertNotNil(closedConnection.endedAt)
            XCTAssertEqual(closedConnection.uploadBytes, liveConnection.uploadBytes)
            XCTAssertFalse(store.liveConnections.contains { $0.id == liveConnection.id })

            store.disconnect()
        }
    }

    // MARK: - Mixed protocol: HTTP alongside SOCKS5 on the same port

    /// Speaks one real HTTP CONNECT tunnel against the local listener,
    /// returning the bytes of its "200 Connection Established" reply so
    /// callers can assert on it precisely. `client` is left connected,
    /// mid-tunnel, for the caller to relay payload bytes over.
    private func openHTTPConnectTunnel(localPort: UInt16, targetHost: String, targetPort: UInt16) async throws -> (client: TCPConn, reply: [UInt8]) {
        let client = TCPConn(host: "127.0.0.1", port: localPort)
        try await client.connect()
        try await client.send(Array("CONNECT \(targetHost):\(targetPort) HTTP/1.1\r\nHost: \(targetHost):\(targetPort)\r\n\r\n".utf8))
        let expectedReply = Array("HTTP/1.1 200 Connection Established\r\n\r\n".utf8)
        let reply = try await client.readExactly(expectedReply.count)
        return (client, reply)
    }

    func testConnectRelaysAnHTTPCONNECTClientJustLikeSOCKS5() async throws {
        let upstream = try FakeEchoUpstream()
        let upstreamPort = try await upstream.start()
        defer { upstream.stop() }

        let store = makeStore()
        let chain = oneHopChain(name: "Test Chain", upstreamPort: upstreamPort)
        store.addChain(chain)
        store.setActiveChain(chain.id)

        let localPort = try await freeEphemeralPort()
        try await withLocalProxyPort(localPort) {
            await store.connect()

            let (client, reply) = try await openHTTPConnectTunnel(localPort: localPort, targetHost: "http-client.example", targetPort: 8443)
            XCTAssertEqual(reply, Array("HTTP/1.1 200 Connection Established\r\n\r\n".utf8))

            let payload = Array("hello through the HTTP CONNECT tunnel".utf8)
            try await client.send(payload)
            let echoed = try await client.readExactly(payload.count)
            client.close()

            XCTAssertEqual(echoed, payload)
            XCTAssertEqual(upstream.receivedRequests, [SOCKS5IncomingRequest(host: "http-client.example", port: 8443)])

            store.disconnect()
        }
    }

    func testConnectRelaysAPlainHTTPRequestRewrittenToOriginForm() async throws {
        let upstream = try FakeEchoUpstream()
        let upstreamPort = try await upstream.start()
        defer { upstream.stop() }

        let store = makeStore()
        let chain = oneHopChain(name: "Test Chain", upstreamPort: upstreamPort)
        store.addChain(chain)
        store.setActiveChain(chain.id)

        let localPort = try await freeEphemeralPort()
        try await withLocalProxyPort(localPort) {
            await store.connect()

            let client = TCPConn(host: "127.0.0.1", port: localPort)
            try await client.connect()
            try await client.send(Array("GET http://plain-http.example:8080/hello?x=1 HTTP/1.1\r\nHost: plain-http.example:8080\r\nProxy-Connection: keep-alive\r\n\r\n".utf8))

            // The fake upstream echoes back exactly what it was sent after
            // its own SOCKS5 CONNECT handshake -- i.e. the origin-form
            // request `LocalProxyServer` reconstructed and replayed.
            let expectedEcho = Array("GET /hello?x=1 HTTP/1.1\r\nHost: plain-http.example:8080\r\n\r\n".utf8)
            let echoed = try await client.readExactly(expectedEcho.count)
            client.close()

            XCTAssertEqual(echoed, expectedEcho)
            XCTAssertEqual(upstream.receivedRequests, [SOCKS5IncomingRequest(host: "plain-http.example", port: 8080)])

            store.disconnect()
        }
    }

    func testConnectHandlesSOCKS5AndHTTPClientsConcurrentlyOnTheSamePort() async throws {
        let upstream = try FakeEchoUpstream()
        let upstreamPort = try await upstream.start()
        defer { upstream.stop() }

        let store = makeStore()
        let chain = oneHopChain(name: "Test Chain", upstreamPort: upstreamPort)
        store.addChain(chain)
        store.setActiveChain(chain.id)

        let localPort = try await freeEphemeralPort()
        try await withLocalProxyPort(localPort) {
            await store.connect()

            async let socksResult: [UInt8] = {
                let client = try await SOCKS5Session.open(
                    server: SOCKS5ServerConfig(host: "127.0.0.1", port: localPort, auth: .none),
                    targetHost: .domain("socks-side.example"),
                    targetPort: 111
                )
                try await client.send(Array("via socks5".utf8))
                let echoed = try await client.receive()
                client.close()
                return echoed
            }()

            async let httpResult: [UInt8] = {
                let (client, _) = try await openHTTPConnectTunnel(localPort: localPort, targetHost: "http-side.example", targetPort: 222)
                try await client.send(Array("via http connect".utf8))
                let echoed = try await client.readExactly(Array("via http connect".utf8).count)
                client.close()
                return echoed
            }()

            let (socksEchoed, httpEchoed) = try await (socksResult, httpResult)
            XCTAssertEqual(socksEchoed, Array("via socks5".utf8))
            XCTAssertEqual(httpEchoed, Array("via http connect".utf8))
            XCTAssertEqual(
                Set(upstream.receivedRequests),
                Set([
                    SOCKS5IncomingRequest(host: "socks-side.example", port: 111),
                    SOCKS5IncomingRequest(host: "http-side.example", port: 222),
                ])
            )

            store.disconnect()
        }
    }

    // MARK: - Concurrency: independent connections, no cross-talk

    func testConcurrentConnectionsToDifferentDestinationsDontCrossTalk() async throws {
        let upstream = try FakeEchoUpstream()
        let upstreamPort = try await upstream.start()
        defer { upstream.stop() }

        let store = makeStore()
        let chain = oneHopChain(name: "Test Chain", upstreamPort: upstreamPort)
        store.addChain(chain)
        store.setActiveChain(chain.id)

        let localPort = try await freeEphemeralPort()
        try await withLocalProxyPort(localPort) {
            await store.connect()

            async let first: [UInt8] = {
                let client = try await SOCKS5Session.open(
                    server: SOCKS5ServerConfig(host: "127.0.0.1", port: localPort, auth: .none),
                    targetHost: .domain("first.example"),
                    targetPort: 111
                )
                try await client.send(Array("first payload".utf8))
                let echoed = try await client.receive()
                client.close()
                return echoed
            }()

            async let second: [UInt8] = {
                let client = try await SOCKS5Session.open(
                    server: SOCKS5ServerConfig(host: "127.0.0.1", port: localPort, auth: .none),
                    targetHost: .domain("second.example"),
                    targetPort: 222
                )
                try await client.send(Array("second payload".utf8))
                let echoed = try await client.receive()
                client.close()
                return echoed
            }()

            let (firstEchoed, secondEchoed) = try await (first, second)
            XCTAssertEqual(firstEchoed, Array("first payload".utf8))
            XCTAssertEqual(secondEchoed, Array("second payload".utf8))
            XCTAssertEqual(
                Set(upstream.receivedRequests),
                Set([
                    SOCKS5IncomingRequest(host: "first.example", port: 111),
                    SOCKS5IncomingRequest(host: "second.example", port: 222),
                ])
            )

            store.disconnect()
        }
    }

    // MARK: - Live hop switch: no dropped connections

    func testSwitchingActiveChainNeverDropsAnInFlightConnection() async throws {
        let upstreamA = try FakeEchoUpstream()
        let portA = try await upstreamA.start()
        defer { upstreamA.stop() }

        let upstreamB = try FakeEchoUpstream()
        let portB = try await upstreamB.start()
        defer { upstreamB.stop() }

        let store = makeStore()
        let chainA = oneHopChain(name: "Chain A", upstreamPort: portA)
        let chainB = oneHopChain(name: "Chain B", upstreamPort: portB)
        store.addChain(chainA)
        store.addChain(chainB)
        store.setActiveChain(chainA.id)

        let localPort = try await freeEphemeralPort()
        try await withLocalProxyPort(localPort) {
            await store.connect()

            // This dial only returns once our relay has already completed its
            // own CONNECT to upstream A -- so by the time `open` returns, the
            // hops for *this* connection are already resolved and snapshotted.
            let clientA = try await SOCKS5Session.open(
                server: SOCKS5ServerConfig(host: "127.0.0.1", port: localPort, auth: .none),
                targetHost: .domain("target-a.example"),
                targetPort: 111
            )

            // Switch the active chain while clientA's relay is already established.
            store.setActiveChain(chainB.id)

            // The in-flight connection must be unaffected by the switch.
            let payloadA = Array("still relaying through A".utf8)
            try await clientA.send(payloadA)
            let echoedA = try await clientA.receive()
            clientA.close()
            XCTAssertEqual(echoedA, payloadA)

            // A brand-new connection opened *after* the switch must use B.
            let clientB = try await SOCKS5Session.open(
                server: SOCKS5ServerConfig(host: "127.0.0.1", port: localPort, auth: .none),
                targetHost: .domain("target-b.example"),
                targetPort: 222
            )
            let payloadB = Array("now relaying through B".utf8)
            try await clientB.send(payloadB)
            let echoedB = try await clientB.receive()
            clientB.close()
            XCTAssertEqual(echoedB, payloadB)

            XCTAssertEqual(upstreamA.receivedRequests, [SOCKS5IncomingRequest(host: "target-a.example", port: 111)])
            XCTAssertEqual(upstreamB.receivedRequests, [SOCKS5IncomingRequest(host: "target-b.example", port: 222)])

            store.disconnect()
        }
    }

    // MARK: - Disconnect

    func testDisconnectRefusesNewDialsAndClosesInFlightConnections() async throws {
        let upstream = try FakeEchoUpstream()
        let upstreamPort = try await upstream.start()
        defer { upstream.stop() }

        let store = makeStore()
        let chain = oneHopChain(name: "Test Chain", upstreamPort: upstreamPort)
        store.addChain(chain)
        store.setActiveChain(chain.id)

        let localPort = try await freeEphemeralPort()
        try await withLocalProxyPort(localPort) {
            await store.connect()

            let client = try await SOCKS5Session.open(
                server: SOCKS5ServerConfig(host: "127.0.0.1", port: localPort, auth: .none),
                targetHost: .domain("mid-transfer.example"),
                targetPort: 333
            )

            store.disconnect()
            XCTAssertFalse(store.isProxyRunning)

            // The connection that was already established observes a close
            // rather than hanging forever.
            do {
                let echoed = try await client.receive(timeout: 5)
                XCTAssertTrue(echoed.isEmpty, "expected a clean EOF, not more data, after disconnect")
            } catch {
                // also acceptable: the peer close surfaces as an error
            }
            client.close()

            // A fresh dial to the now-stopped listener must fail outright.
            do {
                _ = try await SOCKS5Session.open(
                    server: SOCKS5ServerConfig(host: "127.0.0.1", port: localPort, auth: .none),
                    targetHost: .domain("too-late.example"),
                    targetPort: 444,
                    connectTimeout: 3
                )
                XCTFail("expected the dial to fail against a stopped listener")
            } catch {
                // expected
            }
        }
    }

    // MARK: - Port already in use

    func testConnectSurfacesPortInUseError() async throws {
        let occupied = try TCPListener(port: 0)
        try await occupied.start(onAccept: { _ in }, onFailure: { _ in })
        defer { occupied.cancel() }
        let port = try XCTUnwrap(occupied.port)

        let store = makeStore()
        let upstream = try FakeEchoUpstream()
        let upstreamPort = try await upstream.start()
        defer { upstream.stop() }
        let chain = oneHopChain(name: "Test Chain", upstreamPort: upstreamPort)
        store.addChain(chain)
        store.setActiveChain(chain.id)

        await withLocalProxyPort(port) {
            await store.connect()
            XCTAssertFalse(store.isProxyRunning)
            XCTAssertEqual(store.proxyError, "Port \(port) is already in use.")
        }
    }

    // MARK: - SOCKS5 UDP ASSOCIATE, end-to-end through the real local listener

    /// A minimal fake Shadowsocks UDP relay server -- smaller version of
    /// `ChainCoreUDPRelayLiveSocketTests`' own fake (each test target keeps
    /// its own right-sized fixture, same reasoning as `FakeEchoUpstream`'s
    /// own doc comment above): terminal-only (no forwarding), it just echoes
    /// back whatever payload it decrypts, wrapped as if the embedded target
    /// itself had replied.
    private final class FakeShadowsocksUDPEcho {
        private let password: String
        private let cipher: ShadowsocksCipher
        private let listener: UDPListener

        init(password: String, cipher: ShadowsocksCipher) throws {
            self.password = password
            self.cipher = cipher
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
                    let reply = try shadowsocksSealUDPPacket(password: password, cipher: cipher, targetHost: opened.address, targetPort: opened.port, payload: opened.payload)
                    try await client.send(reply, timeout: nil)
                }
            } catch {
                return
            }
        }
    }

    /// Drives the whole path a real SOCKS5-UDP-capable client would: raw
    /// greeting + UDP ASSOCIATE over the control TCP connection (there's no
    /// production `SOCKS5Session` helper for ASSOCIATE -- only CONNECT --
    /// since this codebase's own client side never needs to *originate* one,
    /// so the request/reply bytes are hand-rolled here, RFC 1928 Section 6/7
    /// shape), then real UDP datagrams framed with the public
    /// `socks5UDPDatagram`/`parseSOCKS5UDPDatagram` helpers against the port
    /// the ASSOCIATE reply hands back.
    func testUDPAssociateRelaysADatagramThroughAShadowsocksHop() async throws {
        let echoServer = try FakeShadowsocksUDPEcho(password: "udp-e2e-pw", cipher: .aes256Gcm)
        let echoPort = try await echoServer.start()
        defer { echoServer.stop() }

        let store = makeStore()
        let chain = NamedProxyChain(
            name: "UDP Test Chain",
            hops: [ProxyHop(host: "127.0.0.1", port: echoPort, protocolConfig: .shadowsocks(password: "udp-e2e-pw", cipher: .aes256Gcm))]
        )
        store.addChain(chain)
        store.setActiveChain(chain.id)

        let localPort = try await freeEphemeralPort()
        try await withLocalProxyPort(localPort) {
            await store.connect()

            let control = TCPConn(host: "127.0.0.1", port: localPort)
            try await control.connect()

            // Greeting: offer only NO AUTH, same as every other client here.
            try await control.send([0x05, 0x01, 0x00])
            let greetingReply = try await control.readExactly(2)
            XCTAssertEqual(greetingReply, [0x05, 0x00])

            // UDP ASSOCIATE (CMD 0x03): client's own stated address/port is
            // conventionally ignored (0.0.0.0:0), per `SOCKS5Server.acceptRequest`'s
            // own doc comment.
            try await control.send([0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            let associateReply = try await control.readExactly(10)
            XCTAssertEqual(Array(associateReply[0...3]), [0x05, 0x00, 0x00, 0x01])
            let boundPort = UInt16(associateReply[8]) << 8 | UInt16(associateReply[9])
            XCTAssertNotEqual(boundPort, 0)

            let udp = UDPConn(host: "127.0.0.1", port: boundPort)
            try await udp.connect()

            let datagram = try socks5UDPDatagram(target: .domain("dns.example"), targetPort: 53, payload: Array("what is my ip".utf8))
            try await udp.send(datagram)

            let replyDatagram = try await udp.receiveDatagram(timeout: 10)
            let parsed = try parseSOCKS5UDPDatagram(replyDatagram)
            XCTAssertEqual(parsed.target, .domain("dns.example"))
            XCTAssertEqual(parsed.targetPort, 53)
            XCTAssertEqual(parsed.payload, Array("what is my ip".utf8))

            // The Connections panel should see this ASSOCIATE session as a
            // UDP row with a real destination and non-zero byte counts too --
            // both previously invisible gaps this relay path had (see
            // `LocalProxyServer.relayUDPAssociate`'s doc comment).
            var live: ConnectionInfo?
            for _ in 0..<40 where live == nil {
                live = store.liveConnections.first
                if live == nil { try await Task.sleep(nanoseconds: 100_000_000) }
            }
            let liveConnection = try XCTUnwrap(live)
            XCTAssertEqual(liveConnection.kind, .udp)
            XCTAssertEqual(liveConnection.destination, "dns.example:53")
            XCTAssertEqual(liveConnection.chainName, "UDP Test Chain")
            XCTAssertGreaterThan(liveConnection.uploadBytes, 0)
            XCTAssertGreaterThan(liveConnection.downloadBytes, 0)

            udp.close()
            control.close()
            store.disconnect()
        }
    }

    // MARK: - SOCKS5 UDP ASSOCIATE through a VMess last hop (UDP-over-TCP)

    /// A minimal fake VMess server, UDP mode: decodes the real AEAD
    /// handshake (this client's own command byte is never validated by
    /// the decode, so the same logic works for TCP or UDP requests), then
    /// loops echoing back whatever `[UInt16 BE length][payload]` chunk
    /// arrives -- `TunneledUDPRelay`'s own body-framing convention. Smaller
    /// version of `ChainCoreTests`' `TunneledUDPRelayLiveSocketTests`' own
    /// fake (same "each test target keeps its own right-sized fixture"
    /// reasoning as `FakeShadowsocksUDPEcho` above).
    private final class FakeVMessUDPEcho {
        private let uuid: String
        private let listener: TCPListener
        private var accepted: TCPConn?

        init(uuid: String) throws {
            self.uuid = uuid
            listener = try TCPListener(port: 0)
        }

        func start() async throws -> UInt16 {
            try await listener.start(onAccept: { [weak self] conn in self?.accepted = conn }, onFailure: { _ in })
            return listener.port!
        }

        func stop() { listener.cancel() }

        func run() async throws {
            for _ in 0..<500 where accepted == nil { try await Task.sleep(nanoseconds: 10_000_000) }
            guard let conn = accepted else { throw ProxyError.connectionClosed }
            try await conn.connect()

            let cmdKey = md5(parseUUID(uuid) + cmdKeyMagic)
            let authID = try await conn.readExactly(16, timeout: nil)
            let lengthAndNonce = try await conn.readExactly(18 + 8, timeout: nil)
            let connectionNonce = Array(lengthAndNonce[18..<26])
            let lengthKey = vmessKDF16(key: cmdKey, path: [Array("VMess Header AEAD Key_Length".utf8), authID, connectionNonce])
            let lengthNonce = Array(vmessKDF(key: cmdKey, path: [Array("VMess Header AEAD Nonce_Length".utf8), authID, connectionNonce]).prefix(12))
            let lengthBytes = try aesGCMOpen(key: lengthKey, nonce: lengthNonce, sealed: Array(lengthAndNonce[0..<18]), aad: authID)
            let headerLen = Int(lengthBytes[0]) << 8 | Int(lengthBytes[1])
            let sealedHeader = try await conn.readExactly(headerLen + 16, timeout: nil)
            let requestPlain = try openVMessAEADHeader(key: cmdKey, authID: authID, remainder: lengthAndNonce + sealedHeader)

            let requestBodyIV = Array(requestPlain[1..<17])
            let requestBodyKey = Array(requestPlain[17..<33])
            let responseHeaderByte = requestPlain[33]

            let responseBodyKey = Array(sha256(requestBodyKey).prefix(16))
            let responseBodyIV = Array(sha256(requestBodyIV).prefix(16))
            let header: [UInt8] = [responseHeaderByte, 0, 0, 0]
            let respLengthKey = vmessKDF16(key: responseBodyKey, path: [Array("AEAD Resp Header Len Key".utf8)])
            let respLengthNonce = Array(vmessKDF(key: responseBodyIV, path: [Array("AEAD Resp Header Len IV".utf8)]).prefix(12))
            let sealedRespLength = aesGCMSeal(key: respLengthKey, nonce: respLengthNonce, plaintext: UInt16(header.count).bigEndianBytes, aad: [])
            let respHeaderKey = vmessKDF16(key: responseBodyKey, path: [Array("AEAD Resp Header Key".utf8)])
            let respHeaderNonce = Array(vmessKDF(key: responseBodyIV, path: [Array("AEAD Resp Header IV".utf8)]).prefix(12))
            let sealedRespHeader = aesGCMSeal(key: respHeaderKey, nonce: respHeaderNonce, plaintext: header, aad: [])
            try await conn.send(sealedRespLength + sealedRespHeader, timeout: nil)

            // The `[UInt16 BE length][payload]` datagram frame `TunneledUDPRelay`
            // writes now itself rides inside a real AEAD body chunk (see
            // VMessCore's `sealVMessBodyChunk`/`openVMessBodyChunkPayload`),
            // so this echo needs to decrypt the request-direction chunk before
            // reading the datagram frame, then re-seal it under the
            // response-direction key/IV for the reply -- same handshake-derived
            // pair `VMessSession`'s client side and `ChainCoreTests`'
            // `VMessServerAdapter` both use.
            let chunkLenBytes = try await conn.readExactly(2, timeout: nil)
            let chunkLen = Int(chunkLenBytes[0]) << 8 | Int(chunkLenBytes[1])
            let sealedChunk = try await conn.readExactly(chunkLen, timeout: nil)
            let datagramFrame = try openVMessBodyChunkPayload(key: requestBodyKey, iv: requestBodyIV, counter: 0, sealed: sealedChunk)

            let length = Int(datagramFrame[0]) << 8 | Int(datagramFrame[1])
            let payload = Array(datagramFrame[2..<(2 + length)])

            let echoFrame = UInt16(payload.count).bigEndianBytes + payload
            try await conn.send(sealVMessBodyChunk(key: responseBodyKey, iv: responseBodyIV, counter: 0, plaintext: echoFrame), timeout: nil)
        }
    }

    func testUDPAssociateRelaysADatagramThroughAVMessLastHop() async throws {
        let uuid = "0398d470-bc09-4cd5-889d-3ae4c569b6da"
        let echoServer = try FakeVMessUDPEcho(uuid: uuid)
        let echoPort = try await echoServer.start()
        defer { echoServer.stop() }
        async let serverRun: () = echoServer.run()

        let store = makeStore()
        let chain = NamedProxyChain(
            name: "VMess UDP Test Chain",
            hops: [ProxyHop(host: "127.0.0.1", port: echoPort, protocolConfig: .vmess(uuid: uuid))]
        )
        store.addChain(chain)
        store.setActiveChain(chain.id)

        let localPort = try await freeEphemeralPort()
        try await withLocalProxyPort(localPort) {
            await store.connect()

            let control = TCPConn(host: "127.0.0.1", port: localPort)
            try await control.connect()
            try await control.send([0x05, 0x01, 0x00])
            _ = try await control.readExactly(2)

            try await control.send([0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            let associateReply = try await control.readExactly(10)
            let boundPort = UInt16(associateReply[8]) << 8 | UInt16(associateReply[9])

            let udp = UDPConn(host: "127.0.0.1", port: boundPort)
            try await udp.connect()

            let datagram = try socks5UDPDatagram(target: .domain("real-target.example"), targetPort: 53, payload: Array("vmess udp query".utf8))
            try await udp.send(datagram)

            let replyDatagram = try await udp.receiveDatagram(timeout: 10)
            let parsed = try parseSOCKS5UDPDatagram(replyDatagram)
            XCTAssertEqual(parsed.target, .domain("real-target.example"))
            XCTAssertEqual(parsed.targetPort, 53)
            XCTAssertEqual(parsed.payload, Array("vmess udp query".utf8))

            udp.close()
            control.close()
            store.disconnect()
        }
        try await serverRun
    }
}
