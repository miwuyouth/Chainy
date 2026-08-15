// SOCKS5UDPRelay.swift
//
// RFC 1928 UDP ASSOCIATE support for a SOCKS5 terminal hop. The association's
// TCP control channel always traverses the preceding TCP chain. Its UDP relay
// packets use a direct UDP socket for a single-hop SOCKS5 chain, or the
// preceding chain's own UDPRelay for a multi-hop chain, preventing a silent
// bypass of earlier hops.

import Foundation
import ProxyKit
import SOCKS5Core

public final class SOCKS5UDPRelay: UDPRelay {
    private enum Carrier {
        case direct(any DatagramTransport)
        case prefix(any UDPRelay)
    }

    private let association: SOCKS5UDPAssociation
    private let carrier: Carrier
    private let relayHost: String
    private let relayPort: UInt16

    private init(association: SOCKS5UDPAssociation, carrier: Carrier, relayHost: String, relayPort: UInt16) {
        self.association = association
        self.carrier = carrier
        self.relayHost = relayHost
        self.relayPort = relayPort
    }

    public static func open(hops: [ProxyHop], connectTimeout: TimeInterval? = 10, logID: String? = nil) async throws -> SOCKS5UDPRelay {
        guard let terminal = hops.last else { throw ProxyChainError.emptyChain }
        guard case .socks5(let auth) = terminal.protocolConfig else {
            throw ProxyChainError.udpUnsupportedLastHop(protocolName: terminal.protocolConfig.logName)
        }

        let prefix = Array(hops.dropLast())
        let control: any ProxyTransport
        if prefix.isEmpty {
            let conn = TCPConn(host: terminal.host, port: terminal.port)
            try await conn.connect(timeout: connectTimeout)
            control = conn
        } else {
            control = try await ProxyChain.open(
                hops: prefix, finalTargetHost: terminal.host, finalTargetPort: terminal.port,
                connectTimeout: connectTimeout, logID: logID
            )
        }

        let association: SOCKS5UDPAssociation
        do {
            association = try await SOCKS5UDPAssociation.open(over: control, auth: auth, timeout: connectTimeout)
        } catch {
            control.close()
            throw error
        }

        // RFC 1928 servers commonly advertise an unspecified address and
        // expect the client to reuse the control server's address.
        let advertisedHost = association.relayAddress.displayHost
        let relayHost = advertisedHost == "0.0.0.0" || advertisedHost == "::" ? terminal.host : advertisedHost
        let relayPort = association.relayPort

        do {
            let carrier: Carrier
            if prefix.isEmpty {
                let udp = UDPConn(host: relayHost, port: relayPort)
                try await udp.connect(timeout: connectTimeout)
                carrier = .direct(udp)
            } else {
                carrier = .prefix(try await ProxyChain.openUDPRelay(hops: prefix, connectTimeout: connectTimeout, logID: logID))
            }
            return SOCKS5UDPRelay(association: association, carrier: carrier, relayHost: relayHost, relayPort: relayPort)
        } catch {
            association.close()
            throw error
        }
    }

    public func send(targetHost: String, targetPort: UInt16, payload: [UInt8], timeout: TimeInterval?) async throws {
        let packet = try socks5UDPDatagram(target: ProxyAddress.parse(targetHost), targetPort: targetPort, payload: payload)
        switch carrier {
        case .direct(let transport):
            try await transport.send(packet, timeout: timeout)
        case .prefix(let relay):
            try await relay.send(targetHost: relayHost, targetPort: relayPort, payload: packet, timeout: timeout)
        }
    }

    public func receive(timeout: TimeInterval?) async throws -> (fromHost: String, fromPort: UInt16, payload: [UInt8]) {
        let packet: [UInt8]
        switch carrier {
        case .direct(let transport):
            packet = try await transport.receiveDatagram(timeout: timeout)
        case .prefix(let relay):
            packet = try await relay.receive(timeout: timeout).payload
        }
        let decoded = try parseSOCKS5UDPDatagram(packet)
        return (decoded.target.displayHost, decoded.targetPort, decoded.payload)
    }

    public func close() {
        switch carrier {
        case .direct(let transport): transport.close()
        case .prefix(let relay): relay.close()
        }
        association.close()
    }
}
