// LocalNetworkAddress.swift
//
// Small lookup for "what IP would another device on this LAN dial to reach
// me" -- purely a display helper for the Dashboard's connection card when
// Allow LAN Connections is on; the listener itself binds to all interfaces
// regardless of which one this happens to surface (see TCPListener.init).

import Foundation

enum LocalNetworkAddress {
    /// The first non-loopback IPv4 address on a Wi-Fi/Ethernet interface
    /// (`en*` -- macOS's naming for those, as opposed to `lo0`/`utun*`/etc.),
    /// or `nil` if none is up right now (e.g. offline).
    static func primaryIPv4() -> String? {
        var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddrPtr) == 0, let firstAddr = ifaddrPtr else { return nil }
        defer { freeifaddrs(ifaddrPtr) }

        for ptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
            let interface = ptr.pointee
            guard let addr = interface.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET) else { continue }

            let flags = Int32(interface.ifa_flags)
            guard (flags & IFF_UP) == IFF_UP, (flags & IFF_LOOPBACK) == 0 else { continue }
            guard String(cString: interface.ifa_name).hasPrefix("en") else { continue }

            var hostBuffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let result = getnameinfo(addr, socklen_t(addr.pointee.sa_len), &hostBuffer, socklen_t(hostBuffer.count), nil, 0, NI_NUMERICHOST)
            guard result == 0 else { continue }
            return String(cString: hostBuffer)
        }
        return nil
    }
}
