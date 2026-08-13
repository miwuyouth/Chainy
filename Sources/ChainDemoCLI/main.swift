// ChainDemoCLI
//
// Usage:
//   chaindemo <hop>... <target-host:port>
//
// Each <hop> is one of:
//   socks5,host,port[,username,password]
//   shadowsocks,host,port,password,cipher
//   vmess,host,port,uuid
//
// Drives ChainCore's ProxyChain.open across an arbitrary ordered list of
// hops (any protocol, any order, any length), then relays a plain HTTP GET
// through the resulting session -- the chain equivalent of
// VMessDemoCLI/ShadowsocksDemoCLI/SOCKS5DemoCLI, which each only ever speak
// one protocol directly to one server.
//
// See Scripts/integration_test_chain.sh for a self-contained example
// chaining real protocol servers (xray-core's vmess/socks/shadowsocks
// inbounds) rather than talking to real-world open proxies.

import Foundation
import ProxyKit
import SOCKS5Core
import ShadowsocksCore
import VMessCore
import ChainCore

private func parseHop(_ spec: String) -> ProxyHop {
    let parts = spec.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
    guard parts.count >= 3, let port = UInt16(parts[2]) else {
        print("Invalid hop spec: \(spec)")
        exit(1)
    }
    let host = parts[1]

    switch parts[0] {
    case "socks5":
        let auth: SOCKS5Auth = parts.count >= 5 ? .usernamePassword(username: parts[3], password: parts[4]) : .none
        return ProxyHop(host: host, port: port, protocolConfig: .socks5(auth: auth))

    case "shadowsocks":
        guard parts.count >= 5, let cipher = ShadowsocksCipher(rawValue: parts[4]) else {
            print("Invalid shadowsocks hop spec (need password,cipher): \(spec)")
            print("cipher is one of: \(ShadowsocksCipher.allCases.map(\.rawValue).joined(separator: ", "))")
            exit(1)
        }
        return ProxyHop(host: host, port: port, protocolConfig: .shadowsocks(password: parts[3], cipher: cipher))

    case "vmess":
        guard parts.count >= 4 else {
            print("Invalid vmess hop spec (need uuid): \(spec)")
            exit(1)
        }
        return ProxyHop(host: host, port: port, protocolConfig: .vmess(uuid: parts[3]))

    default:
        print("Unknown protocol '\(parts[0])' in hop spec: \(spec)")
        exit(1)
    }
}

@main
struct ChainDemoCLI {
    static func main() async {
        setvbuf(stdout, nil, _IONBF, 0) // keep log lines and raw relayed bytes in order

        let args = Array(CommandLine.arguments.dropFirst())
        guard args.count >= 2 else {
            print("""
            Usage: chaindemo <hop>... <target-host:port>

            Each <hop> is one of:
              socks5,host,port[,username,password]
              shadowsocks,host,port,password,cipher
              vmess,host,port,uuid

            Example (3-hop chain: SOCKS5 -> Shadowsocks -> VMess -> target):
              chaindemo socks5,127.0.0.1,28401 shadowsocks,127.0.0.1,28402,mypassword,aes-256-gcm vmess,127.0.0.1,28403,0398d470-bc09-4cd5-889d-3ae4c569b6da example.com:443
            """)
            exit(1)
        }

        let hopSpecs = args.dropLast()
        let (targetHost, targetPort) = parseHostPort(args.last!, defaultPort: 80)
        let hops = hopSpecs.map(parseHop)

        do {
            print("Opening \(hops.count)-hop chain ...")
            let transport = try await ProxyChain.open(hops: hops, finalTargetHost: targetHost, finalTargetPort: targetPort)
            print("Chain established, final target \(targetHost):\(targetPort).")

            let httpRequest = "GET / HTTP/1.1\r\nHost: \(targetHost)\r\nConnection: close\r\n\r\n"
            try await transport.send(Array(httpRequest.utf8), timeout: 10)
            print("Sent HTTP request through the chain. Waiting for response ...")
            print("--- raw bytes from \(targetHost):\(targetPort), relayed through \(hops.count) hop(s) ---")

            var totalBytes = 0
            while true {
                let chunk = try await transport.readAvailable(timeout: 10)
                if chunk.isEmpty { break }
                totalBytes += chunk.count
                FileHandle.standardOutput.write(Data(chunk))
            }
            print("\n--- end of stream (\(totalBytes) bytes) ---")
            transport.close()
        } catch {
            print("Chain demo failed: \(error)")
            exit(1)
        }
    }
}
