// ShadowsocksDemoCLI
//
// Usage:
//   ssdemo <server-host:port> <password> <cipher> <target-host:port>
//
// <cipher> is one of: aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305
//
// Unlike VMessDemoCLI, this has no built-in default remote server (there's
// no publicly-known Shadowsocks test server to point at), so all four
// arguments are required. See Scripts/integration_test_shadowsocks.sh for a
// self-contained local server + client example.

import Foundation
import ProxyKit
import ShadowsocksCore

@main
struct ShadowsocksDemoCLI {
    static func main() async {
        setvbuf(stdout, nil, _IONBF, 0) // keep log lines and raw relayed bytes in order

        let args = CommandLine.arguments
        guard args.count == 5, let cipher = ShadowsocksCipher(rawValue: args[3]) else {
            print("""
            Usage: ssdemo <server-host:port> <password> <cipher> <target-host:port>
            <cipher> is one of: \(ShadowsocksCipher.allCases.map(\.rawValue).joined(separator: ", "))
            """)
            exit(1)
        }

        let (serverHost, serverPort) = parseHostPort(args[1], defaultPort: 8388)
        let password = args[2]
        let (targetHost, targetPort) = parseHostPort(args[4], defaultPort: 80)

        let server = ShadowsocksServerConfig(host: serverHost, port: serverPort, password: password, cipher: cipher)
        let target = ProxyAddress.parse(targetHost)

        do {
            print("Connecting to shadowsocks server \(serverHost):\(serverPort) (\(cipher.rawValue)) ...")
            let session = try await ShadowsocksSession.open(server: server, targetHost: target, targetPort: targetPort)
            print("Sent target address for \(targetHost):\(targetPort).")

            let httpRequest = "GET / HTTP/1.1\r\nHost: \(targetHost)\r\nConnection: close\r\n\r\n"
            try await session.send(Array(httpRequest.utf8))
            print("Sent HTTP request through the Shadowsocks tunnel. Waiting for response ...")
            print("--- raw bytes from \(targetHost):\(targetPort), relayed through the shadowsocks server ---")

            var totalBytes = 0
            while true {
                let chunk = try await session.receive()
                if chunk.isEmpty { break }
                totalBytes += chunk.count
                FileHandle.standardOutput.write(Data(chunk))
            }
            print("\n--- end of stream (\(totalBytes) bytes) ---")
            session.close()
        } catch {
            print("Shadowsocks demo failed: \(error)")
            exit(1)
        }
    }
}
