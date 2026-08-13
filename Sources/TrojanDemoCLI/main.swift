// TrojanDemoCLI
//
// Usage:
//   trojandemo <server-host:port> <password> <target-host:port> [sni] [allowInsecure] [tls]
//
// Unlike VMessDemoCLI, this has no built-in default remote server (there's
// no publicly-known Trojan test server to point at), so the server, password,
// and target are always required. <sni> defaults to the server host;
// <allowInsecure> (pass "1" or "true") skips TLS certificate validation, for
// a self-signed test server. <tls> defaults to "1" (Trojan's own design
// implies TLS); pass "0" for the rarer real-world node that runs the trojan
// handshake over plain TCP instead (a `security=none` subscription link) --
// appended at the end, after the two existing TLS-only options, rather than
// inserted before them, so Scripts/integration_test_trojan.sh's existing
// positional calls (which never pass it) keep meaning exactly what they did
// before this option existed. See that script for a self-contained local
// server + client example.

import Foundation
import ProxyKit
import TrojanCore

@main
struct TrojanDemoCLI {
    static func main() async {
        setvbuf(stdout, nil, _IONBF, 0) // keep log lines and raw relayed bytes in order

        let args = CommandLine.arguments
        guard args.count >= 4 else {
            print("""
            Usage: trojandemo <server-host:port> <password> <target-host:port> [sni] [allowInsecure] [tls]
            """)
            exit(1)
        }

        let (serverHost, serverPort) = parseHostPort(args[1], defaultPort: 443)
        let password = args[2]
        let (targetHost, targetPort) = parseHostPort(args[3], defaultPort: 80)
        let sni = args.count > 4 ? args[4] : nil
        let allowInsecure = args.count > 5 && (args[5] == "1" || args[5] == "true")
        let tls = args.count <= 6 || args[6] == "1" || args[6] == "true"

        let server = TrojanServerConfig(host: serverHost, port: serverPort, password: password, tls: tls, sni: sni, allowInsecure: allowInsecure)
        let target = ProxyAddress.parse(targetHost)

        do {
            print("Connecting to trojan server \(serverHost):\(serverPort)\(tls ? " (TLS, sni \(sni ?? serverHost))" : " (no TLS)") ...")
            let session = try await TrojanSession.open(server: server, targetHost: target, targetPort: targetPort)
            print("Sent credential + CONNECT header for \(targetHost):\(targetPort).")

            let httpRequest = "GET / HTTP/1.1\r\nHost: \(targetHost)\r\nConnection: close\r\n\r\n"
            try await session.send(Array(httpRequest.utf8))
            print("Sent HTTP request through the Trojan tunnel. Waiting for response ...")
            print("--- raw bytes from \(targetHost):\(targetPort), relayed through the trojan server ---")

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
            print("Trojan demo failed: \(error)")
            exit(1)
        }
    }
}
