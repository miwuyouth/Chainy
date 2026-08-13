// SOCKS5DemoCLI
//
// Usage:
//   socks5demo <server-host:port> <target-host:port> [username password]
//
// Unlike VMessDemoCLI, this has no built-in default remote server (there's
// no publicly-known open SOCKS5 test server to point at, and pointing one at
// an arbitrary open proxy would be irresponsible), so the server and target
// are always required. See Scripts/integration_test_socks5.sh for a
// self-contained local server + client example (both with and without
// username/password auth).

import Foundation
import ProxyKit
import SOCKS5Core

@main
struct SOCKS5DemoCLI {
    static func main() async {
        setvbuf(stdout, nil, _IONBF, 0) // keep log lines and raw relayed bytes in order

        let args = CommandLine.arguments
        guard args.count == 3 || args.count == 5 else {
            print("""
            Usage: socks5demo <server-host:port> <target-host:port> [username password]
            """)
            exit(1)
        }

        let (serverHost, serverPort) = parseHostPort(args[1], defaultPort: 1080)
        let (targetHost, targetPort) = parseHostPort(args[2], defaultPort: 80)
        let auth: SOCKS5Auth = args.count == 5 ? .usernamePassword(username: args[3], password: args[4]) : .none

        let server = SOCKS5ServerConfig(host: serverHost, port: serverPort, auth: auth)
        let target = ProxyAddress.parse(targetHost)

        do {
            print("Connecting to SOCKS5 server \(serverHost):\(serverPort) ...")
            let session = try await SOCKS5Session.open(server: server, targetHost: target, targetPort: targetPort)
            print("CONNECT accepted for \(targetHost):\(targetPort).")

            let httpRequest = "GET / HTTP/1.1\r\nHost: \(targetHost)\r\nConnection: close\r\n\r\n"
            try await session.send(Array(httpRequest.utf8))
            print("Sent HTTP request through the SOCKS5 tunnel. Waiting for response ...")
            print("--- raw bytes from \(targetHost):\(targetPort), relayed through the SOCKS5 server ---")

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
            print("SOCKS5 demo failed: \(error)")
            exit(1)
        }
    }
}
