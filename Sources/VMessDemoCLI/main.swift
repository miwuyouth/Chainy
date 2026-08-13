// VMessDemoCLI
//
// Usage:
//   vmessdemo [vmess-server-host:port] [uuid] [target-host:port]
//
// All three arguments are optional and fall back to a small built-in
// default (a real, publicly reachable vmess server, tunneling to
// example.com:80) so the binary is runnable with no arguments too.

import Foundation
import ProxyKit
import VMessCore

/// Reads `[server] [uuid] [target]` positional CLI arguments, defaulting to
/// a known-good demo server/target so `vmessdemo` works with no arguments.
func parseArguments() -> (VMessServerConfig, VMessTarget) {
    let args = CommandLine.arguments
    var serverAddr = "35.211.2.124:26182"
    var uuid = "0398d470-bc09-4cd5-889d-3ae4c569b6da"
    var targetAddr = "example.com:80"

    if args.count > 1 { serverAddr = args[1] }
    if args.count > 2 { uuid = args[2] }
    if args.count > 3 { targetAddr = args[3] }

    let (serverHost, serverPort) = parseHostPort(serverAddr, defaultPort: 26182)
    let (targetHost, targetPort) = parseHostPort(targetAddr, defaultPort: 80)

    return (VMessServerConfig(host: serverHost, port: serverPort, uuid: uuid),
            VMessTarget(host: targetHost, port: targetPort))
}

@main
struct VMessDemoCLI {
    static func main() async {
        setvbuf(stdout, nil, _IONBF, 0) // keep log lines and raw relayed bytes in order
        let (server, target) = parseArguments()
        do {
            print("Connecting to vmess server \(server.host):\(server.port) ...")
            let session = try await VMessSession.open(server: server, target: target)
            print("Sent VMess AEAD request header for \(target.host):\(target.port).")

            let httpRequest = "GET / HTTP/1.1\r\nHost: \(target.host)\r\nConnection: close\r\n\r\n"
            try await session.send(Array(httpRequest.utf8))
            print("Sent HTTP request through the VMess tunnel. Waiting for response ...")

            let responseHeader = try await session.readResponseHeader()
            print("VMess response header OK (option byte: \(responseHeader.optionByte)).")
            print("--- raw bytes from \(target.host):\(target.port), relayed through the vmess server ---")

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
            print("VMess demo failed: \(error)")
            exit(1)
        }
    }
}
