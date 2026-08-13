// VLESSDemoCLI
//
// Usage:
//   vlessdemo <server-host:port> <uuid> <target-host:port> [tls] [sni] [allowInsecure]
//
// <tls> ("1"/"true") wraps the connection in TLS before sending the VLESS
// request header -- the common "VLESS + TLS" deployment; omitted or "0"
// sends the request (and the fully unencrypted body that follows) directly,
// matching VMessDemoCLI's Security=none-style bare connection. <sni>
// defaults to the server host; <allowInsecure> ("1"/"true") skips TLS
// certificate validation, for a self-signed test server.

import Foundation
import ProxyKit
import VLESSCore

@main
struct VLESSDemoCLI {
    static func main() async {
        setvbuf(stdout, nil, _IONBF, 0) // keep log lines and raw relayed bytes in order

        let args = CommandLine.arguments
        guard args.count >= 4 else {
            print("""
            Usage: vlessdemo <server-host:port> <uuid> <target-host:port> [tls] [sni] [allowInsecure]
            """)
            exit(1)
        }

        let (serverHost, serverPort) = parseHostPort(args[1], defaultPort: 443)
        let uuid = args[2]
        let (targetHost, targetPort) = parseHostPort(args[3], defaultPort: 80)
        let tls = args.count > 4 && (args[4] == "1" || args[4] == "true")
        let sni = args.count > 5 ? args[5] : nil
        let allowInsecure = args.count > 6 && (args[6] == "1" || args[6] == "true")

        let server = VLESSServerConfig(host: serverHost, port: serverPort, uuid: uuid, tls: tls, sni: sni, allowInsecure: allowInsecure)
        let target = VLESSTarget(host: targetHost, port: targetPort)

        do {
            print("Connecting to vless server \(serverHost):\(serverPort)\(tls ? " (TLS, sni \(sni ?? serverHost))" : "") ...")
            let session = try await VLESSSession.open(server: server, target: target)
            print("Sent VLESS request header for \(targetHost):\(targetPort).")

            let httpRequest = "GET / HTTP/1.1\r\nHost: \(targetHost)\r\nConnection: close\r\n\r\n"
            try await session.send(Array(httpRequest.utf8))
            print("Sent HTTP request through the VLESS tunnel. Waiting for response ...")
            print("--- raw bytes from \(targetHost):\(targetPort), relayed through the vless server ---")

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
            print("VLESS demo failed: \(error)")
            exit(1)
        }
    }
}
