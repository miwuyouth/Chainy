import SwiftUI
import ShadowsocksCore
import VMessCore

/// The protocol-dependent field set for editing one `HopDraft`: a protocol
/// picker plus whichever host/port/credential fields that protocol needs.
/// Meant to be dropped inside a parent `Form`.
struct HopFieldsForm: View {
    @Binding var draft: HopDraft

    var body: some View {
        Picker("Protocol", selection: $draft.kind) {
            ForEach(HopProtocolKind.allCases) { kind in
                Text(kind.label).tag(kind)
            }
        }

        TextField("Host", text: $draft.host)
            .accessibilityIdentifier("hopForm.host")
        TextField("Port (1–65535)", text: $draft.port)
            .accessibilityIdentifier("hopForm.port")

        switch draft.kind {
        case .socks5, .http:
            TextField("Username (optional)", text: $draft.username)
            SecureField("Password (optional)", text: $draft.password)

        case .shadowsocks:
            SecureField(draft.cipher.is2022Edition ? "Base64 PSK (2022 edition)" : "Password", text: $draft.password)
            Picker("Cipher", selection: $draft.cipher) {
                ForEach(ShadowsocksCipher.allCases, id: \.self) { cipher in
                    Text(cipher.rawValue).tag(cipher)
                }
            }

        case .vmess:
            TextField("UUID", text: $draft.uuid)
            Picker("Body encryption", selection: $draft.vmessSecurity) {
                ForEach(VMessSecurity.allCases, id: \.self) { security in
                    Text(security.rawValue).tag(security)
                }
            }
            Toggle("Chunk length masking", isOn: $draft.vmessBodyOptions.chunkMasking)
            Toggle("Global padding", isOn: $draft.vmessBodyOptions.globalPadding)
                .disabled(!draft.vmessBodyOptions.chunkMasking)
            Toggle("Authenticated length (server must enable experiment)", isOn: $draft.vmessBodyOptions.authenticatedLength)
            Toggle("Use TLS", isOn: $draft.tls)
            if draft.tls {
                TextField("SNI (optional, defaults to host)", text: $draft.sni)
                Toggle("Allow insecure (skip certificate verification)", isOn: $draft.allowInsecure)
            }
            webSocketFields

        case .trojan:
            SecureField("Password", text: $draft.password)
            Toggle("Use TLS", isOn: $draft.tls)
            if draft.tls {
                TextField("SNI (optional, defaults to host)", text: $draft.sni)
                Toggle("Allow insecure (skip certificate verification)", isOn: $draft.allowInsecure)
            }
            webSocketFields

        case .vless:
            TextField("UUID", text: $draft.uuid)
            Toggle("Use TLS", isOn: $draft.tls)
            if draft.tls {
                TextField("SNI (optional, defaults to host)", text: $draft.sni)
                Toggle("Allow insecure (skip certificate verification)", isOn: $draft.allowInsecure)
            }
            webSocketFields
        }
    }

    /// Shared by vmess/vless/trojan: opts into wrapping the connection in a
    /// WebSocket tunnel -- between TLS (if any) and the protocol's own
    /// handshake -- at a given path, disguising the traffic as ordinary
    /// HTTP(S) behind a CDN. Mirrors the same toggle-gates-fields shape the
    /// TLS block above already uses.
    @ViewBuilder
    private var webSocketFields: some View {
        Toggle("Use WebSocket (ws)", isOn: $draft.useWebSocket)
        if draft.useWebSocket {
            TextField("Path (e.g. /ray)", text: $draft.wsPath)
            TextField("Host header (optional, defaults to SNI/host)", text: $draft.wsHostHeader)
        }
    }
}
