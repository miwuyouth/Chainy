# Chainy

[简体中文](README.zh-CN.md)

[![CI](https://github.com/miwuyouth/Chainy/actions/workflows/ci.yml/badge.svg)](https://github.com/miwuyouth/Chainy/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/miwuyouth/Chainy)](https://github.com/miwuyouth/Chainy/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/macOS-13%2B-black)

**A visual proxy-chain builder for macOS. Turn existing nodes into multi-hop routes without writing Xray or sing-box configuration files.**

Chainy runs locally and combines VMess, Trojan, Shadowsocks, VLESS, SOCKS5, and HTTP hops into ordered TCP routes. It includes subscription import, compatible UDP relay modes, live connection statistics, and automatic chain selection.

## Screenshots

### Build multi-hop routes visually

<p align="center">
  <img src="docs/screenshots/chain-builder.png" alt="Chainy visual chain builder showing a two-hop route" width="900">
</p>

| Monitor the active route | Manage imported nodes |
|---|---|
| ![Chainy overview with live connection statistics](docs/screenshots/overview.png) | ![Chainy node library](docs/screenshots/nodes.png) |

## Download

Download the latest `.dmg` from [GitHub Releases](https://github.com/miwuyouth/Chainy/releases/latest), open it, and drag Chainy into Applications.

### System requirements

- macOS 13 Ventura or later
- Apple Silicon or Intel Mac

### About the current unsigned build

The project does not currently have a paid Apple Developer account, so the downloadable build is not notarized. The source and build configuration are public so you can inspect or build the app yourself.

On first launch, try **Control-click Chainy → Open → Open**. If macOS still blocks it, go to **System Settings → Privacy & Security** and choose **Open Anyway**. The terminal workaround is documented in [Troubleshooting](docs/TROUBLESHOOTING.md).

> **Current limitation:** Chainy exposes a local SOCKS5/HTTP proxy but does not yet configure macOS system proxy settings automatically.

## Quick start

1. Open **Nodes** and add a node, or copy a Clash/V2Ray subscription URL or supported share link and choose **Import from Clipboard**.
2. Open **Chain Builder**, add the hops in order, name the chain, and save it.
3. Open **Overview**, select the chain, and choose **Connect**.
4. Configure your system or browser to use `127.0.0.1:1080`. The port is configurable in Settings; the listener accepts SOCKS5 and HTTP automatically.
5. When finished, disconnect Chainy and restore any proxy setting you changed manually.

## Why Chainy?

Most proxy clients select one node. Chainy is focused on a narrower job: making routes such as the following easy to build, inspect, compare, and switch:

```text
Your Mac -> accessible entry node -> stable relay/exit -> destination
```

Use it when you want to:

- combine an accessible entry node with a preferred exit node;
- compare several saved multi-hop routes;
- reuse nodes from Clash or V2Ray subscriptions;
- inspect latency, throughput, traffic, and timeout behavior without maintaining configuration files by hand.

## Features

- **Visual Chain Builder** — arrange supported protocols into ordered multi-hop TCP routes
- **Subscription import** — import Clash YAML subscriptions and supported V2Ray-style links from the clipboard
- **Mixed local proxy** — accept SOCKS5 and HTTP clients on the same configurable port
- **Compatible UDP relay** — relay UDP when the terminal hop and chain composition support it
- **Diagnostics** — inspect latency, bandwidth, live traffic, connection history, and timeout rate
- **Auto-optimize** — periodically test saved chains and select the best measured route
- **Local configuration** — no account, analytics, or Chainy-operated cloud service
- **Native macOS app** — Swift and SwiftUI, with universal releases for Apple Silicon and Intel

## Protocol compatibility

All listed protocols can be used as TCP hops. Additional transport and terminal-hop capabilities vary:

| Protocol | TCP hop | WebSocket / TLS | UDP as terminal hop |
|---|:---:|:---:|---|
| VMess | ✓ | WS and optional TLS | ✓; verified against real Xray-core |
| VLESS | ✓ | WS and optional TLS | ✓ |
| Trojan | ✓ | WS and optional TLS | ✓ |
| Shadowsocks | ✓ | — | Only when every hop is Shadowsocks; 2022 ciphers are TCP-only |
| SOCKS5 | ✓ | — | Not currently supported as the terminal UDP hop |
| HTTP | ✓ | — | Not supported |

Supported imports include Clash YAML and `ss://`, `vmess://`, `trojan://`, `vless://`, and `http://` links. Unsupported entries—such as REALITY, XTLS Vision, gRPC, HTTP/2, QUIC, Shadowsocks plugins, Hysteria, TUIC, and SSR—are reported during import instead of being silently accepted.

Chainy is early-stage software. Test your own protocol combination before depending on it, review the current [issues](https://github.com/miwuyouth/Chainy/issues), and keep another way to restore network access.

## Build from source

Building requires Xcode 15 or later and [XcodeGen](https://github.com/yonaskolb/XcodeGen):

```bash
git clone https://github.com/miwuyouth/Chainy.git
cd Chainy
brew install xcodegen
xcodegen generate
open Chainy.xcodeproj
```

In Xcode, select the `Chainy` scheme and run the app. Debug builds use ad-hoc signing and do not require a paid developer account. See [CONTRIBUTING.md](CONTRIBUTING.md) for tests and the development workflow.

## Privacy, security, and responsible use

Chainy is a client only; it does not provide proxy servers or subscriptions. Use only nodes you are authorized to access and follow the laws and policies that apply to you.

Chainy has no analytics or Chainy-operated backend. Configurations, including proxy credentials and subscription URLs, are stored locally in your user Application Support directory. Diagnostics may contact Google and Tele2 test endpoints through the selected chain. Read [PRIVACY.md](PRIVACY.md) and [SECURITY.md](SECURITY.md) before using sensitive configurations.

## Contributing

Bug reports, protocol compatibility reports, documentation improvements, and focused pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and use the issue templates.

## License

Chainy is released under the [MIT License](LICENSE).
