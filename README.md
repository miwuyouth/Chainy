# Chainy

[简体中文](README.zh-CN.md)

[![CI](https://github.com/miwuyouth/Chainy/actions/workflows/ci.yml/badge.svg)](https://github.com/miwuyouth/Chainy/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/miwuyouth/Chainy)](https://github.com/miwuyouth/Chainy/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/miwuyouth/Chainy/total)](https://github.com/miwuyouth/Chainy/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/macOS-13%2B-black)

**A visual proxy-chain builder for macOS. Turn existing nodes into multi-hop routes without writing Xray or sing-box configuration files.**

Chainy runs locally and supports VMess, Trojan, Shadowsocks, VLESS, SOCKS5, and HTTP hops in any order. It includes subscription import, UDP relay, live connection statistics, and automatic chain selection.

> [!IMPORTANT]
> Chainy does not provide proxy servers or subscription services. You must supply nodes that you are authorized to use and comply with the laws and policies that apply to you.

## Why Chainy?

Most proxy clients select one node. Chainy is focused on a narrower job: making routes such as the following easy to build, inspect, and switch:

```text
Your Mac -> local entry node -> stable relay -> destination
```

Use it when you want to:

- combine an accessible entry node with a preferred exit node;
- compare several saved multi-hop routes;
- reuse nodes from Clash or V2Ray subscriptions;
- inspect latency, throughput, traffic, and timeout behavior without maintaining configuration files by hand.

## Features

- **Visual Chain Builder** — arrange any number of supported hops in any order
- **Subscription import** — import Clash YAML and V2Ray-style links from the clipboard
- **Mixed local proxy** — SOCKS5 and HTTP on the same configurable port
- **UDP relay** — relay UDP across supported chain combinations
- **Diagnostics** — latency, bandwidth, live traffic, connection history, and timeout rate
- **Auto-optimize** — periodically test saved chains and select the best measured route
- **Local configuration** — no account, analytics, or Chainy-operated cloud service
- **Native macOS app** — Swift and SwiftUI, universal release for Apple Silicon and Intel

## Screenshots

| Overview | Chain Builder | Nodes |
|---|---|---|
| ![Overview](docs/screenshots/overview.png) | ![Chain Builder](docs/screenshots/chain-builder.png) | ![Nodes](docs/screenshots/nodes.png) |

## Requirements

- macOS 13 Ventura or later
- Xcode 15 or later when building from source
- [XcodeGen](https://github.com/yonaskolb/XcodeGen) when generating the Xcode project

## Install a release

Download the latest `.dmg` from [GitHub Releases](https://github.com/miwuyouth/Chainy/releases/latest), open it, and drag Chainy into Applications.

### About the current unsigned build

The project does not currently have a paid Apple Developer account, so the downloadable build is not notarized. The source and build configuration are public so you can inspect or build the app yourself.

On first launch, try **Control-click Chainy → Open → Open**. If macOS still blocks it, go to **System Settings → Privacy & Security** and choose **Open Anyway**. The terminal workaround is documented in [Troubleshooting](docs/TROUBLESHOOTING.md).

## Build from source

```bash
git clone https://github.com/miwuyouth/Chainy.git
cd Chainy
brew install xcodegen
xcodegen generate
open Chainy.xcodeproj
```

In Xcode, select the `Chainy` scheme and run the app. Debug builds use ad-hoc signing and do not require a paid developer account.

Core package tests can be run without generating the Xcode project:

```bash
swift test --skip InteropTests
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow and optional integration tests.

## Publish a release

Release packaging is automated by GitHub Actions. After the release commit is on `main`, create and push a semantic version tag:

```bash
git tag v0.2.0
git push origin v0.2.0
```

The Release workflow tests the tagged source, builds an ad-hoc-signed universal app for Apple Silicon and Intel, creates `Chainy-0.2.0.dmg` and its SHA-256 checksum, then publishes both files to a new GitHub Release. The tag must point to a clean commit and use the `vX.Y.Z` format.

To build the same artifacts locally from an already tagged commit:

```bash
Scripts/build_release.sh
```

## Quick start

1. Open **Nodes** and add a node, or copy a Clash/V2Ray subscription URL and choose **Import from Clipboard**.
2. Open **Chain Builder**, add the hops in order, name the chain, and save it.
3. Open **Overview**, select the chain, and choose **Connect**.
4. Configure your system or browser to use `127.0.0.1:1080`. The port is configurable in Settings; the listener accepts SOCKS5 and HTTP automatically.
5. When finished, disconnect Chainy and restore any proxy setting you changed manually.

> Chainy does not yet change macOS system proxy settings automatically. This is a known onboarding limitation and is on the roadmap.

## Supported formats and limitations

Supported outbound hops include VMess, Trojan, Shadowsocks, VLESS, SOCKS5, and HTTP. Transport and cipher support varies by protocol; unsupported subscription entries are reported during import instead of being silently accepted.

Chainy is early-stage software. Before depending on it, review the current [issues](https://github.com/miwuyouth/Chainy/issues), test your own protocol combination, and keep another way to restore network access.

## Privacy and security

Chainy has no analytics or Chainy-operated backend. Configurations, including proxy credentials and subscription URLs, are stored locally in your user Application Support directory. Diagnostics may contact Google and Tele2 test endpoints through the selected chain. Read [PRIVACY.md](PRIVACY.md) and [SECURITY.md](SECURITY.md) before using sensitive configurations.

## Contributing

Bug reports, protocol compatibility reports, documentation improvements, and focused pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and use the issue templates.

## License

Chainy is released under the [MIT License](LICENSE).
