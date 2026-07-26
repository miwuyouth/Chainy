# Chainy

[![Latest release](https://img.shields.io/github/v/release/miwuyouth/Chainy)](https://github.com/miwuyouth/Chainy/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/miwuyouth/Chainy/total)](https://github.com/miwuyouth/Chainy/releases)
[![Last commit](https://img.shields.io/github/last-commit/miwuyouth/Chainy)](https://github.com/miwuyouth/Chainy/commits/main)
[![Issues](https://img.shields.io/github/issues/miwuyouth/Chainy)](https://github.com/miwuyouth/Chainy/issues)
![Platform](https://img.shields.io/badge/platform-macOS%2013%2B-blue)
![Arch](https://img.shields.io/badge/arch-Apple%20Silicon%20%7C%20Intel-lightgrey)
![License](https://img.shields.io/badge/license-proprietary-lightgrey)

A native macOS proxy-chaining client — build multi-hop chains across **VMess, Trojan, Shadowsocks, VLESS, SOCKS5, and HTTP** proxies, with full UDP relay support. Universal binary for Apple Silicon and Intel.

> Compiled releases only for now — the source isn't public yet. See [Releases](../../releases) for the changelog.

## Features

- **Chain Builder** — visually chain multiple hops between client and destination
- **Subscription import** — pull nodes from Clash / V2Ray subscription URLs
- **Live stats** — latency, bandwidth, traffic graph, timeout rate
- **Auto-optimize** — automatically switches to the fastest chain
- **UDP relay** across all supported protocols

## Screenshots

| Overview | Chain Builder | Nodes |
|---|---|---|
| ![Overview](docs/screenshots/overview.png) | ![Chain Builder](docs/screenshots/chain-builder.png) | ![Nodes](docs/screenshots/nodes.png) |

## Download

Grab the latest `.dmg` from the [Releases](../../releases) page.

## Install

1. Open the dmg, drag **Chainy.app** into the **Applications** shortcut inside it.
2. See "First launch" below — Gatekeeper will block it on first open since this build isn't notarized yet.

## First launch (unsigned build)

This release is **ad-hoc signed only**, not notarized by Apple. macOS may say it's "damaged" or from an "unidentified developer" — that's expected. Do one of:

- **Right-click (Control-click) `Chainy.app` → Open**, then confirm **Open** in the dialog. Only needed once.
- If macOS says the app "is damaged and can't be opened," run in Terminal, then reopen:
  ```
  xattr -cr /Applications/Chainy.app
  ```
- Or: **System Settings → Privacy & Security** → scroll down → **Open Anyway**.

## Usage

1. **Nodes** — click *Add Node* to add one manually, or *Import from Clipboard* to pull in a Clash/V2Ray subscription URL.
2. **Chain Builder** — click *+* to add hops between client and destination, name the chain, click *Save Chain*.
3. **Overview** — select a saved chain and click *Connect*. Turn on *Auto-optimize* to have it automatically switch to whichever saved chain is fastest.
4. **Point your system/browser proxy at Chainy** — once connected, it listens locally on `127.0.0.1:1080` as a mixed SOCKS5 + HTTP proxy (auto-detected, no need to pick one). The port is configurable in **Settings**.

## Feedback

Found a bug or have a feature request? Please open an [Issue](../../issues) — include your macOS version and, if it crashed, the crash log if available.
