# Chainy

macOS proxy-chaining client — VMess / Trojan / Shadowsocks / VLESS / SOCKS5 / HTTP, with UDP relay support. Universal binary (Apple Silicon + Intel), macOS 13+.

This repository hosts **compiled releases only** — the source is not public yet.

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

## Feedback

Found a bug or have a feature request? Please open an [Issue](../../issues) — include your macOS version and, if it crashed, the crash log if available.
