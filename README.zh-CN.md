# Chainy

[English](README.md)

**面向 macOS 的可视化链式代理构建工具。使用已有节点组合多跳线路，不再手写 Xray 或 sing-box 配置。**

Chainy 在本机运行，可将 VMess、Trojan、Shadowsocks、VLESS、SOCKS5 和 HTTP 节点组成有序的多跳 TCP 线路，并提供订阅导入、兼容模式下的 UDP 转发、实时连接统计和线路自动选择。

## 截图

| 总览 | 链路构建 | 节点 |
|---|---|---|
| ![总览](docs/screenshots/overview.png) | ![链路构建](docs/screenshots/chain-builder.png) | ![节点](docs/screenshots/nodes.png) |

## 下载

从 [GitHub Releases](https://github.com/miwuyouth/Chainy/releases/latest) 下载最新 `.dmg`，打开后将 Chainy 拖入“应用程序”。

### 系统要求

- macOS 13 Ventura 或更高版本
- Apple Silicon 或 Intel Mac

### 关于目前未公证的版本

项目目前没有付费 Apple Developer 账号，因此下载版尚未经过 Apple notarization。源码和构建配置已经公开，你可以检查代码或自行构建。

首次启动请尝试：**按住 Control 点击 Chainy → 打开 → 再次确认打开**。如果仍被拦截，请前往 **系统设置 → 隐私与安全性 → 仍要打开**。终端处理方式放在[故障排除文档](docs/TROUBLESHOOTING.md)中。

> **当前限制：** Chainy 会提供本地 SOCKS5/HTTP 代理，但暂时不会自动修改 macOS 系统代理设置。

## 快速开始

1. 打开 **Nodes** 手动添加节点；或者复制 Clash/V2Ray 订阅地址或受支持的分享链接，再点击 **Import from Clipboard**。
2. 打开 **Chain Builder**，按顺序添加节点，命名并保存线路。
3. 在 **Overview** 选择线路，然后点击 **Connect**。
4. 将系统或浏览器代理手动设置为 `127.0.0.1:1080`。端口可以在设置中修改，同时支持 SOCKS5 和 HTTP。
5. 使用结束后断开 Chainy，并恢复之前手动修改的代理设置。

## 它解决什么问题？

大多数代理客户端只选择一个节点，而 Chainy 专注于更窄的场景：直观地创建、检查、比较和切换多跳线路。

```text
你的 Mac -> 可访问的入口节点 -> 稳定中转/出口节点 -> 目标网站
```

适合以下需求：

- 将可访问的入口节点与指定出口节点组合；
- 保存并比较多条链式线路；
- 复用 Clash 或 V2Ray 订阅中的已有节点；
- 不写配置文件，也能查看延迟、吞吐、流量和超时情况。

## 主要功能

- **可视化 Chain Builder**：将受支持的协议组成有序的多跳 TCP 线路
- **订阅导入**：从剪贴板导入 Clash YAML 订阅和受支持的 V2Ray 风格链接
- **混合本地代理**：同一可配置端口同时接受 SOCKS5 和 HTTP 客户端
- **兼容模式 UDP 转发**：在末跳协议及整条线路支持时转发 UDP
- **诊断与监控**：查看延迟、带宽、实时流量、连接记录和超时率
- **自动优化**：定期测试已保存线路，并选择测量结果最好的链
- **本地配置**：无需账号，没有统计分析和 Chainy 云服务
- **原生 macOS 应用**：使用 Swift/SwiftUI 开发，发布包支持 Apple Silicon 和 Intel

## 协议兼容性

下列协议都可以作为 TCP 节点使用，额外传输方式和 UDP 末跳能力有所不同：

| 协议 | TCP 节点 | WebSocket / TLS | 作为 UDP 末跳 |
|---|:---:|:---:|---|
| VMess | ✓ | WS 和可选 TLS | 实验性；尚未与真实 VMess 服务端验证分帧兼容性 |
| VLESS | ✓ | WS 和可选 TLS | ✓ |
| Trojan | ✓ | WS 和可选 TLS | ✓ |
| Shadowsocks | ✓ | — | 仅限整条线路全部为 Shadowsocks；2022 cipher 仅支持 TCP |
| SOCKS5 | ✓ | — | 暂不支持作为 UDP 末跳 |
| HTTP | ✓ | — | 不支持 |

支持导入 Clash YAML，以及 `ss://`、`vmess://`、`trojan://`、`vless://` 和 `http://` 链接。REALITY、XTLS Vision、gRPC、HTTP/2、QUIC、Shadowsocks 插件、Hysteria、TUIC 和 SSR 等不受支持的内容会在导入时明确报告，而不是静默接受。

Chainy 仍处于早期阶段。正式依赖前请测试自己的协议组合、查看当前 [Issues](https://github.com/miwuyouth/Chainy/issues)，并保留其他恢复网络访问的方式。

## 从源码构建

源码构建需要 Xcode 15 或更高版本，以及 [XcodeGen](https://github.com/yonaskolb/XcodeGen)：

```bash
git clone https://github.com/miwuyouth/Chainy.git
cd Chainy
brew install xcodegen
xcodegen generate
open Chainy.xcodeproj
```

在 Xcode 中选择 `Chainy` scheme 后运行。Debug 构建使用 ad-hoc 签名，不需要付费开发者账号。测试和开发流程请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 隐私、安全与合理使用

Chainy 只是客户端，不提供代理节点或订阅服务。请仅使用你有权访问的节点，并遵守所在地法律及相关服务条款。

Chainy 没有统计分析或自有后端。代理凭据和订阅地址会保存在当前用户的 Application Support 目录。连接诊断会通过所选线路访问 Google 和 Tele2 的测试地址。使用敏感配置前请阅读 [PRIVACY.md](PRIVACY.md) 和 [SECURITY.md](SECURITY.md)。

## 参与贡献

欢迎提交 Bug、协议兼容性反馈、文档改进和范围清晰的 Pull Request。详情见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

Chainy 使用 [MIT License](LICENSE) 开源。
