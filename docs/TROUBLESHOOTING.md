# Troubleshooting

## macOS says Chainy cannot be opened

The current release is ad-hoc signed and not notarized because the project does not yet have a paid Apple Developer account.

Try these options in order:

1. Control-click Chainy in Applications, choose **Open**, then confirm **Open**.
2. Open **System Settings → Privacy & Security**, scroll to the security message about Chainy, and choose **Open Anyway**.
3. Build Chainy from source using the instructions in the README.

As a last resort, after verifying that the app came from the official GitHub release, remove the downloaded quarantine attribute:

```bash
xattr -dr com.apple.quarantine /Applications/Chainy.app
```

This reduces a macOS security protection. Do not run it against an app obtained from another source.

## Connected, but applications have no traffic

Chainy currently exposes a local mixed SOCKS5/HTTP proxy but does not change macOS system proxy settings automatically. Configure the application or system to use `127.0.0.1:1080`, or the custom port selected in Chainy Settings.

Check that:

- the selected chain is connected;
- the local port is not already used by another process;
- your browser or system proxy uses the same port;
- every node supports the transport and settings imported by Chainy;
- LAN access is enabled only when another device needs to connect.

## Import skipped some nodes

Subscription formats often contain protocols, transports, ciphers, or extensions that Chainy does not support. Chainy reports unsupported entries rather than treating them as usable. Open an issue with a redacted example that uses placeholder hosts and credentials.

## Reporting a problem

Use the GitHub issue templates. Never attach a real subscription, credential, private node address, or unredacted exported configuration.
