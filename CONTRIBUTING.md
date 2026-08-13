# Contributing to Chainy

Thank you for helping improve Chainy. Focused bug fixes, compatibility reports, tests, and documentation improvements are welcome.

## Before opening an issue

- Search existing issues.
- Test the latest release or `main` when practical.
- Remove proxy credentials, subscription URLs, private hosts, and identifying log content.
- For vulnerabilities, follow `SECURITY.md` instead of opening a public bug report.

## Development setup

Requirements: macOS 13+, Xcode 15+, Swift 5.9+, and XcodeGen.

```bash
brew install xcodegen
xcodegen generate
open Chainy.xcodeproj
```

Run package tests with:

```bash
swift test --skip InteropTests
```

`InteropTests` includes an exhaustive 1...5-hop protocol matrix. It is intentionally excluded from the ordinary CI job because it is slow and requires a local `xray-core` fixture. Run it before a release with `swift test --filter InteropTests` after following the setup comments in `Tests/InteropTests/Support/XrayTestEnvironment.swift`.

The scripts under `Scripts/` also provide focused integration checks. Never replace fixture values with real credentials.

## Pull requests

- Keep each pull request focused on one change.
- Add or update tests when behavior changes.
- Run `swift test --skip InteropTests` and describe any tests you could not run.
- Update documentation for user-visible behavior.
- Do not commit generated `.xcodeproj`, `.build`, release artifacts, credentials, or real subscription data.

By contributing, you agree that your contribution is licensed under the MIT License.
