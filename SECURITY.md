# Security Policy

## Supported versions

Chainy is early-stage software. Security fixes are applied to the latest release and the `main` branch; older releases may not receive patches.

## Reporting a vulnerability

Please do not disclose an exploitable vulnerability, proxy credential, subscription URL, private server address, or unredacted log in a public issue.

Use GitHub's **Report a vulnerability** feature under the repository's Security tab. If private vulnerability reporting is temporarily unavailable, open a public issue containing only a request for a private contact channel and no technical details.

Include, when possible:

- the affected version or commit;
- macOS and CPU architecture;
- a minimal reproduction using placeholder credentials;
- impact and whether the issue is remotely exploitable;
- any suggested mitigation.

## Scope and expectations

Chainy handles untrusted network data and locally stored proxy credentials. It has not undergone an independent security audit. Review the source, use least-privilege credentials, keep macOS updated, and avoid depending on Chainy as a security boundary.

Never publish real credentials in issues, pull requests, tests, screenshots, or logs.
