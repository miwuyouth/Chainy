# Privacy

Chainy is designed to run locally. It does not include analytics, advertising, crash-reporting SDKs, user accounts, or a Chainy-operated backend.

## Data stored on your Mac

Chainy stores saved chains, nodes, proxy credentials, subscription URLs, and related settings in the current user's Application Support directory and `UserDefaults`. These values are currently stored as local application data and are not encrypted by Chainy. Anyone or any process able to read your user account's files may be able to read them.

Do not import credentials on a shared or untrusted Mac. Remove sensitive configurations before sharing an exported configuration, diagnostic archive, screenshot, or backup.

## Network activity

Chainy makes network connections only to perform features you request:

- fetching a subscription URL copied into the app;
- connecting to proxy nodes and destinations selected by you;
- relaying traffic from applications using Chainy's local proxy;
- testing connectivity against `www.google.com`;
- testing bandwidth by downloading test data from `speedtest.tele2.net`.

The operators of subscription services, proxy nodes, destinations, and diagnostic endpoints may observe connection metadata according to their own policies. Proxy protocols do not make unencrypted destination traffic encrypted end-to-end; use HTTPS or another end-to-end encrypted protocol where appropriate.

## Listening interfaces

By default, Chainy listens on the loopback interface. If you enable LAN access, other devices able to reach your Mac may be able to use the local proxy. Only enable LAN access on networks you trust and protect the host with an appropriate firewall.

## Questions

For privacy questions, open a GitHub issue that does not contain credentials or other sensitive data.
