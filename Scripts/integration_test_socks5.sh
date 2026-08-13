#!/usr/bin/env bash
#
# Integration test: drives the built SOCKS5DemoCLI against a real local
# xray-core SOCKS5 inbound (not just our own encode/decode logic against
# itself) across a small matrix of configurations:
#
#   1. No-auth,             IPv4 server, IPv4 target
#   2. No-auth,              IPv4 server, domain-name target ("localhost")
#   3. No-auth,              IPv6 server ([::1]), IPv4 target
#   4. No-auth,              IPv4 server, IPv6 target ([::1])
#   5. Username/password auth, correct credentials
#   6. Username/password auth, deliberately WRONG password -- must fail
#      within a few seconds with a reported authentication error, not hang.
#   7. A large (2MB) response spanning many TCP packets, byte-compared
#      against the source file -- exercises the readAvailable() reassembly
#      loop the same way the VMess/Shadowsocks integration tests do.
#
# Requires: an xray-core binary (https://github.com/XTLS/Xray-core/releases)
# -- the same one used by Scripts/integration_test.sh, since xray-core also
# speaks SOCKS5 as an inbound protocol. Point XRAY_BIN at it, or place one at
# ./xray next to this script, or have `xray` on PATH.
#
# Usage: Scripts/integration_test_socks5.sh

set -euo pipefail
cd "$(dirname "$0")/.."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XRAY_BIN="${XRAY_BIN:-}"
if [[ -z "$XRAY_BIN" ]]; then
  if [[ -x "$SCRIPT_DIR/xray" ]]; then
    XRAY_BIN="$SCRIPT_DIR/xray"
  elif command -v xray >/dev/null 2>&1; then
    XRAY_BIN="$(command -v xray)"
  fi
fi

if [[ -z "$XRAY_BIN" ]]; then
  cat <<'EOF'
No xray-core binary found.

This integration test spins up a REAL local SOCKS5 server (xray-core's socks
inbound) with several configurations and drives the built CLI against it, to
validate protocol behavior beyond our own unit tests.

To run it:
  1. Download a build for your platform from
     https://github.com/XTLS/Xray-core/releases (e.g. Xray-macos-arm64-v8a.zip
     on Apple Silicon), unzip it, and either:
       - place the `xray` binary at Scripts/xray, or
       - export XRAY_BIN=/path/to/xray, or
       - put `xray` on your PATH.
  2. Re-run: Scripts/integration_test_socks5.sh

Skipping (not a failure).
EOF
  exit 0
fi

WORKDIR="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORKDIR"' EXIT

echo "Building SOCKS5DemoCLI ..."
swift build 2>&1 | tail -5
CLI=".build/debug/SOCKS5DemoCLI"

AUTH_USER="socks5-integration-user"
AUTH_PASS="correct-horse-battery-staple"

cat > "$WORKDIR/config.json" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "tag": "a", "listen": "127.0.0.1", "port": 28201, "protocol": "socks",
      "settings": { "auth": "noauth", "udp": false } },
    { "tag": "b", "listen": "::1", "port": 28202, "protocol": "socks",
      "settings": { "auth": "noauth", "udp": false } },
    { "tag": "auth", "listen": "127.0.0.1", "port": 28203, "protocol": "socks",
      "settings": { "auth": "password", "accounts": [ { "user": "$AUTH_USER", "pass": "$AUTH_PASS" } ], "udp": false } }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" } ]
}
EOF

echo "hello-from-integration-test" > "$WORKDIR/index.html"

mkdir -p "$WORKDIR/big"
python3 -c "import os; open('$WORKDIR/big/index.html', 'wb').write(os.urandom(2 * 1024 * 1024))"

echo "Starting local HTTP targets (IPv4 + IPv6 loopback, plus a 2MB file) ..."
python3 -m http.server 18090 --directory "$WORKDIR"     --bind 127.0.0.1 >"$WORKDIR/http4.log"   2>&1 &
python3 -m http.server 18091 --directory "$WORKDIR"     --bind ::1      >"$WORKDIR/http6.log"   2>&1 &
python3 -m http.server 18092 --directory "$WORKDIR/big" --bind 127.0.0.1 >"$WORKDIR/http_big.log" 2>&1 &

echo "Starting local xray-core SOCKS5 server ($XRAY_BIN) ..."
"$XRAY_BIN" run -c "$WORKDIR/config.json" >"$WORKDIR/xray.log" 2>&1 &

sleep 1

pass=0
fail=0

check() {
  local name="$1"; shift
  echo "--- $name ---"
  # Capture full output via command substitution (not a live pipe into grep):
  # `grep -q` exits as soon as it sees a match, which would otherwise deliver
  # SIGPIPE to a still-writing CLI process and, combined with `pipefail`,
  # misreport a perfectly successful run as a failure.
  local output
  output="$("$@" 2>&1)" || true
  if grep -q "hello-from-integration-test" <<<"$output"; then
    echo "PASS: $name"
    pass=$((pass + 1))
  else
    echo "FAIL: $name"
    echo "$output"
    fail=$((fail + 1))
  fi
}

check "no-auth, IPv4 server, IPv4 target"   "$CLI" 127.0.0.1:28201 127.0.0.1:18090
check "no-auth, IPv4 server, domain target" "$CLI" 127.0.0.1:28201 localhost:18090
check "no-auth, IPv6 server, IPv4 target"   "$CLI" "[::1]:28202"   127.0.0.1:18090
check "no-auth, IPv4 server, IPv6 target"   "$CLI" 127.0.0.1:28201 "[::1]:18091"
check "username/password auth, correct credentials" "$CLI" 127.0.0.1:28203 127.0.0.1:18090 "$AUTH_USER" "$AUTH_PASS"

echo "--- large (2MB) response reassembles byte-exact across many TCP packets ---"
"$CLI" 127.0.0.1:28201 127.0.0.1:18092 >"$WORKDIR/big_raw.out" 2>&1 || true
if python3 - "$WORKDIR/big_raw.out" "$WORKDIR/big/index.html" <<'PYEOF'
import sys
raw = open(sys.argv[1], 'rb').read()
sep = raw.find(b'\r\n\r\n')  # end of the (well-formed, ASCII) HTTP response headers
body = raw[sep + 4:] if sep != -1 else b''
marker = body.rfind(b'\n--- end of stream')  # the CLI's own trailing log line
if marker != -1:
    body = body[:marker]
expected = open(sys.argv[2], 'rb').read()
sys.exit(0 if body == expected else 1)
PYEOF
then
  echo "PASS: large response byte-exact"
  pass=$((pass + 1))
else
  echo "FAIL: large response did not match source file exactly"
  fail=$((fail + 1))
fi

echo "--- wrong password must fail fast (not hang) ---"
start=$(date +%s)
if "$CLI" 127.0.0.1:28203 127.0.0.1:18090 "$AUTH_USER" "definitely-the-wrong-password" >"$WORKDIR/wrong.log" 2>&1; then
  echo "FAIL: wrong password unexpectedly succeeded"
  fail=$((fail + 1))
else
  elapsed=$(( $(date +%s) - start ))
  if [[ $elapsed -lt 15 ]] && grep -q "authenticationFailed" "$WORKDIR/wrong.log"; then
    echo "PASS: wrong password failed closed after ${elapsed}s"
    pass=$((pass + 1))
  else
    echo "FAIL: wrong password took ${elapsed}s or gave an unexpected error:"
    cat "$WORKDIR/wrong.log"
    fail=$((fail + 1))
  fi
fi

echo
echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
