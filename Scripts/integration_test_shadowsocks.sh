#!/usr/bin/env bash
#
# Integration test: drives the built ShadowsocksDemoCLI against a real local
# shadowsocks-rust server (not just our own encode/decode logic against
# itself) across a small matrix of cipher/address configurations:
#
#   1. aes-256-gcm,          IPv4 server, IPv4 target
#   2. chacha20-ietf-poly1305, IPv4 server, domain-name target ("localhost")
#   3. aes-128-gcm,          IPv6 server ([::1]), IPv4 target
#   4. aes-256-gcm,          IPv4 server, IPv6 target ([::1])
#   5. A deliberately WRONG password against server 1 -- must fail within
#      ~15s with a reported error, not hang forever. (Same failure shape as
#      VMess's wrong-UUID case: the server just never answers, so this is
#      what exercises ShadowsocksSession's read timeout.)
#   6. A large (2MB) response spanning many TCP packets, byte-compared
#      against the source file -- catches any bug in the chunk-reassembly
#      loop that a tiny single-packet response wouldn't, and specifically
#      exercises the multi-chunk decrypt path (a 2MB response is far more
#      than one 0x3FFF-byte chunk).
#
# Requires: a shadowsocks-rust `ssserver` binary
# (https://github.com/shadowsocks/shadowsocks-rust/releases). Point SSSERVER_BIN
# at it, or place one at ./ssserver next to this script, or have `ssserver` on PATH.
#
# Usage: Scripts/integration_test_shadowsocks.sh

set -euo pipefail
cd "$(dirname "$0")/.."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSSERVER_BIN="${SSSERVER_BIN:-}"
if [[ -z "$SSSERVER_BIN" ]]; then
  if [[ -x "$SCRIPT_DIR/ssserver" ]]; then
    SSSERVER_BIN="$SCRIPT_DIR/ssserver"
  elif command -v ssserver >/dev/null 2>&1; then
    SSSERVER_BIN="$(command -v ssserver)"
  fi
fi

if [[ -z "$SSSERVER_BIN" ]]; then
  cat <<'EOF'
No shadowsocks-rust `ssserver` binary found.

This integration test spins up a REAL local Shadowsocks server (shadowsocks-rust)
with several cipher/address configurations and drives the built CLI against it,
to validate protocol behavior beyond our own unit tests.

To run it:
  1. Download a build for your platform from
     https://github.com/shadowsocks/shadowsocks-rust/releases (e.g.
     shadowsocks-vX.Y.Z.aarch64-apple-darwin.tar.xz on Apple Silicon), extract
     it, and either:
       - place the `ssserver` binary at Scripts/ssserver, or
       - export SSSERVER_BIN=/path/to/ssserver, or
       - put `ssserver` on your PATH.
  2. Re-run: Scripts/integration_test_shadowsocks.sh

Skipping (not a failure).
EOF
  exit 0
fi

WORKDIR="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORKDIR"' EXIT

echo "Building ShadowsocksDemoCLI ..."
swift build 2>&1 | tail -5
CLI=".build/debug/ShadowsocksDemoCLI"

PASSWORD_A="password-A-correct-horse"
PASSWORD_B="password-B-correct-horse"
PASSWORD_C="password-C-correct-horse"
WRONG_PASSWORD="definitely-the-wrong-password"

cat > "$WORKDIR/config.json" <<EOF
{
  "servers": [
    { "server": "127.0.0.1", "server_port": 28101, "password": "$PASSWORD_A", "method": "aes-256-gcm", "mode": "tcp_only" },
    { "server": "127.0.0.1", "server_port": 28102, "password": "$PASSWORD_B", "method": "chacha20-ietf-poly1305", "mode": "tcp_only" },
    { "server": "::1",       "server_port": 28103, "password": "$PASSWORD_C", "method": "aes-128-gcm", "mode": "tcp_only" }
  ]
}
EOF

echo "hello-from-integration-test" > "$WORKDIR/index.html"
mkdir -p "$WORKDIR/big"
python3 -c "import os; open('$WORKDIR/big/index.html', 'wb').write(os.urandom(2 * 1024 * 1024))"

echo "Starting local HTTP targets (IPv4 + IPv6 loopback, plus a 2MB file) ..."
python3 -m http.server 18080 --directory "$WORKDIR"     --bind 127.0.0.1 >"$WORKDIR/http4.log"   2>&1 &
python3 -m http.server 18081 --directory "$WORKDIR"     --bind ::1      >"$WORKDIR/http6.log"   2>&1 &
python3 -m http.server 18082 --directory "$WORKDIR/big" --bind 127.0.0.1 >"$WORKDIR/http_big.log" 2>&1 &

echo "Starting local shadowsocks-rust server ($SSSERVER_BIN) ..."
"$SSSERVER_BIN" -c "$WORKDIR/config.json" >"$WORKDIR/ssserver.log" 2>&1 &

sleep 1

pass=0
fail=0

check() {
  local name="$1"; shift
  echo "--- $name ---"
  # Capture full output via command substitution (not a live pipe into
  # grep): grep -q exiting early on match would otherwise deliver SIGPIPE to
  # a still-writing CLI process and, combined with `pipefail`, misreport a
  # perfectly successful run as a failure.
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

check "aes-256-gcm, IPv4 server, IPv4 target"            "$CLI" 127.0.0.1:28101 "$PASSWORD_A" aes-256-gcm 127.0.0.1:18080
check "chacha20-ietf-poly1305, IPv4 server, domain target" "$CLI" 127.0.0.1:28102 "$PASSWORD_B" chacha20-ietf-poly1305 localhost:18080
check "aes-128-gcm, IPv6 server, IPv4 target"            "$CLI" "[::1]:28103"    "$PASSWORD_C" aes-128-gcm 127.0.0.1:18080
check "aes-256-gcm, IPv4 server, IPv6 target"            "$CLI" 127.0.0.1:28101 "$PASSWORD_A" aes-256-gcm "[::1]:18081"

echo "--- large (2MB) response reassembles byte-exact across many chunks ---"
"$CLI" 127.0.0.1:28101 "$PASSWORD_A" aes-256-gcm 127.0.0.1:18082 >"$WORKDIR/big_raw.out" 2>&1 || true
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
if "$CLI" 127.0.0.1:28101 "$WRONG_PASSWORD" aes-256-gcm 127.0.0.1:18080 >"$WORKDIR/wrong.log" 2>&1; then
  echo "FAIL: wrong password unexpectedly succeeded"
  fail=$((fail + 1))
else
  elapsed=$(( $(date +%s) - start ))
  if [[ $elapsed -lt 15 ]] && grep -q "timedOut" "$WORKDIR/wrong.log"; then
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
