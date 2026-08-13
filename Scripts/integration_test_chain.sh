#!/usr/bin/env bash
#
# Integration test: drives the built ChainDemoCLI through real, independent
# proxy-protocol inbounds (not just our own encode/decode logic against
# itself, and not just the in-process fakes in ChainCoreTests) across a
# matrix of chain shapes:
#
#   1. SOCKS5 -> Shadowsocks -> VMess -> target (canonical order)
#   2. VMess -> SOCKS5 -> Shadowsocks -> target (mixed order)
#   3. Shadowsocks -> SOCKS5(username/password) -> target (auth on a
#      non-first hop)
#   4. A large (2MB) response through a 3-hop chain, byte-compared against
#      the source file -- exercises chunk reassembly through multiple
#      stacked layers, not just one.
#   5. A deliberately WRONG SOCKS5 password on a *middle* hop -- must fail
#      within a few seconds with a reported authentication error, not hang.
#
# All hops are served by ONE real xray-core process with several inbounds
# (vmess/socks/shadowsocks), each with a plain "freedom" (direct-connect)
# outbound -- so hop N's CONNECT target being hop N+1's inbound port on the
# same process is exactly the same shape a chain across independent real
# servers would be, just colocated for test convenience. xray-core is
# already the real server this repo's other integration tests (VMess,
# SOCKS5, and -- see Scripts/integration_test_shadowsocks.sh's own
# shadowsocks-rust default -- optionally Shadowsocks too) run against.
#
# Requires: an xray-core binary (https://github.com/XTLS/Xray-core/releases)
# -- the same one used by Scripts/integration_test.sh and
# Scripts/integration_test_socks5.sh. Point XRAY_BIN at it, or place one at
# ./xray next to this script, or have `xray` on PATH.
#
# Usage: Scripts/integration_test_chain.sh

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

This integration test spins up REAL local vmess/socks/shadowsocks servers
(xray-core, which supports all three as inbounds) and drives the built
ChainDemoCLI through them chained together, to validate chain-proxy
behavior against independent real protocol implementations, not just our
own client/server test doubles.

To run it:
  1. Download a build for your platform from
     https://github.com/XTLS/Xray-core/releases (e.g. Xray-macos-arm64-v8a.zip
     on Apple Silicon), unzip it, and either:
       - place the `xray` binary at Scripts/xray, or
       - export XRAY_BIN=/path/to/xray, or
       - put `xray` on your PATH.
  2. Re-run: Scripts/integration_test_chain.sh

Skipping (not a failure).
EOF
  exit 0
fi

WORKDIR="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORKDIR"' EXIT

echo "Building ChainDemoCLI ..."
swift build 2>&1 | tail -5
CLI=".build/debug/ChainDemoCLI"

UUID_A="0398d470-bc09-4cd5-889d-3ae4c569b6da"
UUID_B="11111111-2222-3333-4444-555555555555"
SS_PASSWORD_A="chain-integration-password-a"
SS_PASSWORD_B="chain-integration-password-b"
AUTH_USER="chain-integration-user"
AUTH_PASS="correct-horse-battery-staple"
AUTH_WRONG_PASS="definitely-the-wrong-password"

cat > "$WORKDIR/config.json" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "tag": "vmess-a", "listen": "127.0.0.1", "port": 28401, "protocol": "vmess",
      "settings": { "clients": [ { "id": "$UUID_A", "alterId": 0 } ] },
      "streamSettings": { "network": "tcp" } },
    { "tag": "vmess-b", "listen": "127.0.0.1", "port": 28402, "protocol": "vmess",
      "settings": { "clients": [ { "id": "$UUID_B", "alterId": 0 } ] },
      "streamSettings": { "network": "tcp" } },
    { "tag": "socks-noauth", "listen": "127.0.0.1", "port": 28403, "protocol": "socks",
      "settings": { "auth": "noauth", "udp": false } },
    { "tag": "socks-auth", "listen": "127.0.0.1", "port": 28404, "protocol": "socks",
      "settings": { "auth": "password", "accounts": [ { "user": "$AUTH_USER", "pass": "$AUTH_PASS" } ], "udp": false } },
    { "tag": "ss-a", "listen": "127.0.0.1", "port": 28405, "protocol": "shadowsocks",
      "settings": { "method": "aes-256-gcm", "password": "$SS_PASSWORD_A", "network": "tcp" } },
    { "tag": "ss-b", "listen": "127.0.0.1", "port": 28406, "protocol": "shadowsocks",
      "settings": { "method": "chacha20-ietf-poly1305", "password": "$SS_PASSWORD_B", "network": "tcp" } }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" } ]
}
EOF

echo "hello-from-chain-integration-test" > "$WORKDIR/index.html"

mkdir -p "$WORKDIR/big"
python3 -c "import os; open('$WORKDIR/big/index.html', 'wb').write(os.urandom(2 * 1024 * 1024))"

echo "Starting local HTTP targets ..."
python3 -m http.server 18280 --directory "$WORKDIR"     --bind 127.0.0.1 >"$WORKDIR/http.log"     2>&1 &
python3 -m http.server 18281 --directory "$WORKDIR/big" --bind 127.0.0.1 >"$WORKDIR/http_big.log" 2>&1 &

echo "Starting local xray-core (vmess x2, socks x2, shadowsocks x2 inbounds) ($XRAY_BIN) ..."
"$XRAY_BIN" run -c "$WORKDIR/config.json" >"$WORKDIR/xray.log" 2>&1 &

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
  if grep -q "hello-from-chain-integration-test" <<<"$output"; then
    echo "PASS: $name"
    pass=$((pass + 1))
  else
    echo "FAIL: $name"
    echo "$output"
    fail=$((fail + 1))
  fi
}

check "3-hop: socks5 -> shadowsocks -> vmess -> target" \
  "$CLI" "socks5,127.0.0.1,28403" "shadowsocks,127.0.0.1,28405,$SS_PASSWORD_A,aes-256-gcm" "vmess,127.0.0.1,28401,$UUID_A" \
  127.0.0.1:18280

check "3-hop, mixed order: vmess -> socks5 -> shadowsocks -> target" \
  "$CLI" "vmess,127.0.0.1,28402,$UUID_B" "socks5,127.0.0.1,28403" "shadowsocks,127.0.0.1,28406,$SS_PASSWORD_B,chacha20-ietf-poly1305" \
  127.0.0.1:18280

check "2-hop, auth on the non-first hop: shadowsocks -> socks5(user/pass) -> target" \
  "$CLI" "shadowsocks,127.0.0.1,28405,$SS_PASSWORD_A,aes-256-gcm" "socks5,127.0.0.1,28404,$AUTH_USER,$AUTH_PASS" \
  127.0.0.1:18280

echo "--- large (2MB) response reassembles byte-exact through a 3-hop chain ---"
"$CLI" "socks5,127.0.0.1,28403" "shadowsocks,127.0.0.1,28405,$SS_PASSWORD_A,aes-256-gcm" "vmess,127.0.0.1,28401,$UUID_A" \
  127.0.0.1:18281 >"$WORKDIR/big_raw.out" 2>&1 || true
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
  echo "PASS: large response byte-exact through chain"
  pass=$((pass + 1))
else
  echo "FAIL: large response did not match source file exactly"
  fail=$((fail + 1))
fi

echo "--- wrong SOCKS5 password on a middle hop must fail fast (not hang) ---"
start=$(date +%s)
if "$CLI" "shadowsocks,127.0.0.1,28405,$SS_PASSWORD_A,aes-256-gcm" "socks5,127.0.0.1,28404,$AUTH_USER,$AUTH_WRONG_PASS" \
     127.0.0.1:18280 >"$WORKDIR/wrong.log" 2>&1; then
  echo "FAIL: wrong middle-hop password unexpectedly succeeded"
  fail=$((fail + 1))
else
  elapsed=$(( $(date +%s) - start ))
  if [[ $elapsed -lt 15 ]] && grep -q "authenticationFailed" "$WORKDIR/wrong.log"; then
    echo "PASS: wrong middle-hop password failed closed after ${elapsed}s"
    pass=$((pass + 1))
  else
    echo "FAIL: wrong middle-hop password took ${elapsed}s or gave an unexpected error:"
    cat "$WORKDIR/wrong.log"
    fail=$((fail + 1))
  fi
fi

echo
echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
