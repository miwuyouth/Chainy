#!/usr/bin/env bash
#
# Integration test: drives the built VMessDemoCLI against a real local
# xray-core vmess server (not just our own encode/decode logic against
# itself) across a small matrix of server/target configurations:
#
#   1. UUID A, IPv4 vmess server,  IPv4 target
#   2. UUID B, IPv4 vmess server,  domain-name target ("localhost")
#   3. UUID C, IPv6 vmess server ([::1]), IPv4 target
#   4. UUID A, IPv4 vmess server,  IPv6 target ([::1])
#   5. A deliberately WRONG uuid against server A -- must fail within
#      ~15s with a reported error, not hang forever. (A real VMess server
#      gives a bad AuthID/UUID no distinguishing response at all, to
#      resist active probing -- it just stops talking -- so this is the
#      scenario that motivated VMessCore's read/connect timeouts.)
#   6. UUID A against a server configured with a non-zero legacy alterId
#      -- our client only ever sends the modern AEAD request format, so
#      this checks (empirically, against a real server) that xray-core's
#      inbound still accepts it regardless of the server's alterId setting.
#   7. A large (2MB) response spanning many TCP packets, byte-compared
#      against the source file -- catches any bug in the readAvailable()
#      reassembly loop that a tiny single-packet response wouldn't.
#
# Requires: an xray-core binary (https://github.com/XTLS/Xray-core/releases).
# Point XRAY_BIN at it, or place one at ./xray next to this script, or have
# `xray` on PATH.
#
# Usage: Scripts/integration_test.sh

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

This integration test spins up a REAL local vmess server (xray-core) with
several configurations and drives the built CLI against it, to validate
protocol behavior beyond our own unit tests.

To run it:
  1. Download a build for your platform from
     https://github.com/XTLS/Xray-core/releases (e.g. Xray-macos-arm64-v8a.zip
     on Apple Silicon), unzip it, and either:
       - place the `xray` binary at Scripts/xray, or
       - export XRAY_BIN=/path/to/xray, or
       - put `xray` on your PATH.
  2. Re-run: Scripts/integration_test.sh

Skipping (not a failure).
EOF
  exit 0
fi

WORKDIR="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORKDIR"' EXIT

echo "Building VMessDemoCLI ..."
swift build 2>&1 | tail -5
CLI=".build/debug/VMessDemoCLI"

UUID_A="0398d470-bc09-4cd5-889d-3ae4c569b6da"
UUID_B="11111111-2222-3333-4444-555555555555"
UUID_C="99999999-8888-7777-6666-555544443333"
UUID_WRONG="ffffffff-ffff-ffff-ffff-ffffffffffff"

cat > "$WORKDIR/config.json" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "tag": "a", "listen": "127.0.0.1", "port": 28001, "protocol": "vmess",
      "settings": { "clients": [ { "id": "$UUID_A", "alterId": 0 } ] },
      "streamSettings": { "network": "tcp" } },
    { "tag": "b", "listen": "127.0.0.1", "port": 28002, "protocol": "vmess",
      "settings": { "clients": [ { "id": "$UUID_B", "alterId": 0 } ] },
      "streamSettings": { "network": "tcp" } },
    { "tag": "c", "listen": "::1", "port": 28003, "protocol": "vmess",
      "settings": { "clients": [ { "id": "$UUID_C", "alterId": 0 } ] },
      "streamSettings": { "network": "tcp" } },
    { "tag": "legacy", "listen": "127.0.0.1", "port": 28004, "protocol": "vmess",
      "settings": { "clients": [ { "id": "$UUID_A", "alterId": 16 } ] },
      "streamSettings": { "network": "tcp" } }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" } ]
}
EOF

echo "hello-from-integration-test" > "$WORKDIR/index.html"

mkdir -p "$WORKDIR/big"
python3 -c "import os; open('$WORKDIR/big/index.html', 'wb').write(os.urandom(2 * 1024 * 1024))"

echo "Starting local HTTP targets (IPv4 + IPv6 loopback, plus a 2MB file) ..."
python3 -m http.server 18080 --directory "$WORKDIR"       --bind 127.0.0.1 >"$WORKDIR/http4.log"   2>&1 &
python3 -m http.server 18081 --directory "$WORKDIR"       --bind ::1      >"$WORKDIR/http6.log"   2>&1 &
python3 -m http.server 18082 --directory "$WORKDIR/big"   --bind 127.0.0.1 >"$WORKDIR/http_big.log" 2>&1 &

echo "Starting local xray-core vmess server ($XRAY_BIN) ..."
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

check "UUID A, IPv4 server, IPv4 target"        "$CLI" 127.0.0.1:28001 "$UUID_A" 127.0.0.1:18080
check "UUID B, IPv4 server, domain target"      "$CLI" 127.0.0.1:28002 "$UUID_B" localhost:18080
check "UUID C, IPv6 server, IPv4 target"        "$CLI" "[::1]:28003"   "$UUID_C" 127.0.0.1:18080
check "UUID A, IPv4 server, IPv6 target"        "$CLI" 127.0.0.1:28001 "$UUID_A" "[::1]:18081"
check "UUID A against legacy alterId=16 server" "$CLI" 127.0.0.1:28004 "$UUID_A" 127.0.0.1:18080

echo "--- large (2MB) response reassembles byte-exact across many TCP packets ---"
"$CLI" 127.0.0.1:28001 "$UUID_A" 127.0.0.1:18082 >"$WORKDIR/big_raw.out" 2>&1 || true
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

echo "--- wrong UUID must fail fast (not hang) ---"
start=$(date +%s)
if "$CLI" 127.0.0.1:28001 "$UUID_WRONG" 127.0.0.1:18080 >"$WORKDIR/wrong.log" 2>&1; then
  echo "FAIL: wrong UUID unexpectedly succeeded"
  fail=$((fail + 1))
else
  elapsed=$(( $(date +%s) - start ))
  if [[ $elapsed -lt 15 ]] && grep -q "timedOut" "$WORKDIR/wrong.log"; then
    echo "PASS: wrong UUID failed closed after ${elapsed}s"
    pass=$((pass + 1))
  else
    echo "FAIL: wrong UUID took ${elapsed}s or gave an unexpected error:"
    cat "$WORKDIR/wrong.log"
    fail=$((fail + 1))
  fi
fi

echo
echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
