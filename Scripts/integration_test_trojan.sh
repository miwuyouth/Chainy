#!/usr/bin/env bash
#
# Integration test: drives the built TrojanDemoCLI against a real local
# xray-core trojan inbound (not just our own encode/decode logic against
# itself, and not just TLSDebugCLI's hand-rolled NWListener test server --
# see TrojanSessionLiveSocketTests) across a small matrix of configurations:
#
#   1. Correct password,     IPv4 server, IPv4 target
#   2. Correct password,     IPv4 server, domain-name target ("localhost")
#   3. Correct password,     IPv6 server ([::1]), IPv4 target
#   4. Correct password,     IPv4 server, IPv6 target ([::1])
#   5. A deliberately WRONG password -- must come back empty within ~15s,
#      not hang and not relay the target's content. Unlike VMess/Shadowsocks,
#      a bad password isn't a thrown/non-zero-exit error here: xray-core
#      (confirmed against its own debug log) closes the connection cleanly
#      the moment it fails to match a configured client, which
#      TrojanSession/TrojanDemoCLI see as an ordinary empty stream (exit 0,
#      no bytes) -- there's no ack step to fail *at* the way SOCKS5's auth
#      or VMess's AuthID check has. So this checks CLI output content (no
#      "hello-from-integration-test"), not exit code or a "timedOut" string.
#   6. A large (2MB) response spanning many TCP packets, byte-compared
#      against the source file -- exercises the readAvailable() reassembly
#      loop the same way the VMess/Shadowsocks/SOCKS5 integration tests do.
#
# Requires: an xray-core binary (https://github.com/XTLS/Xray-core/releases)
# -- the same one used by Scripts/integration_test.sh, since xray-core also
# speaks trojan as an inbound protocol -- and `openssl` (used to generate a
# throwaway self-signed TLS certificate for xray's trojan inbound; the CLI
# is pointed at it with allowInsecure=1, the same as
# TrojanSessionLiveSocketTests' own self-signed test server).
#
# Usage: Scripts/integration_test_trojan.sh

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

This integration test spins up a REAL local trojan server (xray-core's
trojan inbound, TLS-terminated) with several configurations and drives the
built CLI against it, to validate protocol behavior beyond our own unit
tests.

To run it:
  1. Download a build for your platform from
     https://github.com/XTLS/Xray-core/releases (e.g. Xray-macos-arm64-v8a.zip
     on Apple Silicon), unzip it, and either:
       - place the `xray` binary at Scripts/xray, or
       - export XRAY_BIN=/path/to/xray, or
       - put `xray` on your PATH.
  2. Re-run: Scripts/integration_test_trojan.sh

Skipping (not a failure).
EOF
  exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "No openssl found (needed to generate a throwaway TLS certificate). Skipping (not a failure)."
  exit 0
fi

WORKDIR="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORKDIR"' EXIT

echo "Building TrojanDemoCLI ..."
swift build 2>&1 | tail -5
CLI=".build/debug/TrojanDemoCLI"

PASSWORD_A="password-A-correct-horse"
PASSWORD_B="password-B-correct-horse"
PASSWORD_C="password-C-correct-horse"
WRONG_PASSWORD="definitely-the-wrong-password"

echo "Generating a throwaway self-signed TLS certificate ..."
openssl req -x509 -newkey rsa:2048 -keyout "$WORKDIR/key.pem" -out "$WORKDIR/cert.pem" \
  -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1

cat > "$WORKDIR/config.json" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "tag": "a", "listen": "127.0.0.1", "port": 28201, "protocol": "trojan",
      "settings": { "clients": [ { "password": "$PASSWORD_A" } ] },
      "streamSettings": { "network": "tcp", "security": "tls",
        "tlsSettings": { "certificates": [ { "certificateFile": "$WORKDIR/cert.pem", "keyFile": "$WORKDIR/key.pem" } ] } } },
    { "tag": "b", "listen": "127.0.0.1", "port": 28202, "protocol": "trojan",
      "settings": { "clients": [ { "password": "$PASSWORD_B" } ] },
      "streamSettings": { "network": "tcp", "security": "tls",
        "tlsSettings": { "certificates": [ { "certificateFile": "$WORKDIR/cert.pem", "keyFile": "$WORKDIR/key.pem" } ] } } },
    { "tag": "c", "listen": "::1", "port": 28203, "protocol": "trojan",
      "settings": { "clients": [ { "password": "$PASSWORD_C" } ] },
      "streamSettings": { "network": "tcp", "security": "tls",
        "tlsSettings": { "certificates": [ { "certificateFile": "$WORKDIR/cert.pem", "keyFile": "$WORKDIR/key.pem" } ] } } }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" } ]
}
EOF

echo "hello-from-integration-test" > "$WORKDIR/index.html"
mkdir -p "$WORKDIR/big"
python3 -c "import os; open('$WORKDIR/big/index.html', 'wb').write(os.urandom(2 * 1024 * 1024))"

echo "Starting local HTTP targets (IPv4 + IPv6 loopback, plus a 2MB file) ..."
python3 -m http.server 18080 --directory "$WORKDIR"     --bind 127.0.0.1 >"$WORKDIR/http4.log"   2>&1 &
python3 -m http.server 18081 --directory "$WORKDIR"     --bind ::1      >"$WORKDIR/http6.log"   2>&1 &
python3 -m http.server 18082 --directory "$WORKDIR/big" --bind 127.0.0.1 >"$WORKDIR/http_big.log" 2>&1 &

echo "Starting local xray-core trojan server ($XRAY_BIN) ..."
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
  if grep -q "hello-from-integration-test" <<<"$output"; then
    echo "PASS: $name"
    pass=$((pass + 1))
  else
    echo "FAIL: $name"
    echo "$output"
    fail=$((fail + 1))
  fi
}

check "password A, IPv4 server, IPv4 target"   "$CLI" 127.0.0.1:28201 "$PASSWORD_A" 127.0.0.1:18080 localhost 1
check "password B, IPv4 server, domain target" "$CLI" 127.0.0.1:28202 "$PASSWORD_B" localhost:18080 localhost 1
check "password C, IPv6 server, IPv4 target"   "$CLI" "[::1]:28203"   "$PASSWORD_C" 127.0.0.1:18080 localhost 1
check "password A, IPv4 server, IPv6 target"   "$CLI" 127.0.0.1:28201 "$PASSWORD_A" "[::1]:18081"   localhost 1

echo "--- large (2MB) response reassembles byte-exact across many TCP packets ---"
"$CLI" 127.0.0.1:28201 "$PASSWORD_A" 127.0.0.1:18082 localhost 1 >"$WORKDIR/big_raw.out" 2>&1 || true
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

echo "--- wrong password must come back empty within ~15s (not hang, not relay content) ---"
start=$(date +%s)
wrong_output="$("$CLI" 127.0.0.1:28201 "$WRONG_PASSWORD" 127.0.0.1:18080 localhost 1 2>&1)" || true
elapsed=$(( $(date +%s) - start ))
if grep -q "hello-from-integration-test" <<<"$wrong_output"; then
  echo "FAIL: wrong password unexpectedly relayed real content"
  echo "$wrong_output"
  fail=$((fail + 1))
elif [[ $elapsed -lt 15 ]] && grep -q "end of stream (0 bytes)" <<<"$wrong_output"; then
  echo "PASS: wrong password closed with an empty stream after ${elapsed}s"
  pass=$((pass + 1))
else
  echo "FAIL: wrong password took ${elapsed}s or gave an unexpected result:"
  echo "$wrong_output"
  fail=$((fail + 1))
fi

echo
echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
