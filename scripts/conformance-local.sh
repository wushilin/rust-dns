#!/usr/bin/env bash
# Start an isolated rust-dns instance, seed the conformance fixture, and run
# scripts/conformance.py. Requires Python dnspython.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-$ROOT/target/debug/rust-dns}"
ZONE="example.test"
if [ ! -x "$BIN" ]; then
  echo "binary not found: $BIN (run cargo build first)" >&2
  exit 2
fi
TMP="$(mktemp -d)"
read -r DNS_PORT WEB_PORT < <(python3 -c 'import socket; a=socket.socket(); b=socket.socket(); a.bind(("127.0.0.1", 0)); b.bind(("127.0.0.1", 0)); print(a.getsockname()[1], b.getsockname()[1]); a.close(); b.close()')
cat > "$TMP/config.toml" <<EOF
[server]
bind = ["127.0.0.1"]
port = $DNS_PORT
udp = true
tcp = true
nsid = "ns1.$ZONE"
cookies = true

[rate_limit]
max_resolutions_per_second_per_address = 500
max_tracked_addresses = 1000

[transfer]
allow = ["127.0.0.0/8"]

[database]
path = "$TMP/rust-dns.db"

[backup]
dir = ""

[web_console]
bind = "127.0.0.1:$WEB_PORT"

[root]
username = "root"
password = "ci-root-password"

[logging]
level = "warn"
EOF
"$BIN" --config "$TMP/config.toml" >"$TMP/server.log" 2>&1 &
PID=$!
cleanup() {
  kill "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  if [ "${KEEP_CONFORMANCE_TMP:-0}" = "1" ]; then
    echo "temporary files retained at $TMP" >&2
  else
    rm -rf "$TMP"
  fi
}
trap cleanup EXIT INT TERM
python3 "$ROOT/scripts/seed-conformance.py" "http://127.0.0.1:$WEB_PORT"
python3 "$ROOT/scripts/conformance.py" "$ZONE" 127.0.0.1 "$DNS_PORT"
if [ "${RUN_COMPLIANCE:-0}" = "1" ]; then
  "$ROOT/scripts/compliance.sh" "$ZONE" 127.0.0.1 "$DNS_PORT"
fi
