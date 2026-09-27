#!/usr/bin/env bash
# Run the short UDP throughput probe against an isolated instance. This is
# intended for Linux runners; loopback UDP limits make macOS results misleading.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-$ROOT/target/debug/rust-dns}"
DURATION="${2:-5}"
CLIENTS="${3:-8}"
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

[rate_limit]
max_resolutions_per_second_per_address = 0

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
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM
python3 "$ROOT/scripts/seed-conformance.py" "http://127.0.0.1:$WEB_PORT"
python3 "$ROOT/scripts/load-test.py" example.test 127.0.0.1 "$DNS_PORT" "$DURATION" "$CLIENTS"
