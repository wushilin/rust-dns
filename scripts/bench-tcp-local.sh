#!/usr/bin/env bash
# Authoritative throughput over TCP against an isolated local instance
# (dnsperf -m tcp). macOS loopback caps UDP at a few thousand queries/s for
# any server, so TCP is what can be compared on a Mac. Usage:
#   scripts/bench-tcp-local.sh BIN [SECONDS] [CLIENTS] [ROUNDS]
# Prints one "qps=<n>" line per round and the median. Seeds the conformance
# zone (example.test) and queries existing names, NXDOMAIN, NODATA, a
# wildcard and a CNAME (authoritative answers only: no upstream).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:?binary}"
DURATION="${2:-10}"
CLIENTS="${3:-16}"
ROUNDS="${4:-3}"
command -v dnsperf >/dev/null || { echo "dnsperf not found" >&2; exit 2; }
TMP="$(mktemp -d)"
read -r DNS_PORT WEB_PORT < <(python3 -c 'import socket; a=socket.socket(); b=socket.socket(); a.bind(("127.0.0.1", 0)); b.bind(("127.0.0.1", 0)); print(a.getsockname()[1], b.getsockname()[1]); a.close(); b.close()')
cat > "$TMP/config.toml" <<EOC
[server]
bind = ["127.0.0.1"]
port = $DNS_PORT
max_tcp_connections = 4096
max_tcp_connections_per_client = 0
tcp_max_queries_per_connection = 100000000
tcp_max_connection_secs = 100000

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
EOC
"$BIN" --config "$TMP/config.toml" >"$TMP/server.log" 2>&1 &
PID=$!
cleanup() {
  kill "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM
python3 "$ROOT/scripts/seed-conformance.py" "http://127.0.0.1:$WEB_PORT" >/dev/null
cat > "$TMP/queries" <<EOQ
www.example.test A
www.example.test AAAA
example.test SOA
example.test NS
nope.example.test A
www.example.test MX
EOQ
results=()
for _ in $(seq 1 "$ROUNDS"); do
  qps=$(dnsperf -m tcp -s 127.0.0.1 -p "$DNS_PORT" -d "$TMP/queries" -c "$CLIENTS" -T 4 -q 256 -l "$DURATION" 2>/dev/null \
    | awk '/Queries per second/ {print int($4)}')
  echo "qps=$qps"
  results+=("$qps")
done
printf '%s\n' "${results[@]}" | sort -n | awk '{a[NR]=$1} END {print "median=" a[int((NR+1)/2)]}'
