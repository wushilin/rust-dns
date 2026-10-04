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

[forwarding]
# No upstreams: foreign names stay REFUSED (and RA clear); the ACL lets
# 127.0.0.1 use the override zone seeded below.
upstreams = []
allowed_clients = ["127.0.0.0/8"]

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
# An override zone (I1) for the override checks (CONFORMANCE_OVERRIDE).
python3 - "http://127.0.0.1:$WEB_PORT" <<'PY'
import http.cookiejar, json, sys, urllib.request
base = sys.argv[1]
jar = http.cookiejar.CookieJar()
o = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
def req(path, body):
    tok = next((c.value for c in jar if c.name in ("rdns_csrf", "__Host-rdns_csrf")), "")
    r = urllib.request.Request(base + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", "X-Requested-With": "rust-dns", "X-CSRF-Token": tok})
    o.open(r, timeout=5).read()
req("/api/auth/login", {"username": "root", "password": "ci-root-password"})
req("/api/zones", {"name": "vpn.signed.test", "override": {"mode": "static"}})
req("/api/zones/vpn.signed.test/records", {"name": "gw", "type": "A", "value": "10.8.0.1"})
# O24: a copy of signed.test signed with NSEC3 (CONFORMANCE_NSEC3).
r = o.open(urllib.request.Request(base + "/api/zones/signed.test/export"), timeout=5).read()
doc = json.loads(r)
z = doc["zones"][0]
z["name"] = "nsec3.test"
for k in ("soa_mname", "soa_rname"):
    z[k] = z[k].replace("signed.test", "nsec3.test")
for rec in z["records"]:
    rec["value"] = rec["value"].replace("signed.test", "nsec3.test")
    rec.pop("id", None)
req("/api/import?mode=merge", doc)
r = urllib.request.Request(base + "/api/zones/nsec3.test/dnssec", data=json.dumps({"enabled": True, "denial": "nsec3"}).encode(), method="PUT",
    headers={"Content-Type": "application/json", "X-Requested-With": "rust-dns", "X-CSRF-Token": next((c.value for c in jar if c.name in ("rdns_csrf", "__Host-rdns_csrf")), "")})
st = json.loads(o.open(r, timeout=5).read())
assert st["state"] == "signing" and st["denial"] == "nsec3", st
PY
CONFORMANCE_NSEC3=nsec3.test CONFORMANCE_OVERRIDE=vpn.signed.test python3 "$ROOT/scripts/conformance.py" "$ZONE" 127.0.0.1 "$DNS_PORT"
if [ "${RUN_COMPLIANCE:-0}" = "1" ]; then
  "$ROOT/scripts/compliance.sh" "$ZONE" 127.0.0.1 "$DNS_PORT"
fi
