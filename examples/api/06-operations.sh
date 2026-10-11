#!/usr/bin/env bash
# Status, change log, metrics, health, config reload and integrity check.
set -euo pipefail
source "$(dirname "$0")/_env.sh"

echo "== liveness (no auth needed)"
curl -sS "$RDNS_URL/rust-dns/api/health"; echo

echo "== status: counters, rate limit, cache, listeners"
api GET /status

echo "== change log: last 5 entries, then everything after an offset"
api GET "/changelog?limit=5"
api GET "/changelog?after=0&limit=3"

echo "== Prometheus metrics (first lines)"
curl -sS --fail-with-body -H "Authorization: Bearer $RDNS_TOKEN" "$RDNS_URL/rust-dns/metrics" | head -12

echo "== re-read the config file (same as kill -HUP); admin only"
api POST /admin/reload

echo "== full SQLite integrity check; admin only"
api GET /admin/integrity

echo "== live change + query stream over websocket (needs websocat):"
echo "   websocat -H 'Authorization: Bearer \$RDNS_TOKEN' '${RDNS_URL/http/ws}/rust-dns/api/ws?queries=true'"
