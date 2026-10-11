#!/usr/bin/env bash
# Export and import zones as JSON. (BIND zone-file import/export was removed.)
set -euo pipefail
source "$(dirname "$0")/_env.sh"
out="$(mktemp -d)"

echo "== export one zone as JSON"
curl -sS --fail-with-body -H "Authorization: Bearer $RDNS_TOKEN" \
  "$RDNS_URL/rust-dns/api/zones/$ZONE/export?format=json" -o "$out/$ZONE.json"

echo "== export every zone this token can see"
curl -sS --fail-with-body -H "Authorization: Bearer $RDNS_TOKEN" \
  "$RDNS_URL/rust-dns/api/export" -o "$out/all.json"
echo "saved to $out"

echo "== import JSON (mode=merge adds missing zones/records; mode=replace replaces records of listed zones)"
api POST "/import?mode=merge" '{
  "version": 1,
  "exported_at": "",
  "zones": [{
    "name": "imported.example",
    "default_ttl": 600,
    "records": [
      {"name": "@",   "type": "A",   "value": "192.0.2.80"},
      {"name": "www", "type": "CNAME", "value": "imported.example."},
      {"name": "@",   "type": "TXT", "value": "hello from JSON import", "ttl": 60}
    ]
  }]
}'
