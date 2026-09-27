#!/usr/bin/env bash
# Export and import zones as JSON or BIND zone files.
set -euo pipefail
source "$(dirname "$0")/_env.sh"
here="$(cd "$(dirname "$0")" && pwd)"
out="$(mktemp -d)"

echo "== export one zone as a BIND zone file"
curl -sS --fail-with-body -H "Authorization: Bearer $RDNS_TOKEN" \
  "$RDNS_URL/api/zones/$ZONE/export?format=bind" -o "$out/$ZONE.zone"
head -5 "$out/$ZONE.zone"

echo "== export one zone as JSON"
curl -sS --fail-with-body -H "Authorization: Bearer $RDNS_TOKEN" \
  "$RDNS_URL/api/zones/$ZONE/export?format=json" -o "$out/$ZONE.json"

echo "== export every zone this token can see"
curl -sS --fail-with-body -H "Authorization: Bearer $RDNS_TOKEN" \
  "$RDNS_URL/api/export" -o "$out/all.json"
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

echo "== import a BIND zone file into an existing zone (text/plain body)"
api POST /zones '{"name": "bind-import.example"}'
sed 's/example\.com\./bind-import.example./g' "$here/../zones/example.com.zone" > "$out/bind-import.zone"
curl -sS --fail-with-body -X POST -H "Authorization: Bearer $RDNS_TOKEN" \
  -H "Content-Type: text/plain" --data-binary @"$out/bind-import.zone" \
  "$RDNS_URL/api/zones/bind-import.example/import-bind?mode=replace"
echo
