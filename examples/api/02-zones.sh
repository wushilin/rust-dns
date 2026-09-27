#!/usr/bin/env bash
# Create a forward zone and IPv4 / IPv6 reverse zones, then inspect and update them.
# Creating zones requires an administrator token.
set -euo pipefail
source "$(dirname "$0")/_env.sh"

echo "== create forward zone $ZONE"
api POST /zones '{
  "name": "'"$ZONE"'",
  "soa_mname": "ns1.'"$ZONE"'",
  "soa_rname": "hostmaster@'"$ZONE"'",
  "default_ttl": 300
}'

echo "== create IPv4 reverse zone for 192.0.2.0/24"
api POST /zones '{"name": "2.0.192.in-addr.arpa"}'

echo "== create IPv6 reverse zone for 2001:db8::/32"
api POST /zones '{"name": "8.b.d.0.1.0.0.2.ip6.arpa"}'

echo "== list zones visible to this token"
api GET /zones

echo "== one zone with its first page of records and members"
api GET "/zones/$ZONE"

echo "== update SOA timers (the serial increments automatically)"
api PUT "/zones/$ZONE" '{"refresh": 7200, "retry": 900, "minimum": 600}'
