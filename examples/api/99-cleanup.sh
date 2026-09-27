#!/usr/bin/env bash
# Remove everything the example scripts created.
set -uo pipefail
source "$(dirname "$0")/_env.sh"
for z in "$ZONE" 2.0.192.in-addr.arpa 8.b.d.0.1.0.0.2.ip6.arpa imported.example bind-import.example; do
  api DELETE "/zones/$z" || true
done
alice=$(api GET /users | python3 -c 'import json,sys; print(next((u["id"] for u in json.load(sys.stdin)["users"] if u["username"]=="alice"), ""))')
[ -n "$alice" ] && api DELETE "/users/$alice"
