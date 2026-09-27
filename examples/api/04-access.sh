#!/usr/bin/env bash
# Users and per-zone access. Requires an administrator token.
set -euo pipefail
source "$(dirname "$0")/_env.sh"

echo "== create a user who must enroll TOTP at first sign-in"
api POST /users '{"username": "alice", "password": "alice-initial-pass", "display_name": "Alice", "mfa_required": true}'

echo "== let alice edit records in $ZONE (roles: editor, viewer)"
api PUT "/zones/$ZONE/members/alice" '{"role": "editor"}'

echo "== change alice to read-only"
api PUT "/zones/$ZONE/members/alice" '{"role": "viewer"}'

echo "== transfer zone ownership (admins only)"
api PUT "/zones/$ZONE" '{"owner": "alice"}'
api PUT "/zones/$ZONE" '{"owner": "root"}'

echo "== list users"
api GET /users

echo "== remove alice's access, then sign her out everywhere and disable her"
api DELETE "/zones/$ZONE/members/alice"
alice=$(api GET /users | python3 -c 'import json,sys; print([u["id"] for u in json.load(sys.stdin)["users"] if u["username"]=="alice"][0])')
api POST "/users/$alice/sessions/revoke"
api PUT "/users/$alice" '{"disabled": true}'

echo "== API tokens of this user"
api GET /tokens
