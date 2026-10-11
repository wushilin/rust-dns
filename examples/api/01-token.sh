#!/usr/bin/env bash
# Sign in with a username and password and create an API token.
#   RDNS_USER=root RDNS_PASSWORD=... ./01-token.sh
# The token is printed once; store it and export it as RDNS_TOKEN.
set -euo pipefail
NEED_TOKEN=0 source "$(dirname "$0")/_env.sh"
: "${RDNS_USER:=root}"
: "${RDNS_PASSWORD:?set RDNS_PASSWORD}"

jar="$(mktemp)"; trap 'rm -f "$jar"' EXIT

# 1. Sign in. The session cookie lands in the cookie jar.
login=$(curl -sS --fail-with-body -c "$jar" -H "Content-Type: application/json" \
  --data "{\"username\":\"${RDNS_USER}\",\"password\":\"${RDNS_PASSWORD}\"}" \
  "${RDNS_URL}/rust-dns/api/auth/login")
status=$(printf '%s' "$login" | json_field status)
if [ "$status" = "mfa_required" ]; then
  # 1b. Accounts with MFA: send a TOTP code (or a recovery code).
  : "${RDNS_TOTP:?MFA is enabled for this account: set RDNS_TOTP to a current code}"
  curl -sS --fail-with-body -b "$jar" -H "Content-Type: application/json" \
    --data "{\"code\":\"${RDNS_TOTP}\"}" "${RDNS_URL}/rust-dns/api/auth/mfa" >/dev/null
elif [ "$status" != "ok" ]; then
  echo "login status: $status (complete MFA enrollment in the console first)" >&2
  exit 1
fi

# 2. Create a token. Cookie-authenticated writes must send X-Requested-With.
curl -sS --fail-with-body -b "$jar" -H "Content-Type: application/json" \
  -H "X-Requested-With: rust-dns" \
  --data '{"name":"examples"}' "${RDNS_URL}/rust-dns/api/tokens" | json_field token
