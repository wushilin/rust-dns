# Shared settings for the example scripts. Source it, or export the variables
# yourself:
#   export RDNS_URL=http://127.0.0.1:8053
#   export RDNS_TOKEN=rdns_...            # create one with 01-token.sh
#
# API tokens are sent as a bearer header. Token requests need no CSRF header;
# only browser (cookie) sessions must send X-Requested-With: rust-dns.

RDNS_URL="${RDNS_URL:-http://127.0.0.1:8053}"
ZONE="${ZONE:-example.com}"

if [ -z "${RDNS_TOKEN:-}" ] && [ "${NEED_TOKEN:-1}" = "1" ]; then
  echo "RDNS_TOKEN is not set. Run 01-token.sh first, then export RDNS_TOKEN." >&2
  exit 2
fi

# api METHOD PATH [JSON-BODY]
# Prints the response body. Exits non-zero on an HTTP error, showing the error JSON.
api() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS --fail-with-body -X "$method" -H "Authorization: Bearer ${RDNS_TOKEN}")
  if [ -n "$body" ]; then
    args+=(-H "Content-Type: application/json" --data "$body")
  fi
  curl "${args[@]}" "${RDNS_URL}/api${path}"
  echo
}

# json_field FIELD: read one top-level field from JSON on stdin (python3, stdlib only)
json_field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}
