#!/usr/bin/env bash
# Byte-level equivalence check of two rust-dns binaries.
#
#   scripts/equivalence-local.sh BASE_BIN NEW_BIN [--keep] [--show N] [--workdir DIR]
#
# Seeds one BASE instance through the HTTP API, copies its database twice,
# runs BASE and NEW side by side (each forwarding to its own deterministic
# fake upstream) and compares the raw bytes of thousands of answers (see
# scripts/equivalence.py for the matrix and the exact normalisations).
# Exit status: 0 = no differences, 1 = differences, 2 = setup failure.
#
# Needs Python 3 with dnspython: the first of $PYTHON, python3 on PATH
# that can `import dns`.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ $# -lt 2 ]; then
  echo "usage: $0 BASE_BIN NEW_BIN [--keep] [--show N] [--workdir DIR]" >&2
  exit 2
fi
BASE="$1"
NEW="$2"
shift 2
for b in "$BASE" "$NEW"; do
  if [ ! -x "$b" ]; then
    echo "binary not found or not executable: $b" >&2
    exit 2
  fi
done

PY=""
for cand in "${PYTHON:-}" python3 python; do
  [ -n "$cand" ] || continue
  if command -v "$cand" >/dev/null 2>&1 && "$cand" -c 'import dns.message' 2>/dev/null; then
    PY="$cand"
    break
  fi
done
if [ -z "$PY" ]; then
  echo "need Python 3 with dnspython (set PYTHON=/path/to/python or put it on PATH)" >&2
  exit 2
fi

# equivalence.py stops every process it started and removes its temp
# directory itself (unless --keep); this trap only makes sure an interrupted
# run does not leave the Python driver (and through it the servers) behind.
CHILD=""
cleanup() {
  if [ -n "$CHILD" ] && kill -0 "$CHILD" 2>/dev/null; then
    kill -TERM "$CHILD" 2>/dev/null || true
    wait "$CHILD" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

"$PY" "$ROOT/scripts/equivalence.py" --base "$BASE" --new "$NEW" "$@" &
CHILD=$!
set +e
wait "$CHILD"
STATUS=$?
set -e
CHILD=""
exit "$STATUS"
