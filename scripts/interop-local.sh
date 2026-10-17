#!/usr/bin/env bash
# Check rust-dns against independent, open source DNS implementations:
# BIND 9, Knot DNS, ldns, DNSViz, dnspython and ISC's DNS Compliance
# Testing tool (genreport). See docs/COMPLIANCE.md for what each check
# proves and the RFCs it covers.
#
#   scripts/interop-local.sh [rust-dns-binary]
#
# Everything runs in a container (image rust-dns-interop, built from
# scripts/interop/Containerfile on first use; INTEROP_REBUILD=1 rebuilds
# it), so the host needs only podman or docker. The binary is mounted into
# a Fedora 42 container: use a Linux build for the container's
# architecture (the static musl release binary runs anywhere; a glibc
# build needs glibc 2.41 or older on the build host).
#
# Exit status: 0 = every check passed, 1 = a check failed, 2 = setup
# failure, 77 = skipped (no container runtime; INTEROP_REQUIRED=1 makes
# that a failure).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-}"
if [ -z "$BIN" ]; then
  for b in "$ROOT/target/release/rust-dns" "$ROOT/target/debug/rust-dns"; do
    if [ -x "$b" ]; then BIN="$b"; break; fi
  done
fi
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
  echo "binary not found: ${BIN:-target/{release,debug}/rust-dns} (run cargo build first)" >&2
  exit 2
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

RT="${CONTAINER_RUNTIME:-}"
if [ -z "$RT" ]; then
  for r in podman docker; do
    if command -v "$r" >/dev/null 2>&1; then RT="$r"; break; fi
  done
fi
if [ -z "$RT" ]; then
  echo "SKIP: interop checks need podman or docker (neither found)" >&2
  [ "${INTEROP_REQUIRED:-0}" = 1 ] && exit 2
  exit 77
fi

IMAGE=rust-dns-interop
if [ "${INTEROP_REBUILD:-0}" = 1 ] || ! "$RT" image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "building $IMAGE (BIND, Knot, ldns, DNSViz, genreport)" >&2
  "$RT" build -t "$IMAGE" -f "$ROOT/scripts/interop/Containerfile" "$ROOT/scripts/interop" >&2
fi
# INTEROP_ZONEMASTER=1: the same checks plus Zonemaster, in an image built
# on top of the first one (Zonemaster from CPAN: 10-20 minutes the first time).
if [ "${INTEROP_ZONEMASTER:-0}" = 1 ]; then
  IMAGE=rust-dns-interop-zonemaster
  if [ "${INTEROP_REBUILD:-0}" = 1 ] || ! "$RT" image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "building $IMAGE (Zonemaster)" >&2
    "$RT" build -t "$IMAGE" -f "$ROOT/scripts/interop/Containerfile.zonemaster" "$ROOT/scripts/interop" >&2
  fi
fi

# :Z relabels for SELinux hosts; harmless elsewhere.
exec "$RT" run --rm \
  -e INTEROP_SHOW="${INTEROP_SHOW:-25}" \
  -v "$ROOT/scripts:/scripts:ro,Z" \
  -v "$BIN:/usr/local/bin/rust-dns:ro,Z" \
  "$IMAGE" bash /scripts/interop/run.sh
