#!/usr/bin/env bash
# rust-dns vs dnsmasq: same data (N A records), same query mix, same Linux
# container, server and dnsperf pinned to separate cores. macOS loopback
# caps UDP at a few thousand queries/s, so this runs in a Linux container
# (podman or docker). Usage:
#   scripts/bench-dnsmasq/run.sh <linux rust-dns binary> [RECORDS] [SECONDS] [ROUNDS]
# e.g. cargo zigbuild --release --target aarch64-unknown-linux-musl, then
#   scripts/bench-dnsmasq/run.sh target/aarch64-unknown-linux-musl/release/rust-dns
# Prints one RESULT line per round, for the server on 1 core and on 4 cores.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:?linux rust-dns binary}"; N="${2:-1000}"; DUR="${3:-15}"; ROUNDS="${4:-3}"
ENGINE="$(command -v podman || command -v docker)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cp "$HERE/bench.sh" "$HERE/seed.py" "$TMP/"; cp "$BIN" "$TMP/rust-dns"
"$ENGINE" build -q -t localhost/rdns-bench -f "$HERE/Containerfile" "$HERE" >/dev/null
for srv in 0 0-3; do
  "$ENGINE" run --rm -e SRV_CPUS=$srv -e CLI_CPUS=4-7 -v "$TMP:/bench:ro" localhost/rdns-bench \
    bash /bench/bench.sh "$N" "$DUR" "$ROUNDS" 2>&1 | grep '^RESULT\|^RSS'
done
