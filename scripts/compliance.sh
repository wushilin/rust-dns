#!/usr/bin/env bash
# Run ISC's DNS Compliance Testing suite (genreport, the DNS Flag Day tool)
# against a running rust-dns instance.
#
#   scripts/compliance.sh <zone> [server-ip] [port]
#
# Builds genreport from https://gitlab.isc.org/isc-projects/DNS-Compliance-Testing
# on first use (needs a C compiler and OpenSSL headers).
set -euo pipefail
ZONE="${1:?usage: $0 <zone> [server-ip] [port]}"
IP="${2:-127.0.0.1}"
PORT="${3:-53}"
DIR="${GENREPORT_DIR:-$(cd "$(dirname "$0")/.." && pwd)/target/genreport}"
if [ ! -x "$DIR/genreport" ]; then
  echo "building genreport in $DIR" >&2
  rm -rf "$DIR"
  git clone -q --depth 1 https://gitlab.isc.org/isc-projects/DNS-Compliance-Testing.git "$DIR"
  cat > "$DIR/config.h" <<'H'
#define HAVE_STRLCPY 1
#define HAVE_STRLCAT 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_NETINET_IN_H 1
#define HAVE_ARPA_NAMESER_H 1
#define HAVE_RESOLV_H 1
H
  if [ "$(uname)" = "Darwin" ]; then
    printf '#define HAVE_SIN_LEN 1\n#define HAVE_SIN6_LEN 1\n' >> "$DIR/config.h"
    SSL="$(brew --prefix openssl@3 2>/dev/null || echo /usr/local/opt/openssl)"
    cc -O2 -I"$DIR" -I"$SSL/include" -L"$SSL/lib" -o "$DIR/genreport" "$DIR/genreport.c" -lresolv -lcrypto
  else
    cc -O2 -I"$DIR" -o "$DIR/genreport" "$DIR/genreport.c" -lresolv -lcrypto
  fi
fi
echo "== full protocol tests (EDNS, flags, opcodes, TCP)"
echo "$ZONE ns.$ZONE $IP" | "$DIR/genreport" -f -o -P "$PORT"
echo "== all record types"
echo "$ZONE ns.$ZONE $IP" | "$DIR/genreport" -t -o -P "$PORT"
echo "== failures only (empty line after the server name = all good)"
echo "$ZONE ns.$ZONE $IP" | "$DIR/genreport" -f -B -o -P "$PORT"
