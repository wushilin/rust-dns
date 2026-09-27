#!/usr/bin/env bash
# Human-readable dig walkthrough against a running instance populated by
# tests/e2e.rs or by hand. Usage: scripts/e2e-dig.sh [zone] [server-ip] [port]
set -uo pipefail
ZONE="${1:-example.test}"; IP="${2:-127.0.0.1}"; P="${3:-53}"
D="dig @$IP -p $P +noall +answer +authority +comments +time=2 +tries=1"
f() { grep -E "status|IN|flags"; }
echo "=== A (udp)";            $D www.$ZONE A | f
echo "=== AAAA (tcp)";         $D +tcp www.$ZONE AAAA | f
echo "=== SOA";                $D $ZONE SOA | f
echo "=== NS + glue";          dig @$IP -p $P +noall +answer +additional $ZONE NS
echo "=== MX + glue";          dig @$IP -p $P +noall +answer +additional $ZONE MX
echo "=== CNAME chase";        $D alias.$ZONE A | f
echo "=== wildcard";           $D Foo.Apps.$ZONE A | f
echo "=== NXDOMAIN";           $D nope.$ZONE A | f
echo "=== NODATA";             $D www.$ZONE MX | f
echo "=== auto PTR";           $D -x 10.0.0.1 | f
echo "=== ANY (RFC 8482)";     $D $ZONE ANY | f
echo "=== EDNS";               dig @$IP -p $P +bufsize=1232 www.$ZONE A | grep -E "flags|EDNS"
echo "=== version.bind";       dig @$IP -p $P +short CH TXT version.bind
echo "=== foreign +norecurse"; dig @$IP -p $P +norecurse +noall +comments example.org A | grep status
echo "=== AXFR";               dig @$IP -p $P +noall +comments $ZONE AXFR | grep -E "status"
echo "=== EDNS v1";            dig @$IP -p $P +edns=1 +noall +comments www.$ZONE A | grep status
