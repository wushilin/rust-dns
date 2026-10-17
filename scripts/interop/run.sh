#!/usr/bin/env bash
# Interoperability and standards checks of rust-dns with independent DNS
# implementations. Runs inside the rust-dns-interop image
# (scripts/interop/Containerfile); start it with scripts/interop-local.sh.
#
# Starts rust-dns on 127.0.0.1:53 inside the container (port 53, because
# DNSViz and genreport cannot use another port), seeds the conformance
# fixture (scripts/seed-conformance.py + seed-conformance-extra.py), then:
#
#  1. Transfers every zone (AXFR, RFC 5936) with two clients, BIND's dig
#     and Knot's kdig, and requires the same records from both (compared
#     after parsing with dnspython, a third implementation).
#  2. Checks every transferred zone with three zone checkers: BIND's
#     named-checkzone (RFC 1034/1035/2181 structure: SOA, NS, glue,
#     CNAME and other data, MX/SRV targets), Knot's semantic checks
#     (`knotc zone-check`, with DNSSEC validation for signed zones), and for
#     signed zones BIND's dnssec-verify and NLnet Labs' ldns-verify-zone
#     (RFC 4033-4035, 5155 NSEC3, 6605/8080 algorithms: every RRset
#     signed, every signature valid, the NSEC or NSEC3 chain complete).
#  3. Validates live answers of every signed zone with BIND's delv, the
#     zone's DNSKEY as trust anchor: positive answers, CNAME and DNAME,
#     wildcards, NXDOMAIN, NODATA, empty non-terminals and DS denial.
#  4. Analyses every signed zone with DNSViz (authoritative analysis, EDNS
#     probes, DS from dnssec-dsfromkey): no errors and no warnings.
#  5. Runs ISC's DNS Compliance Testing tool (genreport, the DNS Flag Day
#     tool; EDNS RFC 6891, DNS cookies RFC 7873, flags, opcodes, TCP) on
#     an unsigned and a signed zone: every test "ok".
#  6. With INTEROP_ZONEMASTER=1 (its own image), runs Zonemaster on every
#     signed zone: no warnings or errors beyond the test setup's.
#
# Prints PASS/FAIL per check and exits 1 when any check failed.
set -uo pipefail

BIN="${RUST_DNS_BIN:-/usr/local/bin/rust-dns}"
SCRIPTS="${INTEROP_SCRIPTS:-/scripts}"
W="$(mktemp -d)"
ZONES="example.test 0.0.10.in-addr.arpa signed.test nsec3.test ed25519.test rrtypes.test"
SIGNED="signed.test nsec3.test ed25519.test rrtypes.test"
PASSED=0
FAILED=0
FAILURES=()

pass() { PASSED=$((PASSED + 1)); echo "PASS $1"; }
fail() {
  FAILED=$((FAILED + 1))
  FAILURES+=("$1")
  echo "FAIL $1"
  [ -n "${2:-}" ] && sed 's/^/     | /' <<<"$2" | head -n "${INTEROP_SHOW:-25}"
  return 0
}
# check NAME CMD...: passes when CMD exits 0; shows its output otherwise.
check() {
  local name="$1"
  shift
  local out
  if out="$("$@" 2>&1)"; then pass "$name"; else fail "$name" "$out"; fi
}

cat >"$W/config.toml" <<EOF
[server]
bind = ["127.0.0.1"]
port = 53
nsid = "ns1.example.test"
cookies = true

[rate_limit]
# DNSViz and genreport send bursts; rate limiting has its own tests.
max_resolutions_per_second_per_address = 0

[transfer]
allow = ["127.0.0.0/8"]

[forwarding]
# No upstreams: foreign names stay REFUSED (not an open resolver).
upstreams = []
allowed_clients = ["127.0.0.0/8"]

[database]
path = "$W/rust-dns.db"

[backup]
dir = ""

[web_console]
bind = "127.0.0.1:8053"

[root]
username = "root"
password = "ci-root-password"

[logging]
level = "warn"
EOF

"$BIN" --config "$W/config.toml" >"$W/server.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null; wait $PID 2>/dev/null' EXIT
"$BIN" --version
python3 "$SCRIPTS/seed-conformance.py" http://127.0.0.1:8053 >/dev/null || { cat "$W/server.log"; exit 2; }
python3 "$SCRIPTS/seed-conformance-extra.py" http://127.0.0.1:8053 >/dev/null || { cat "$W/server.log"; exit 2; }
python3 "$SCRIPTS/interop/seed-interop.py" http://127.0.0.1:8053 >/dev/null || { cat "$W/server.log"; exit 2; }
echo "tools: $(dig -v 2>&1 | head -1), knot $(kdig -V | awk '{print $NF}'), ldns $(ldns-verify-zone -v 2>&1 | head -1 | awk '{print $NF}' | tr -d ')'), dnsviz $(pip3 show dnsviz 2>/dev/null | awk '/^Version/ {print $2}')"

# ---- 1. zone transfers ---------------------------------------------------
for z in $ZONES; do
  dig @127.0.0.1 +nocmd +nostats +nocomments +onesoa +nocookie "$z" AXFR >"$W/$z.zone"
  kdig @127.0.0.1 +noall +answer "$z" AXFR >"$W/$z.kdig"
  n=$(grep -cv '^;' "$W/$z.zone")
  if head -1 "$W/$z.zone" | grep -q $'\tSOA\t\|[[:space:]]SOA[[:space:]]' && [ "$n" -gt 1 ]; then
    pass "5936: AXFR $z with dig ($n records)"
  else
    fail "5936: AXFR $z with dig" "$(head -5 "$W/$z.zone")"
  fi
  check "5936: AXFR $z with kdig: the same records (dnspython)" \
    python3 "$SCRIPTS/interop/same-zone.py" "$z" "$W/$z.zone" "$W/$z.kdig"
done

# ---- 2. zone checkers ----------------------------------------------------
# Knot DNS checks a zone file offline with `knotc zone-check` (no server
# runs); -f turns semantic-check warnings into errors.
knot_check() {
  local z="$1" dnssec="$2" d="$W/knot-$1-$2"
  mkdir -p "$d"
  cp "$W/$z.zone" "$d/$z.zone"
  cat >"$d/knot.conf" <<EOF
server:
    rundir: "$d"
database:
    storage: "$d"
template:
  - id: default
    storage: "$d"
    semantic-checks: on
    dnssec-validation: $dnssec
zone:
  - domain: $z
    file: $z.zone
EOF
  knotc -f -c "$d/knot.conf" zone-check "$z"
}
for z in $ZONES; do
  # -i local: integrity of in-zone MX/SRV/NS targets and glue (no lookups
  # of out-of-zone names); the -m/-M/-n/-S checks are fatal.
  check "1034/1035/2181: named-checkzone $z" \
    named-checkzone -i local -k fail -m fail -M fail -n fail -S fail -W warn "$z" "$W/$z.zone"
  check "1034/1035: Knot zone-check $z" knot_check "$z" off
done
for z in $SIGNED; do
  # -z: rust-dns signs with one key (a CSK, flags 257) that signs every
  # RRset; without it dnssec-verify asks for a separate ZSK.
  check "4033-4035/5155: dnssec-verify $z" dnssec-verify -z -o "$z" "$W/$z.zone"
  check "4033-4035/5155: ldns-verify-zone $z" ldns-verify-zone -V 2 "$W/$z.zone"
  check "4033-4035/5155: Knot zone-check with DNSSEC validation $z" knot_check "$z" on
done

# ---- 3. live validation with delv ----------------------------------------
# name type expect: expect is "pos" (fully validated answer) or "neg"
# (fully validated negative answer).
QUERIES_SIGNED="@:SOA:pos @:NS:pos @:MX:pos @:TXT:pos @:DNSKEY:pos www:A:pos www:AAAA:pos
alias:A:pos ext:CNAME:pos x.gate:A:pos y.x.gate:A:pos a.b.deep:TXT:pos _dmarc:TXT:pos www.old:A:pos
many:A:pos big:TXT:pos secure:DS:pos
nope:A:neg www:MX:neg b.deep:A:neg x.gate:MX:neg sub:DS:neg gate:TXT:neg"
QUERIES_RRTYPES="@:SOA:pos loc:LOC:pos rp:RP:pos afs:AFSDB:pos _http._tcp:URI:pos spf:SPF:pos
mac:EUI48:pos mac:EUI64:pos nope:A:neg loc:A:neg"
for z in $SIGNED; do
  key=$(awk '$4 == "DNSKEY" && $5 == 257 { printf "%s %s %s \"", $5, $6, $7; for (i = 8; i <= NF; i++) printf "%s", $i; print "\"" }' "$W/$z.zone" | head -1)
  printf 'trust-anchors { "%s." static-key %s; };\n' "$z" "$key" >"$W/$z.anchor"
  if [ "$z" = rrtypes.test ]; then qs=$QUERIES_RRTYPES; else qs=$QUERIES_SIGNED; fi
  bad=""
  count=0
  for q in $qs; do
    IFS=: read -r n t want <<<"$q"
    if [ "$n" = @ ]; then fq="$z"; else fq="$n.$z"; fi
    for transport in +notcp +tcp; do
      out=$(delv @127.0.0.1 -a "$W/$z.anchor" +root="$z" "$transport" "$fq" "$t" 2>&1)
      count=$((count + 1))
      case "$want" in
        pos) grep -q '^; fully validated' <<<"$out" || bad+="$fq $t ($transport): $(head -3 <<<"$out" | tr '\n' ' ')"$'\n' ;;
        neg) grep -q '^; negative response, fully validated' <<<"$out" || bad+="$fq $t ($transport): $(head -3 <<<"$out" | tr '\n' ' ')"$'\n' ;;
      esac
    done
  done
  if [ -z "$bad" ]; then pass "4035/5155: delv $z: $count answers fully validated"; else fail "4035/5155: delv $z" "$bad"; fi
done

# ---- 4. DNSViz -------------------------------------------------------------
for z in $SIGNED; do
  # The DS a parent would publish, as a zone file (dnsviz -D takes a path).
  dnssec-dsfromkey -2 -f "$W/$z.zone" "$z" >"$W/$z.ds" 2>/dev/null
  awk '$4 == "DNSKEY" && $5 == 257' "$W/$z.zone" >"$W/$z.tk"
  # -N/-D: a delegation as the parent would publish it (NS and DS).
  if dnsviz probe -A -E -N "$z:ns1.$z=127.0.0.1" -D "$z:$W/$z.ds" -o "$W/$z.probe.json" "$z" >"$W/$z.probe.log" 2>&1 \
    && dnsviz grok -t "$W/$z.tk" -o "$W/$z.grok.json" <"$W/$z.probe.json" 2>>"$W/$z.probe.log"; then
    status=$(python3 - "$W/$z.grok.json" "$z" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
zone = doc.get(sys.argv[2] + ".", {})
# The test server listens on 127.0.0.1, an address DNSViz rightly flags
# for a public zone; these two codes come from the setup, not the server.
SETUP = {"NS_NAME_PRIVATE_IP", "GLUE_PRIVATE_IP"}
problems = []
def walk(path, v):
    if isinstance(v, dict):
        for k in ("errors", "warnings"):
            for e in v.get(k, []):
                if e.get("code") not in SETUP:
                    problems.append(f"{k[:-1]} at {path}: {e.get('code', '')}: {e.get('description', e)}")
        for k, x in v.items():
            if k not in ("errors", "warnings"):
                walk(f"{path}/{k}", x)
    elif isinstance(v, list):
        for i, x in enumerate(v):
            walk(f"{path}[{i}]", x)
walk(sys.argv[2], zone)
# The DNSSEC status of the delegation: SECURE, INSECURE, BOGUS, ...
print(zone.get("delegation", {}).get("status", "?") if zone else "missing; top-level keys: " + ", ".join(doc))
for p in problems:
    print(p)
PY
)
    first=$(head -1 <<<"$status")
    rest=$(tail -n +2 <<<"$status")
    if [ "$first" = SECURE ] && [ -z "$rest" ]; then
      pass "DNSViz $z: SECURE, no errors or warnings"
    else
      fail "DNSViz $z: status $first" "$rest"
    fi
  else
    fail "DNSViz $z: probe/grok ran" "$(tail -20 "$W/$z.probe.log")"
  fi
done

# ---- 5. ISC DNS Compliance Testing (genreport) ----------------------------
for z in example.test signed.test; do
  out=$(echo "$z ns1.$z 127.0.0.1" | genreport -f -o 2>&1)
  # One line per server: "zone. @addr (ns.): test=result ..."; a result
  # is "ok", optionally with notes ("ok,nsid"), or the problems found
  # ("nocd": the CD bit was not copied, RFC 4035 section 3.1.6).
  bad=$(tr ' ' '\n' <<<"$out" | grep '=' | grep -v '=ok\(,\|$\)' || true)
  if [ -n "$out" ] && [ -z "$bad" ]; then
    pass "6891/7873/1035: genreport $z: $(tr ' ' '\n' <<<"$out" | grep -c '=ok') tests ok"
  else
    fail "6891/7873/1035: genreport $z" "${bad:-$out}"
  fi
done

# ---- 6. Zonemaster (optional image) ---------------------------------------
# Only in the rust-dns-interop-zonemaster image (INTEROP_ZONEMASTER=1).
# Undelegated test (--ns, --ds): every test case at WARNING or above fails,
# except three that judge the test setup, not the server: Address01 and
# Address02 (127.0.0.1 is not globally reachable and has no PTR) and
# Delegation01 (the fixture zones have one name server, not two).
if command -v zonemaster-cli >/dev/null 2>&1; then
  for z in $SIGNED; do
    ds=$(awk '{ print $4 "," $5 "," $6 "," $7 }' "$W/$z.ds" | head -1)
    out=$(zonemaster-cli --no-ipv6 --level WARNING --show-testcase --ns "ns1.$z/127.0.0.1" --ds "$ds" "$z" 2>&1)
    bad=$(grep -E '^ *[0-9.]+ +(WARNING|ERROR|CRITICAL) ' <<<"$out" | grep -Ev ' (Address01|Address02|Delegation01) ' || true)
    if grep -q '^Seconds Level' <<<"$out" && [ -z "$bad" ]; then
      pass "Zonemaster $z: no warnings or errors (Address01/02, Delegation01: setup)"
    else
      fail "Zonemaster $z" "${bad:-$out}"
    fi
  done
fi

echo
echo "$PASSED passed, $FAILED failed"
for f in "${FAILURES[@]}"; do echo "  failed: $f"; done
if [ "${INTEROP_KEEP:-0}" = 1 ]; then echo "work files kept in $W"; fi
[ "$FAILED" -eq 0 ]
