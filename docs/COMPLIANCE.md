# Standards compliance

How rust-dns is checked against the DNS standards, and by whom. The
server's own code never grades itself: every layer below is either a
different implementation of the protocol, or a check written from the RFC
text that cites the section it exercises.

## The layers

| Kit | What it is | Run with | Needs |
|---|---|---|---|
| `scripts/conformance.py` | About 130 checks written from the RFCs, each named after the section it exercises; DNSSEC answers validated with dnspython | `scripts/conformance-local.sh` | Python + dnspython, cryptography |
| `scripts/interop-local.sh` | The zones and live answers of a seeded server checked by independent implementations: BIND 9, Knot DNS, ldns, DNSViz, dnspython, ISC genreport (below) | `scripts/interop-local.sh` | podman or docker |
| `scripts/compliance.sh` | ISC's DNS Compliance Testing tool (genreport) against any running instance | `scripts/compliance.sh <zone> <ip> <port>` | C compiler, OpenSSL headers |
| `tests/dnssec.rs`, `tests/follow.rs` | BIND `dnssec-verify -z` and `delv` in the Rust suite (primary and standby) | `cargo test` (`REQUIRE_BIND_TOOLS=1`) | BIND tools |
| `src/dnssec/vectors.rs` | DNSSEC known-answer vectors from dnspython and BIND `dnssec-dsfromkey` | `cargo test` | none |
| `scripts/equivalence-local.sh` | Byte-for-byte comparison of two rust-dns builds over thousands of queries (catches unintended changes, not standards drift) | `scripts/equivalence-local.sh BASE NEW` | Python + dnspython |
| `compat/dnssec/wushilin_net.rs` | Google Public DNS validates the live `wushilin.net` DNSKEY (AD) through the root trust anchor | `cargo test --test compat_dnssec_wushilin_net` | internet |

## The interop kit

`scripts/interop-local.sh [binary]` builds the image
`rust-dns-interop` (`scripts/interop/Containerfile`, Fedora 42) on first
use and runs `scripts/interop/run.sh` in it: rust-dns on 127.0.0.1:53
inside the container, seeded with the conformance fixture
(`seed-conformance.py`, `seed-conformance-extra.py`, plus
`interop/seed-interop.py`, which gives the name servers addresses), then:

| Check | Implementation | RFCs | Zones |
|---|---|---|---|
| AXFR with two clients, the same records after parsing | BIND `dig`, Knot `kdig`, dnspython | 5936 | all 6 |
| Zone structure: SOA, NS and glue, CNAME and other data, MX/SRV targets not CNAMEs, in-zone targets exist | BIND `named-checkzone -i local -k/-m/-M/-n/-S fail` | 1034, 1035, 2181 | all 6 |
| Semantic checks, warnings fatal | Knot `knotc -f zone-check` | 1034, 1035 | all 6 |
| Every RRset signed, every signature valid, NSEC/NSEC3 chain complete | BIND `dnssec-verify -z`, NLnet Labs `ldns-verify-zone`, Knot `zone-check` with `dnssec-validation: on` | 4033, 4034, 4035, 5155, 6605, 8080 | signed: ECDSA P-256 NSEC, NSEC3, Ed25519, rrtypes |
| Live answers validate, UDP and TCP: positive, CNAME, DNAME, wildcard, multi-label wildcard, NXDOMAIN, NODATA, empty non-terminal, wildcard NODATA, DS at a signed cut, DS denial at an unsigned cut, a 700-byte TXT | BIND `delv`, the zone's DNSKEY as trust anchor | 4035 §3.1, 5155 §7.2, 4592, 6672, 8020 | 4 signed zones, 158 answers |
| Full DNSSEC and delegation analysis with EDNS probes, DS as a parent would publish it: SECURE, no errors or warnings | DNSViz 0.11.2 (`probe -A -E -N -D`, `grok`) | 4033-4035, 5155, 6891, 1034 §4.2.2 | 4 signed zones |
| EDNS (versions, options, flags, payload), DNS cookies, NSID, flags, unknown opcodes, TCP, DO/CD on a signed zone | ISC genreport (`-f`, every result must be `ok`) | 6891, 7873, 5001, 1035, 4035 §3.1.6, 7766 | example.test, signed.test |
| Zonemaster test suite, undelegated (`--ns`, `--ds`): name server (recursion, EDNS, AXFR, case, upward referrals), DNSSEC, consistency, delegation, syntax, zone; nothing at WARNING or above | Zonemaster 8.0.3 / Engine 9.0.1 (`INTEROP_ZONEMASTER=1`) | the RFCs each test case cites | 4 signed zones |

`INTEROP_ZONEMASTER=1` adds Zonemaster, from the image
`rust-dns-interop-zonemaster` (`scripts/interop/Containerfile.zonemaster`,
built on the first one from CPAN, 10-20 minutes the first time: the
published Zonemaster image is amd64 only, and Fedora's crypto policy must
allow SHA-1 for Zonemaster::LDNS).

Prints `PASS`/`FAIL` per check, the tool output under a failure, and
exits 1 when any check failed (77 when neither podman nor docker is
installed; `INTEROP_REQUIRED=1` makes that 2). The binary is mounted into
the container, so it must run on Fedora 42 for the host's architecture:
the static musl release binary always does.

DNSViz flags `NS_NAME_PRIVATE_IP` and `GLUE_PRIVATE_IP` for a name server
on 127.0.0.1; those two codes come from the test setup and are ignored.
Everything else DNSViz reports fails the check. Zonemaster likewise
ignores only Address01 and Address02 (127.0.0.1 is not globally
reachable and has no PTR) and Delegation01 (the fixture zones have one
name server; two are an operational requirement, RFC 1034 §4.1). The
verifiers are not
vacuous: with one RRSIG altered, or one NSEC removed, from a transferred
zone, `dnssec-verify` and `ldns-verify-zone` both fail.

### Current result

On 0.3.0 plus the fixes below (aarch64, 2026-10-17):

| Kit | Result |
|---|---|
| `scripts/interop-local.sh` with `INTEROP_ZONEMASTER=1` | 50 of 50 checks pass |
| `scripts/conformance-local.sh` | 164 of 164 checks pass, three runs in a row |
| `scripts/equivalence-local.sh` against 0.3.0 | 20,743 cases; the only differences (105) are the CD bit below, header byte 3 `0x80` -> `0x90` |

Fixed after the kit's first run:

- **CD bit not copied (RFC 4035 §3.1.6).** "A security-aware name server
  MUST copy the CD bit from a query into the corresponding response."
  0.3.0 answered every query with CD clear (genreport: `docd=nocd` on the
  signed zone; on an unsigned zone genreport does not test the bit, which
  is why `compliance.sh` against example.test never showed it). Every
  response to a query now carries the query's CD bit, whichever filter
  made it (authoritative, cached, stale, refused, relayed, transfers;
  `complete` in `src/dns/pipeline.rs`, before TSIG signs the bytes).
  `conformance.py` checks it on UDP and TCP, for answers, NXDOMAIN,
  REFUSED, an unsigned zone without EDNS, and its absence without CD.
- **Forward cache mixed CD=1 and CD=0 answers (RFC 6840 §5.9).** A query
  with CD makes a validating upstream skip validation; its answer was
  cached under the same key as a CD=0 query's, so a client asking for
  validated data could be served an unvalidated one. CD is now part of the
  cache key (`src/dns/fwdcache.rs`, unit test
  `answers_fetched_with_cd_are_not_served_without_it`).
- **The rate-limit checks measured the kernel, not the limiter.**
  `conformance.py` sent 700 datagrams in one burst; the server socket's
  receive buffer overflowed (kernel `RcvbufErrors`), the limiter never saw
  the excess, and "slip" failed intermittently while "drops beyond 500/s"
  passed for the wrong reason. The check now paces 1,400 queries in bursts
  of 20 and reads replies in between: 500 answered and 450 slip replies per
  window, with no kernel drops. The limiter was correct throughout.

Not a protocol issue, noted by the kit: a zone created without NS records
gets an NS synthesized from its SOA MNAME (`ns1.<zone>`, `src/zones.rs`),
which has no address unless one is added; `named-checkzone` rejects such a
zone. Give a zone real NS records (and glue) before delegating to it.

## Third-party suites considered

| Suite | Verdict |
|---|---|
| [ISC DNS Compliance Testing](https://gitlab.isc.org/isc-projects/DNS-Compliance-Testing) (genreport; the tool behind [ednscomp.isc.org](https://ednscomp.isc.org) and DNS Flag Day) | Used (`compliance.sh`, and strictly in the interop kit, also on a signed zone). The online service needs a public delegation. |
| [DNSViz](https://github.com/dnsviz/dnsviz) | Used. Fedora's 0.11.0 fails with dnspython 2.7 (`CookieOption.data`); the image installs 0.11.2 from PyPI. |
| BIND 9 tools (`named-checkzone`, `dnssec-verify`, `delv`, `dig`) | Used. |
| [Knot DNS](https://www.knot-dns.cz/) (`knotc zone-check`, `kdig`) | Used. Fedora packages no `kzonecheck`; `knotc zone-check` runs the same checks offline. |
| [ldns](https://nlnetlabs.nl/projects/ldns/) (`ldns-verify-zone`) | Used. |
| [Zonemaster](https://github.com/zonemaster/zonemaster) (AFNIC, Internetstiftelsen) | Used, optional (`INTEROP_ZONEMASTER=1`): built from CPAN since the published image is amd64 only. Its delegation tests judge a public deployment (address reachability, PTR, two name servers); those three test cases are ignored for the loopback test server. |
| [validns](https://github.com/tobez/validns) | Not used: unmaintained (last release 2014), no Ed25519; ldns, BIND and Knot cover it. |
| [Deckard](https://gitlab.nic.cz/knot/deckard) (CZ.NIC) | Not applicable: scripted scenarios for recursive resolvers. |
| [respdiff](https://gitlab.nic.cz/knot/respdiff) | Not applicable: compares resolvers' answers; `equivalence.py` does the same between rust-dns builds. |
| dnsperf | Performance, not compliance (see `load-test-local.sh`). |
| dnsmasq | No test suite: the 2.93 release has no test directory or `make check` target (only `contrib/dbus-test/dbus-test.py`, a D-Bus example, and a `bloatcheck` size target). |
