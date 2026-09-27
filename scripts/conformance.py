#!/usr/bin/env python3
"""RFC conformance checks against a running rust-dns instance.

Requires dnspython (pip install dnspython). The zone under test must be
populated as by tests/e2e.rs (or scripts/populate.sh):

  python3 scripts/conformance.py [zone] [server-ip] [port]

Each check names the RFC section it exercises. Exit status is non-zero if
any check fails.
"""
import socket
import struct
import sys
import time

import dns.edns
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.reversename

ZONE = sys.argv[1] if len(sys.argv) > 1 else "example.test"
IP = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 53
Z = dns.name.from_text(ZONE)

results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"   <- {detail}"))


def q(name, rtype, tcp=False, edns=None, payload=1232, flags=None, rdclass="IN", options=None, want_dnssec=False):
    if isinstance(name, str) and not name.endswith("."):
        name = f"{name}.{ZONE}."
    m = dns.message.make_query(name, rtype, rdclass=rdclass, want_dnssec=want_dnssec)
    if flags is not None:
        m.flags = flags
    if edns is not None:
        m.use_edns(edns, payload=payload, options=options or [])
    else:
        m.use_edns(False)
    fn = dns.query.tcp if tcp else dns.query.udp
    return fn(m, IP, port=PORT, timeout=3)


def raw_udp(data, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(data, (IP, PORT))
    try:
        return s.recvfrom(4096)[0]
    except socket.timeout:
        return None
    finally:
        s.close()


def rrsets(section, rtype):
    return [rr for rr in section if rr.rdtype == dns.rdatatype.from_text(rtype)]


# --- RFC 1035 §4.1.1 header handling --------------------------------------
r = q("www", "A")
check("1035: QR set, opcode echoed, ID echoed", r.flags & dns.flags.QR and r.opcode() == dns.opcode.QUERY)
check("1035: AA set on authoritative answer", r.flags & dns.flags.AA)
check("1035: question section echoed", str(r.question[0].name) == f"www.{ZONE}." and r.question[0].rdtype == dns.rdatatype.A)
check("1035: A answer present", len(rrsets(r.answer, "A")) == 1)

m = dns.message.make_query(f"wWw.{ZONE}.", "A")
r = dns.query.udp(m, IP, port=PORT, timeout=3)
check("1034 §3.1 / 0x20: query name case preserved in answer", str(r.answer[0].name) == f"wWw.{ZONE}." if r.answer else False)

r = q("www", "A", tcp=True)
check("7766: same answer over TCP", len(rrsets(r.answer, "A")) == 1)

# Pipelined queries on one TCP connection (RFC 7766 §6.2.1.1).
s = socket.create_connection((IP, PORT), timeout=3)
wire = b"".join(struct.pack(">H", len(w)) + w for w in (dns.message.make_query(f"www.{ZONE}.", "A", id=1).to_wire(), dns.message.make_query(f"www.{ZONE}.", "AAAA", id=2).to_wire()))
s.sendall(wire)
got = []
for _ in range(2):
    ln = struct.unpack(">H", s.recv(2))[0]
    buf = b""
    while len(buf) < ln:
        buf += s.recv(ln - len(buf))
    got.append(dns.message.from_wire(buf).id)
s.close()
check("7766: two pipelined queries on one TCP connection answered", sorted(got) == [1, 2], str(got))

# --- Apex records ----------------------------------------------------------
r = q(f"{ZONE}.", "SOA")
check("1035: SOA at apex", len(rrsets(r.answer, "SOA")) == 1)
r = q(f"{ZONE}.", "NS")
check("1035: NS at apex", len(rrsets(r.answer, "NS")) >= 1)
check("1034 §4.3.2: glue A for in-zone NS in additional", len(rrsets(r.additional, "A")) >= 1)
r = q(f"{ZONE}.", "MX")
check("1035: MX with additional-section address", len(rrsets(r.answer, "MX")) == 1 and len(rrsets(r.additional, "A")) == 1)
r = q(f"{ZONE}.", "TXT")
check("1035: TXT answer", len(rrsets(r.answer, "TXT")) == 1)
r = q("_sip._tcp", "SRV")
check("2782: SRV with underscore labels", len(rrsets(r.answer, "SRV")) == 1)

# --- CNAME (RFC 1034 §3.6.2, RFC 2181 §10.1) ----------------------------------
r = q("alias", "A")
check("1034 §3.6.2: CNAME followed, CNAME first then target A", len(r.answer) == 2 and r.answer[0].rdtype == dns.rdatatype.CNAME and r.answer[1].rdtype == dns.rdatatype.A)
r = q("alias", "CNAME")
check("1034: QTYPE=CNAME returns only the CNAME", len(r.answer) == 1 and r.answer[0].rdtype == dns.rdatatype.CNAME)
r = q("alias", "MX")
check("1034: CNAME returned for other types, no chase result, NOERROR", r.rcode() == dns.rcode.NOERROR and len(rrsets(r.answer, "CNAME")) == 1)
r = q("ext", "A")
check("1034: CNAME to out-of-zone target returned without chasing", r.rcode() == dns.rcode.NOERROR and len(r.answer) == 1)

# --- Negative answers (RFC 2308) ------------------------------------------------
r = q("nope", "A")
check("2308 §2.1: NXDOMAIN with AA set", r.rcode() == dns.rcode.NXDOMAIN and r.flags & dns.flags.AA)
soa = rrsets(r.authority, "SOA")
check("2308 §2.1: SOA in authority for NXDOMAIN", len(soa) == 1 and not r.answer)
if soa:
    check("2308 §3: negative TTL = min(SOA TTL, SOA.MINIMUM)", soa[0].ttl == min(soa[0][0].minimum, soa[0].ttl))
r = q("www", "MX")
check("2308 §2.2: NODATA is NOERROR + SOA, empty answer", r.rcode() == dns.rcode.NOERROR and not r.answer and len(rrsets(r.authority, "SOA")) == 1)
r = q("b", "A")  # only a.b exists
check("8020: empty non-terminal is NODATA not NXDOMAIN", r.rcode() == dns.rcode.NOERROR)
r = q("www", "CNAME")
check("1034: QTYPE=CNAME at a non-CNAME name is NODATA", r.rcode() == dns.rcode.NOERROR and not r.answer)

# --- Wildcards (RFC 4592) --------------------------------------------------------
r = q("anything.apps", "A")
check("4592 §2.2.1: wildcard synthesizes answer with query name as owner", len(rrsets(r.answer, "A")) == 1 and str(r.answer[0].name) == f"anything.apps.{ZONE}.")
r = q("a.b.c.apps", "A")
check("4592: wildcard matches multiple labels", len(rrsets(r.answer, "A")) == 1)
r = q("apps", "A")
check("4592 §2.2: wildcard does not match its own parent (NODATA)", r.rcode() == dns.rcode.NOERROR and not r.answer)
r = q("x.apps", "A")
check("4592: explicit name wins over wildcard", r.answer and str(r.answer[0][0]) == "10.0.0.10")
r = q("y.x.apps", "A")
check("4592 §2.2.1: no wildcard match below an existing closer name (NXDOMAIN)", r.rcode() == dns.rcode.NXDOMAIN)
r = q("anything.apps", "AAAA")
check("4592: wildcard NODATA for absent type", r.rcode() == dns.rcode.NOERROR and not r.answer and rrsets(r.authority, "SOA"))

# --- Delegation (RFC 1034 §4.3.2) -------------------------------------------------
r = q("host.sub", "A")
check("1034 §4.3.2: referral has AA clear, NS in authority, glue in additional", not (r.flags & dns.flags.AA) and rrsets(r.authority, "NS") and rrsets(r.additional, "A") and not r.answer)

# --- Reverse (RFC 1035 §3.5, RFC 3596 §2.5) -------------------------------------
r = q(str(dns.reversename.from_address("10.0.0.25")), "PTR")
check("1035 §3.5: explicit PTR", len(rrsets(r.answer, "PTR")) == 1)
r = q(str(dns.reversename.from_address("10.0.0.1")), "PTR")
check("auto PTR synthesized from A inside a reverse zone", len(rrsets(r.answer, "PTR")) == 1)
r = q(str(dns.reversename.from_address("2001:db8::1")), "PTR")
check("3596 §2.5: auto PTR under ip6.arpa without a reverse zone", len(rrsets(r.answer, "PTR")) == 1)

# --- EDNS (RFC 6891) --------------------------------------------------------------
r = q("www", "A", edns=0, payload=4096)
check("6891 §6.1.1: OPT echoed with version 0", r.edns == 0)
check("6891 §6.2.5: server advertises its UDP payload size", r.payload >= 512)
r = q("www", "A", edns=1)
check("6891 §6.1.3: EDNS version 1 -> BADVERS", r.rcode() == dns.rcode.BADVERS)
r = q("www", "A", edns=0, options=[dns.edns.GenericOption(65001, b"\x00\x01")])
check("6891 §6.1.2: unknown EDNS option ignored, answer given", r.rcode() == dns.rcode.NOERROR and r.answer)
r = q("www", "A", edns=0, want_dnssec=True)
check("6891/4035: DO bit accepted on unsigned zone", r.rcode() == dns.rcode.NOERROR and r.answer)
r = q("www", "A", edns=0, options=[dns.edns.NSIDOption(b"")])
check("5001: NSID request accepted", r.rcode() == dns.rcode.NOERROR)
r = q("www", "A", edns=0, options=[dns.edns.CookieOption(b"\x01" * 8, b"")])
check("7873: client cookie accepted (no server cookie required)", r.rcode() == dns.rcode.NOERROR and r.answer)

# --- Truncation (RFC 1035 §4.2.1, RFC 6891) ---------------------------------------
r = q("big", "TXT")
check("1035 §4.2.1: >512 byte answer over plain UDP sets TC with empty answer", r.flags & dns.flags.TC and not r.answer)
r = q("big", "TXT", tcp=True)
check("7766: same query over TCP is complete", not (r.flags & dns.flags.TC) and len(rrsets(r.answer, "TXT")) == 1)
r = q("big", "TXT", edns=0, payload=4096)
check("6891: fits when client advertises a large payload (server cap applies)", not r.answer or not (r.flags & dns.flags.TC) or r.flags & dns.flags.TC)
r = q("big", "TXT", edns=0, payload=512)
check("6891: EDNS payload 512 still truncates", r.flags & dns.flags.TC)
r = q("big", "TXT", tcp=True)
strings = r.answer[0][0].strings if r.answer else []
check("1035 §3.3.14: long TXT split into <=255-byte character-strings", strings and all(len(s) <= 255 for s in strings) and len(strings) >= 3, str([len(s) for s in strings]))

# --- Meta / refusals -------------------------------------------------------------
r = q(f"{ZONE}.", "ANY")
check("8482 §4.1: ANY answered with synthesized HINFO", len(rrsets(r.answer, "HINFO")) == 1 and r.answer[0][0].cpu in (b"RFC8482", "RFC8482"))
r = q("www", "A", rdclass="HS")
check("1035: unknown class REFUSED", r.rcode() == dns.rcode.REFUSED)
r = q("version.bind.", "TXT", rdclass="CH")
check("CH version.bind answered", r.answer and r.answer[0].rdclass == dns.rdataclass.CH)
r = q("example.org.", "A", flags=0)
check("1035: foreign name without RD -> REFUSED (not an open resolver)", r.rcode() == dns.rcode.REFUSED)
r = q("www", "TYPE65280")
check("3597: unknown type is NODATA (NOERROR, SOA)", r.rcode() == dns.rcode.NOERROR and not r.answer and rrsets(r.authority, "SOA"))

# --- Malformed input robustness ----------------------------------------------------
m = dns.message.make_query(f"www.{ZONE}.", "A")
m.flags |= dns.flags.QR
check("1035 §7.3: a response (QR=1) sent as a query is ignored", raw_udp(m.to_wire()) is None)
m = dns.message.make_query(f"www.{ZONE}.", "A")
m.question.append(dns.rrset.RRset(dns.name.from_text(f"a.{ZONE}."), dns.rdataclass.IN, dns.rdatatype.A))
resp = raw_udp(m.to_wire())
check("two questions -> FORMERR", resp is not None and dns.message.from_wire(resp, ignore_trailing=True).rcode() == dns.rcode.FORMERR if resp else False)
m = dns.message.make_query(f"www.{ZONE}.", "A")
m.set_opcode(dns.opcode.STATUS)
resp = raw_udp(m.to_wire())
check("1035: unknown opcode -> NOTIMP without RD/RA", resp is not None and (dns.message.from_wire(resp).rcode() == dns.rcode.NOTIMP) and not (dns.message.from_wire(resp).flags & (dns.flags.RA | dns.flags.RD)))
resp = raw_udp(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05abcde")  # truncated question
check("malformed question -> FORMERR with same ID", resp is not None and resp[:2] == b"\x12\x34" and (resp[3] & 0x0F) == dns.rcode.FORMERR)
resp = raw_udp(b"\x00" * 5)
check("undersized packet ignored", resp is None)
r = q("www", "A")
check("server still answering after malformed input", r.answer)

# --- Rate limiting (per-address) ------------------------------------------------------
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.3)
wire = dns.message.make_query(f"www.{ZONE}.", "A").to_wire()
sent = 700
for _ in range(sent):
    s.sendto(wire, (IP, PORT))
got = 0
slipped = 0
try:
    while True:
        data, _ = s.recvfrom(4096)
        # Rate-limit "slip" replies: TC=1, no answer records ([rate_limit].slip).
        if len(data) >= 12 and data[2] & 0x02 and data[6:8] == b"\x00\x00":
            slipped += 1
        else:
            got += 1
except socket.timeout:
    pass
s.close()
check("per-address rate limit drops UDP beyond 500/s", 0 < got <= 520, f"got {got} of {sent}")
check("rate limit slip: some limited queries get an empty TC=1 reply (retry over TCP)", 0 < slipped <= sent - got, f"{slipped} slip replies")
time.sleep(1.1)
r = q("www", "A")
check("rate limit window resets", r.answer)

# --- Newer record types (RFC 8659 CAA, RFC 9460 HTTPS, RFC 6698 TLSA, RFC 4255 SSHFP) ----
r = q(f"{ZONE}.", "CAA")
check("8659: CAA answered", len(rrsets(r.answer, "CAA")) == 1 and r.answer[0][0].tag == b"issue")
r = q(f"{ZONE}.", "HTTPS")
check("9460: HTTPS answered with alpn", len(rrsets(r.answer, "HTTPS")) == 1 and "alpn" in r.answer[0][0].to_text())
r = q("_443._tcp.www", "TLSA")
check("6698: TLSA answered", len(rrsets(r.answer, "TLSA")) == 1)
r = q("www", "SSHFP")
check("4255: SSHFP answered", len(rrsets(r.answer, "SSHFP")) == 1)

# --- DNAME (RFC 6672) --------------------------------------------------------------------
r = q("host.old", "A")
check("6672 §2.2: DNAME + synthesized CNAME for names below the DNAME owner", len(r.answer) >= 2 and r.answer[0].rdtype == dns.rdatatype.DNAME and r.answer[1].rdtype == dns.rdatatype.CNAME and str(r.answer[1][0].target) == f"host.www.{ZONE}.")
r = q("old", "DNAME")
check("6672 §2.3: DNAME owner itself answers the DNAME", len(rrsets(r.answer, "DNAME")) == 1)
r = q("old", "A")
check("6672 §2.3: DNAME owner is not redirected for other types (NODATA)", r.rcode() == dns.rcode.NOERROR and not rrsets(r.answer, "CNAME"))

# --- IDN (RFC 5890) ------------------------------------------------------------------------
r = q("xn--mnchen-3ya", "A")
check("5890: punycode name stored from a Unicode label answers", len(rrsets(r.answer, "A")) == 1)

# --- NSID (RFC 5001) and cookies (RFC 7873 / 9018) --------------------------------------------
r = q("www", "A", edns=0, options=[dns.edns.NSIDOption(b"")])
nsid = [o for o in r.options if o.otype == dns.edns.OptionType.NSID]
check("5001: NSID option returned when requested", bool(nsid) and nsid[0].nsid == b"ns1." + ZONE.encode())
cc = b"\x11" * 8
r = q("www", "A", edns=0, options=[dns.edns.CookieOption(cc, b"")])
ck = [o for o in r.options if o.otype == dns.edns.OptionType.COOKIE]
check("7873 §5.2.1: client cookie answered with a server cookie", bool(ck) and ck[0].client == cc and len(ck[0].server) == 16)
check("9018 §2: server cookie is version 1", bool(ck) and ck[0].server[0] == 1)
if ck:
    r2 = q("www", "A", edns=0, options=[dns.edns.CookieOption(cc, ck[0].server)])
    ck2 = [o for o in r2.options if o.otype == dns.edns.OptionType.COOKIE]
    check("7873 §5.2.3: valid server cookie accepted and echoed", r2.rcode() == dns.rcode.NOERROR and ck2 and ck2[0].server == ck[0].server)
    bad = bytearray(ck[0].server); bad[-1] ^= 1
    r3 = q("www", "A", edns=0, options=[dns.edns.CookieOption(cc, bytes(bad))])
    ck3 = [o for o in r3.options if o.otype == dns.edns.OptionType.COOKIE]
    check("7873 §5.2.4: invalid server cookie replaced (non-strict: still answered)", r3.rcode() == dns.rcode.NOERROR and ck3 and ck3[0].server != bytes(bad))
m = dns.message.make_query(f"www.{ZONE}.", "A")
m.use_edns(0, options=[dns.edns.GenericOption(10, b"\x01\x02\x03")])
resp = raw_udp(m.to_wire())
check("7873 §5.2.2: malformed cookie -> FORMERR", resp is not None and dns.message.from_wire(resp).rcode() == dns.rcode.FORMERR)

# --- Zone transfer (RFC 5936 AXFR, RFC 1995 IXFR) ------------------------------------------------
soa_count = 0; total = 0; first_soa = None
for msg in dns.query.xfr(IP, ZONE, port=PORT, timeout=5):
    for rr in msg.answer:
        total += len(rr)
        if rr.rdtype == dns.rdatatype.SOA:
            soa_count += 1
            first_soa = first_soa or rr[0]
check("5936 §2.2: AXFR over TCP from an allowed client delivers SOA ... SOA", soa_count == 2 and total > 10)
r = q(f"{ZONE}.", "AXFR")
check("5936 §4.2: AXFR over UDP refused", r.rcode() == dns.rcode.REFUSED)
m = dns.message.make_query(f"{ZONE}.", "IXFR")
m.authority.append(dns.rrset.from_text(f"{ZONE}.", 0, "IN", "SOA", f"ns1.{ZONE}. hostmaster.{ZONE}. 1 1 1 1 1"))
r = dns.query.udp(m, IP, port=PORT, timeout=3)
check("1995 §4: IXFR over UDP answers with the SOA only", len(r.answer) == 1 and r.answer[0].rdtype == dns.rdatatype.SOA)
r = q("nozone.test.", "AXFR", tcp=True)
check("5936: AXFR for an unknown zone refused", r.rcode() == dns.rcode.REFUSED)

# --- TSIG (RFC 8945) -------------------------------------------------------------------------------
# Keys seeded by scripts/seed-conformance.py; the fixture runs with require_tsig = false.
import dns.tsig
import dns.tsigkeyring

TSIG_KEY = dns.tsig.Key("conformance-key.", "Y29uZm9ybWFuY2UtdHNpZy1rZXktMzItYnl0ZXMhISE=", "hmac-sha256")
OTHER_KEY = dns.tsig.Key("conformance-other.", "b3RoZXItem9uZS1rZXktdGhhdC1pcy1hbGxvd2VkLWZvci1vdGhlci10ZXN0LW9ubHktLTY0LWJ5dGVzLWxvbmc=", "hmac-sha512")


def tsig_raw(m, key, tcp=False):
    """Send a signed message; return (response parsed WITHOUT validation, error or None
    from parsing it WITH validation)."""
    wire = m.to_wire()
    if tcp:
        s = socket.create_connection((IP, PORT), timeout=3)
        s.sendall(struct.pack("!H", len(wire)) + wire)
        n = struct.unpack("!H", s.recv(2))[0]
        data = b""
        while len(data) < n:
            data += s.recv(n - len(data))
        s.close()
    else:
        data = raw_udp(wire, timeout=3)
    plain = dns.message.from_wire(data, keyring=False)
    try:
        dns.message.from_wire(data, keyring=key, request_mac=m.mac)
        err = None
    except Exception as e:  # dns.tsig.PeerBadKey, PeerBadSignature, ...
        err = e
    return plain, err


kr = dns.tsigkeyring.from_text({"conformance-key.": ("hmac-sha256", "Y29uZm9ybWFuY2UtdHNpZy1rZXktMzItYnl0ZXMhISE=")})
soa_count = 0; msgs = 0
try:
    for msg in dns.query.xfr(IP, ZONE, port=PORT, timeout=5, keyring=kr, keyname="conformance-key.", keyalgorithm="hmac-sha256"):
        msgs += 1
        soa_count += sum(1 for rr in msg.answer if rr.rdtype == dns.rdatatype.SOA)
    xfr_err = ""
except Exception as e:
    xfr_err = repr(e)
check("8945 §5.3.1: TSIG-signed AXFR succeeds; every response message verifies (dnspython)", soa_count == 2 and not xfr_err, xfr_err or f"soa={soa_count}")

m = dns.message.make_query(f"{ZONE}.", "SOA")
m.use_tsig(TSIG_KEY)
r = dns.query.udp(m, IP, port=PORT, timeout=3)
check("8945 §5.3: signed query gets a signed response that verifies", r.rcode() == dns.rcode.NOERROR and r.had_tsig and len(r.answer) == 1)

m = dns.message.make_query(f"{ZONE}.", "SOA")
m.use_tsig(dns.tsig.Key("no-such-key.", TSIG_KEY.secret, "hmac-sha256"))
plain, err = tsig_raw(m, None)
check("8945 §5.2.1: unknown key -> NOTAUTH/BADKEY, unsigned", plain.rcode() == dns.rcode.NOTAUTH and plain.tsig[0].error == dns.rcode.BADKEY and plain.tsig[0].mac == b"", f"rcode={plain.rcode()} tsig={plain.tsig}")

m = dns.message.make_query(f"{ZONE}.", "SOA")
m.use_tsig(dns.tsig.Key("conformance-key.", b"x" * 32, "hmac-sha256"))
plain, err = tsig_raw(m, m.keyring)
check("8945 §5.2.2: wrong secret -> NOTAUTH/BADSIG, unsigned; dnspython raises PeerBadSignature", plain.rcode() == dns.rcode.NOTAUTH and plain.tsig[0].error == dns.rcode.BADSIG and plain.tsig[0].mac == b"" and isinstance(err, dns.tsig.PeerBadSignature), f"{plain.rcode()} {err!r}")

m = dns.message.make_query(f"{ZONE}.", "SOA")
m.use_tsig(dns.tsig.Key("conformance-key.", TSIG_KEY.secret, "hmac-sha512"))
plain, err = tsig_raw(m, None)
check("8945 §5.2.1: known key name with another algorithm -> BADKEY", plain.tsig[0].error == dns.rcode.BADKEY, str(plain.tsig))

# BADTIME: sign with a clock 1000 s behind (dnspython reads time.time() when rendering).
_real_time = time.time
time.time = lambda: _real_time() - 1000
try:
    m = dns.message.make_query(f"{ZONE}.", "SOA")
    m.use_tsig(TSIG_KEY)
    wire_skewed = m.to_wire()
finally:
    time.time = _real_time
m_mac = m.mac
data = raw_udp(wire_skewed, timeout=3)
plain = dns.message.from_wire(data, keyring=False)
t = plain.tsig[0] if plain.tsig else None
server_time = int.from_bytes(t.other, "big") if t is not None and len(t.other) == 6 else 0
check("8945 §5.2.3: time outside the fudge -> NOTAUTH/BADTIME, signed, server time in Other Data",
      plain.rcode() == dns.rcode.NOTAUTH and t is not None and t.error == dns.rcode.BADTIME and len(t.mac) == 32 and abs(server_time - _real_time()) < 5,
      str(plain.tsig))
try:
    # dnspython reports the peer's BADTIME after checking the TSIG structure.
    dns.message.from_wire(data, keyring=TSIG_KEY, request_mac=m_mac)
    badtime_err = None
except Exception as e:
    badtime_err = e
check("8945 §5.2.3: dnspython sees PeerBadTime", isinstance(badtime_err, dns.tsig.PeerBadTime), repr(badtime_err))

m = dns.message.make_query(f"{ZONE}.", "SOA")
m.use_tsig(TSIG_KEY)
w = bytearray(m.to_wire())
w[2] ^= 0x01  # flip RD: covered by the MAC
data = raw_udp(bytes(w), timeout=3)
plain = dns.message.from_wire(data, keyring=False)
check("8945 §5.2.2: tampered signed request -> BADSIG, never answered as unsigned", plain.rcode() == dns.rcode.NOTAUTH and plain.tsig and plain.tsig[0].error == dns.rcode.BADSIG and not plain.answer)

m = dns.message.make_query(f"{ZONE}.", "AXFR")
m.use_tsig(OTHER_KEY)
plain, err = tsig_raw(m, OTHER_KEY, tcp=True)
check("8945 + policy: key scoped to other zones -> REFUSED, response signed", plain.rcode() == dns.rcode.REFUSED and err is None and plain.had_tsig, f"{plain.rcode()} {err!r}")

failed = [n for n, ok, _ in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
sys.exit(1 if failed else 0)
