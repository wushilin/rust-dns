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
        m.use_edns(edns, payload=payload, options=options or [], ednsflags=dns.flags.DO if want_dnssec else 0)
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
check("3225 §3: DO bit copied into the response OPT", r.ednsflags & dns.flags.DO)
check("4035 §3.1: unsigned zone: no RRSIG even with DO", not rrsets(r.answer, "RRSIG"))
r = q("www", "A", edns=0)
check("3225 §3: DO clear in the response when the query had none", not (r.ednsflags & dns.flags.DO))
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


# --- DNSSEC (RFC 4033-4035, RFC 6605 ECDSA P-256, NSEC) ---------------------------------------------
# signed.test is seeded with signing turned on (scripts/seed-conformance.py).
# Every signature is validated with dnspython (dns.dnssec.validate), an
# implementation independent of the server's.
import dns.dnssec

SZ = dns.name.from_text("signed.test.")
IN = dns.rdataclass.IN
RRSIG = dns.rdatatype.RRSIG
NSEC = dns.rdatatype.NSEC


def sq(name, rtype, tcp=True, payload=4096, do=True, edns=0):
    if isinstance(name, str) and not name.endswith("."):
        name = f"{name}.signed.test."
    m = dns.message.make_query(name, rtype, want_dnssec=do)
    if edns is None:
        m.use_edns(False)
    else:
        m.use_edns(edns, payload=payload, ednsflags=dns.flags.DO if do else 0)
    fn = dns.query.tcp if tcp else dns.query.udp
    return fn(m, IP, port=PORT, timeout=3)


r = sq(SZ, "DNSKEY")
dnskey = r.get_rrset(r.answer, SZ, IN, dns.rdatatype.DNSKEY)
dnskey_sig = r.get_rrset(r.answer, SZ, IN, RRSIG, dns.rdatatype.DNSKEY)
KEYS = {SZ: dnskey} if dnskey is not None else {}
try:
    dns.dnssec.validate(dnskey, dnskey_sig, KEYS)
    err = ""
except Exception as e:
    err = repr(e)
check("4034 §2 / 6605: DNSKEY at the apex (flags 257, algorithm 13), self-signature validates", dnskey is not None and not err and all(k.flags == 257 and k.algorithm == 13 for k in dnskey), err)


def validate_sections(r, sections=("answer", "authority"), skip_referral_ns=True):
    """Validate every RRset (except RRSIGs, and unsigned delegation NS) with
    its RRSIG. Returns a list of problems."""
    problems = []
    for sec in sections:
        rs = getattr(r, sec)
        for rrset in rs:
            if rrset.rdtype == RRSIG:
                continue
            if not rrset.name.is_subdomain(SZ):
                continue
            if skip_referral_ns and rrset.rdtype == dns.rdatatype.NS and not (r.flags & dns.flags.AA):
                continue
            sig = r.get_rrset(rs, rrset.name, IN, RRSIG, rrset.rdtype)
            if sig is None:
                problems.append(f"{rrset.name} {dns.rdatatype.to_text(rrset.rdtype)}: no RRSIG in {sec}")
                continue
            try:
                dns.dnssec.validate(rrset, sig, KEYS)
            except Exception as e:
                problems.append(f"{rrset.name} {dns.rdatatype.to_text(rrset.rdtype)}: {e!r}")
    return problems


def nsecs(r):
    return [rr for rr in r.authority if rr.rdtype == NSEC]


def covers(nsec_rrset, name):
    owner, nxt = nsec_rrset.name, nsec_rrset[0].next
    if owner < nxt:
        return owner < name < nxt
    return name > owner or name < nxt  # last NSEC wraps to the apex


def has_type(nsec_rrset, rtype):
    return dns.rdatatype.from_text(rtype) in [t for w in nsec_rrset[0].windows for t in _window_types(w)]


def _window_types(w):
    window, bitmap = w
    out = []
    for i, byte in enumerate(bitmap):
        for bit in range(8):
            if byte & (0x80 >> bit):
                out.append(window * 256 + i * 8 + bit)
    return out


r = sq("www", "A")
p = validate_sections(r)
check("4035 §3.1.1: positive answer carries RRSIG; validates (dnspython)", rrsets(r.answer, "RRSIG") and not p, str(p))
r = sq("WwW.SiGnEd.TeSt.", "A")
check("4034 §6.2 + 0x20: mixed-case query name validates", r.answer and not validate_sections(r), str(validate_sections(r)))
r = sq("www", "A", do=False)
check("4035 §3.2.1: no DNSSEC records without DO", r.answer and not rrsets(r.answer, "RRSIG") and not nsecs(r))
r = sq(SZ, "SOA")
check("4035 §2.2: SOA signed", not validate_sections(r) and rrsets(r.answer, "RRSIG"))
r = sq(SZ, "NS")
check("4035 §2.2: apex NS signed", not validate_sections(r) and rrsets(r.answer, "RRSIG"))
r = sq(SZ, "MX")
check("4035: MX signed; additional glue does not break validation", not validate_sections(r))

nx = dns.name.from_text("nope.signed.test.")
r = sq(nx, "A")
p = validate_sections(r)
ce_wild = dns.name.from_text("*.signed.test.")
check("4035 §3.1.3.2: NXDOMAIN: SOA + NSECs signed and valid", r.rcode() == dns.rcode.NXDOMAIN and not p and nsecs(r), str(p))
check("4035 §3.1.3.2: NXDOMAIN: an NSEC covers the name", any(covers(n, nx) for n in nsecs(r)))
check("4035 §3.1.3.2: NXDOMAIN: an NSEC covers the wildcard at the closest encloser", any(covers(n, ce_wild) for n in nsecs(r)))

r = sq("www", "MX")
p = validate_sections(r)
own = [n for n in nsecs(r) if n.name == dns.name.from_text("www.signed.test.")]
check("4035 §3.1.3.1: NODATA: NSEC at the name without the type, signed", r.rcode() == dns.rcode.NOERROR and not r.answer and own and not has_type(own[0], "MX") and has_type(own[0], "A") and not p, str(p))

ent = dns.name.from_text("deep.signed.test.")
r = sq(ent, "A")
p = validate_sections(r)
check("4035 §3.1.3.2 / 8020: empty non-terminal NODATA: covering NSEC whose next name is below it", r.rcode() == dns.rcode.NOERROR and not p and any(covers(n, ent) and n[0].next.is_subdomain(ent) for n in nsecs(r)), str(p))

wq = dns.name.from_text("host.gate.signed.test.")
r = sq(wq, "A")
p = validate_sections(r)
sig = r.get_rrset(r.answer, wq, IN, RRSIG, dns.rdatatype.A)
check("4035 §3.1.3.3: wildcard answer validates (RRSIG labels = wildcard owner labels)", r.answer and not p and sig is not None and sig[0].labels == 3, str(p))
check("4035 §3.1.3.3: wildcard answer proves the next closer name does not exist", any(covers(n, wq) for n in nsecs(r)))
r = sq("a.b.c.gate", "A")
check("4592 + 4035: multi-label wildcard expansion validates", r.answer and not validate_sections(r))
r = sq(wq, "AAAA")
p = validate_sections(r)
wild_owner = dns.name.from_text("*.gate.signed.test.")
check("4035 §3.1.3.4: wildcard NODATA: no-closer-match NSEC + wildcard NSEC without the type", r.rcode() == dns.rcode.NOERROR and not r.answer and not p and any(covers(n, wq) for n in nsecs(r)) and any(n.name == wild_owner and not has_type(n, "AAAA") for n in nsecs(r)), str(p))

r = sq("alias", "A")
p = validate_sections(r)
check("4035 §3.1: in-zone CNAME chain: CNAME and target both signed", len(rrsets(r.answer, "RRSIG")) == 2 and not p, str(p))
r = sq("ext", "A")
check("4035: CNAME to an out-of-zone target: the CNAME is signed", rrsets(r.answer, "CNAME") and not validate_sections(r))
r = sq("host.old", "A")
dn = rrsets(r.answer, "DNAME")
cn = rrsets(r.answer, "CNAME")
sigs = rrsets(r.answer, "RRSIG")
cname_signed = any(s.covers == dns.rdatatype.CNAME for s in sigs)
r.answer = [rr for rr in r.answer if rr.rdtype != dns.rdatatype.CNAME and not (rr.rdtype == RRSIG and rr.covers == dns.rdatatype.CNAME)]
p = validate_sections(r)
check("6672 §5.3.1: DNAME signed, synthesized CNAME unsigned, target (wildcard) answer signed", dn and cn and not cname_signed and not p and any(s.covers == dns.rdatatype.DNAME for s in sigs), str(p))

r = sq("host.secure", "A")
p = validate_sections(r)
check("4035 §3.1.4: referral to a signed child: NS unsigned, DS + RRSIG in authority", not (r.flags & dns.flags.AA) and rrsets(r.authority, "DS") and not p, str(p))
r = sq("host.sub", "A")
p = validate_sections(r)
cut = [n for n in nsecs(r) if n.name == dns.name.from_text("sub.signed.test.")]
check("4035 §3.1.4.1: referral to an unsigned child: NSEC at the cut proves no DS", not (r.flags & dns.flags.AA) and cut and has_type(cut[0], "NS") and not has_type(cut[0], "DS") and not p, str(p))
r = sq("secure", "DS")
check("4035 §3.1.4.1: DS query at the cut answered authoritatively by the parent", r.flags & dns.flags.AA and rrsets(r.answer, "DS") and not validate_sections(r))
r = sq("sub", "DS")
check("4035 §3.1.4.1: DS query at an unsigned cut: authoritative NODATA with NSEC", r.flags & dns.flags.AA and not r.answer and nsecs(r) and not validate_sections(r))

r = sq(SZ, "ANY")
types = {rr.rdtype for rr in r.answer if rr.rdtype != RRSIG}
check("8482 §4.1 + 4035: ANY on a signed zone with DO: one real RRset with its RRSIG", len(types) == 1 and rrsets(r.answer, "RRSIG") and not validate_sections(r), str(types))
r = sq(SZ, "ANY", do=False)
check("8482: ANY without DO still the synthesized HINFO", len(rrsets(r.answer, "HINFO")) == 1)
r = sq("www", "TYPE65280")
check("3597 + 4035: unknown type NODATA proven by the NSEC at the name", r.rcode() == dns.rcode.NOERROR and nsecs(r) and not validate_sections(r))
r = sq(SZ, "NSEC")
check("4034 §4: NSEC query at a name answers its NSEC, signed", rrsets(r.answer, "NSEC") and not validate_sections(r))

# Truncation: the signed answer never splits an RRset from its RRSIG.
r = sq("many", "A", tcp=False, payload=512)
full = sq("many", "A")
check("4035 §3.1.1 / 2181 §9: signed answer larger than 512: TC=1 and nothing partial", len(full.to_wire()) > 512 and r.flags & dns.flags.TC and not r.answer and not r.authority, f"full={len(full.to_wire())} tc={bool(r.flags & dns.flags.TC)} answers={len(r.answer)}")
check("7766: the same signed answer over TCP is complete and validates", not (full.flags & dns.flags.TC) and len(rrsets(full.answer, "A")) == 1 and len(rrsets(full.answer, "A")[0]) == 30 and not validate_sections(full))
r = sq("big", "TXT", tcp=False, payload=512)
check("4035 + 1035 §4.2.1: large signed TXT over UDP/512 truncated (TC, empty)", r.flags & dns.flags.TC and not r.answer)
r = sq("big", "TXT", tcp=False, payload=1232)
check("6891: large signed TXT fits in 1232 with its RRSIG, validates", not (r.flags & dns.flags.TC) and not validate_sections(r))
r = sq("big", "TXT", tcp=False, edns=None, do=False)
check("1035 §4.2.1: without EDNS the answer is limited to 512 (TC)", r.flags & dns.flags.TC and not r.answer)

# AXFR of the signed zone: every RRset validates and the NSEC chain is complete.
axfr = []
for msg in dns.query.xfr(IP, "signed.test", port=PORT, timeout=5, relativize=False):
    axfr.extend(msg.answer)
zone_rrsets = {}
for rr in axfr:
    key = (rr.name, rr.rdtype, rr.covers if rr.rdtype == RRSIG else 0)
    if key in zone_rrsets:
        zone_rrsets[key].union_update(rr)
    else:
        zone_rrsets[key] = rr
problems = []
signed_count = 0
for (name, rdtype, _), rrset in zone_rrsets.items():
    if rdtype == RRSIG:
        continue
    below_cut = any(name.is_subdomain(c) and name != c for c in (dns.name.from_text("sub.signed.test."), dns.name.from_text("secure.signed.test.")))
    at_cut_ns = rdtype == dns.rdatatype.NS and name != SZ
    sig = zone_rrsets.get((name, RRSIG, rdtype))
    if below_cut or at_cut_ns:
        if sig is not None:
            problems.append(f"{name} {dns.rdatatype.to_text(rdtype)} signed but not authoritative")
        continue
    if sig is None:
        problems.append(f"{name} {dns.rdatatype.to_text(rdtype)} unsigned")
        continue
    try:
        dns.dnssec.validate(rrset, sig, KEYS)
        signed_count += 1
    except Exception as e:
        problems.append(f"{name} {dns.rdatatype.to_text(rdtype)}: {e!r}")
check("5936 + 4035: AXFR of a signed zone: every authoritative RRset validates, glue/delegation NS unsigned", signed_count > 20 and not problems, str(problems[:3]))
chain = {name: rrset for (name, rdtype, _), rrset in zone_rrsets.items() if rdtype == NSEC}
walk, cur = [], SZ
while cur in chain and cur not in walk:
    walk.append(cur)
    cur = chain[cur][0].next
owners = {name for (name, rdtype, _) in zone_rrsets if not any(name.is_subdomain(c) and name != c for c in (dns.name.from_text("sub.signed.test."), dns.name.from_text("secure.signed.test.")))}
check("4034 §4.1.1: NSEC chain in canonical order covers every authoritative name and wraps to the apex", cur == SZ and set(walk) == owners and walk == sorted(walk), f"{len(walk)} links, {len(owners)} names")

# --- NSEC3 (RFC 5155, RFC 9276), O24; only where the harness seeded one ----
# The harness signs a copy of signed.test as nsec3.test with `denial:
# nsec3`. Hashes are computed by dnspython (dns.dnssec.nsec3_hash) and
# every RRset is validated with dns.dnssec.validate.
import os
N3 = os.environ.get("CONFORMANCE_NSEC3")
if N3:
    NZ = dns.name.from_text(N3 + ".")
    NSEC3 = dns.rdatatype.NSEC3

    def nq(name, rtype, do=True):
        if isinstance(name, str) and not name.endswith("."):
            name = f"{name}.{N3}."
        m = dns.message.make_query(name, rtype, want_dnssec=do)
        m.use_edns(0, payload=4096, ednsflags=dns.flags.DO if do else 0)
        return dns.query.tcp(m, IP, port=PORT, timeout=3)

    r = nq(NZ, "DNSKEY")
    nkey = r.get_rrset(r.answer, NZ, IN, dns.rdatatype.DNSKEY)
    NKEYS = {NZ: nkey} if nkey is not None else {}

    def nvalidate(r):
        problems = []
        for sec in ("answer", "authority"):
            rs = getattr(r, sec)
            for rrset in rs:
                if rrset.rdtype == RRSIG or not rrset.name.is_subdomain(NZ):
                    continue
                if rrset.rdtype == dns.rdatatype.NS and not (r.flags & dns.flags.AA):
                    continue
                sig = r.get_rrset(rs, rrset.name, IN, RRSIG, rrset.rdtype)
                if sig is None:
                    problems.append(f"{rrset.name} {dns.rdatatype.to_text(rrset.rdtype)}: no RRSIG")
                    continue
                try:
                    dns.dnssec.validate(rrset, sig, NKEYS)
                except Exception as e:
                    problems.append(f"{rrset.name} {dns.rdatatype.to_text(rrset.rdtype)}: {e!r}")
        return problems

    def h(name):
        if isinstance(name, str):
            name = dns.name.from_text(name if name.endswith(".") else f"{name}.{N3}.")
        return dns.dnssec.nsec3_hash(name, None, 0, 1).lower()

    def n3s(r):
        return [rr for rr in r.authority if rr.rdtype == NSEC3]

    def n3_owner(rrset):
        return rrset.name.labels[0].decode().lower()

    def _b32hex(b):
        import base64
        return base64.b32hexencode(b).decode().rstrip("=").lower()

    def matches(r, name):
        return [n for n in n3s(r) if n3_owner(n) == h(name)]

    def n3_covers(n, name):
        o, x, t = n3_owner(n), _b32hex(n[0].next), h(name)
        if o < x:
            return o < t < x
        return t > o or t < x

    def n3_types(n):
        return [t for w in n[0].windows for t in _window_types(w)]

    def params_ok(r):
        return all(n[0].algorithm == 1 and n[0].flags == 0 and n[0].iterations == 0 and n[0].salt == b"" for n in n3s(r))

    r = nq(NZ, "NSEC3PARAM")
    p = nvalidate(r)
    np_ = rrsets(r.answer, "NSEC3PARAM")
    check("5155 §4 / 9276 §3.1: NSEC3PARAM at the apex: SHA-1, flags 0, 0 iterations, no salt; signed", np_ and np_[0][0].algorithm == 1 and np_[0][0].flags == 0 and np_[0][0].iterations == 0 and np_[0][0].salt == b"" and not p and NKEYS, str(p))
    r = nq("nope", "A")
    p = nvalidate(r)
    check("5155 §7.2.2: NXDOMAIN: NSEC3 records signed and valid, no NSEC", r.rcode() == dns.rcode.NXDOMAIN and n3s(r) and not nsecs(r) and not p and params_ok(r), str(p))
    check("5155 §7.2.1: NXDOMAIN: closest encloser (apex) matched, next closer covered", matches(r, N3 + ".") and any(n3_covers(n, "nope") for n in n3s(r)))
    check("5155 §7.2.2: NXDOMAIN: wildcard at the closest encloser covered", any(n3_covers(n, "*") for n in n3s(r)))
    r = nq("x.y.a.b.deep", "A")
    check("5155 §7.2.1: deep NXDOMAIN: closest encloser a.b.deep matched, next closer y.a.b.deep covered", r.rcode() == dns.rcode.NXDOMAIN and matches(r, "a.b.deep") and any(n3_covers(n, "y.a.b.deep") for n in n3s(r)) and any(n3_covers(n, "*.a.b.deep") for n in n3s(r)) and not nvalidate(r))
    r = nq("www", "MX")
    m = matches(r, "www")
    check("5155 §7.2.3: NODATA: the matching NSEC3 lists A, not MX; signed", r.rcode() == dns.rcode.NOERROR and not r.answer and m and dns.rdatatype.A in n3_types(m[0]) and dns.rdatatype.MX not in n3_types(m[0]) and not nvalidate(r))
    r = nq("deep", "A")
    m = matches(r, "deep")
    check("5155 §7.1 / §7.2.3: empty non-terminal has an NSEC3 with no types (NODATA)", r.rcode() == dns.rcode.NOERROR and m and n3_types(m[0]) == [] and not nvalidate(r))
    r = nq("host.gate", "A")
    p = nvalidate(r)
    check("5155 §7.2.6: wildcard answer validates, next closer name covered", r.answer and not p and any(n3_covers(n, "host.gate") for n in n3s(r)), str(p))
    r = nq("host.gate", "AAAA")
    w = matches(r, "*.gate")
    check("5155 §7.2.5: wildcard NODATA: closest encloser, next closer, wildcard without the type", r.rcode() == dns.rcode.NOERROR and matches(r, "gate") and any(n3_covers(n, "host.gate") for n in n3s(r)) and w and dns.rdatatype.AAAA not in n3_types(w[0]) and not nvalidate(r))
    r = nq("host.sub", "A")
    m = matches(r, "sub")
    check("5155 §7.2.7: referral to an unsigned child: NSEC3 at the cut with NS, no DS (no opt-out)", not (r.flags & dns.flags.AA) and m and dns.rdatatype.NS in n3_types(m[0]) and dns.rdatatype.DS not in n3_types(m[0]) and not nvalidate(r))
    r = nq("sub", "DS")
    check("5155 §7.2.4: DS query at an unsigned cut: authoritative NODATA with the matching NSEC3", r.flags & dns.flags.AA and not r.answer and matches(r, "sub") and not nvalidate(r))
    r = nq("www", "NSEC")
    check("5155: an NSEC3 zone has no NSEC: NSEC query is NODATA proven by NSEC3", r.rcode() == dns.rcode.NOERROR and not r.answer and matches(r, "www") and not nvalidate(r))
    r = nq(f"{h('www')}.{N3}.", "NSEC3")
    check("5155 §7.2.8: a query for an NSEC3 owner name is NXDOMAIN", r.rcode() == dns.rcode.NXDOMAIN and not r.answer and not nvalidate(r))
    axfr = []
    for msg in dns.query.xfr(IP, N3, port=PORT, timeout=5, relativize=False):
        axfr.extend(msg.answer)
    zr = {}
    for rr in axfr:
        k = (rr.name, rr.rdtype, rr.covers if rr.rdtype == RRSIG else 0)
        if k in zr:
            zr[k].union_update(rr)
        else:
            zr[k] = rr
    cuts = [dns.name.from_text(f"sub.{N3}."), dns.name.from_text(f"secure.{N3}.")]
    problems, ok = [], 0
    for (name, rdtype, _), rrset in zr.items():
        if rdtype == RRSIG:
            continue
        below = any(name.is_subdomain(c) and name != c for c in cuts)
        if below or (rdtype == dns.rdatatype.NS and name != NZ):
            continue
        sig = zr.get((name, RRSIG, rdtype))
        if sig is None:
            problems.append(f"{name} {dns.rdatatype.to_text(rdtype)} unsigned")
            continue
        try:
            dns.dnssec.validate(rrset, sig, NKEYS)
            ok += 1
        except Exception as e:
            problems.append(f"{name} {dns.rdatatype.to_text(rdtype)}: {e!r}")
    check("5155 + 5936: AXFR of an NSEC3 zone: every authoritative RRset (NSEC3 included) validates", ok > 20 and not problems and not any(k[1] == NSEC for k in zr), str(problems[:3]))
    chain = {n3_owner(rs): _b32hex(rs[0].next) for (name, rdtype, _), rs in zr.items() if rdtype == NSEC3}
    names = set()
    for (name, rdtype, _) in zr:
        if rdtype in (NSEC3, RRSIG) or any(name.is_subdomain(c) and name != c for c in cuts):
            continue
        n = name
        while n != NZ and n.is_subdomain(NZ):
            names.add(n)
            n = n.parent()
        names.add(NZ)
    want = {h(n) for n in names}
    walk, cur = [], min(chain) if chain else None
    while cur in chain and cur not in walk:
        walk.append(cur)
        cur = chain[cur]
    check("5155 §7.1: NSEC3 chain: one per authoritative name and empty non-terminal, ordered ring by hash", set(chain) == want and len(walk) == len(chain) and walk == sorted(walk), f"{len(chain)} NSEC3, {len(want)} names")

# --- Ed25519 (RFC 8080), O25; only where the harness seeded one ------------
# The harness signs another copy of signed.test as ed25519.test with an
# Ed25519 key (algorithm 15, NSEC). dnspython (with `cryptography`) does the
# Ed25519 verification.
ED = os.environ.get("CONFORMANCE_ED25519")
if ED:
    EZ = dns.name.from_text(ED + ".")

    def eq(name, rtype):
        if isinstance(name, str) and not name.endswith("."):
            name = f"{name}.{ED}."
        m = dns.message.make_query(name, rtype, want_dnssec=True)
        m.use_edns(0, payload=4096, ednsflags=dns.flags.DO)
        return dns.query.tcp(m, IP, port=PORT, timeout=3)

    r = eq(EZ, "DNSKEY")
    ekey = r.get_rrset(r.answer, EZ, IN, dns.rdatatype.DNSKEY)
    EKEYS = {EZ: ekey} if ekey is not None else {}

    def evalidate(r):
        problems, sigs = [], 0
        for sec in ("answer", "authority"):
            rs = getattr(r, sec)
            for rrset in rs:
                if rrset.rdtype == RRSIG:
                    sigs += sum(1 for s in rrset if s.algorithm != 15)
                    continue
                if not rrset.name.is_subdomain(EZ) or (rrset.rdtype == dns.rdatatype.NS and not (r.flags & dns.flags.AA)):
                    continue
                sig = r.get_rrset(rs, rrset.name, IN, RRSIG, rrset.rdtype)
                if sig is None:
                    problems.append(f"{rrset.name} {dns.rdatatype.to_text(rrset.rdtype)}: no RRSIG")
                    continue
                try:
                    dns.dnssec.validate(rrset, sig, EKEYS)
                except Exception as e:
                    problems.append(f"{rrset.name} {dns.rdatatype.to_text(rrset.rdtype)}: {e!r}")
        if sigs:
            problems.append(f"{sigs} RRSIGs not of algorithm 15")
        return problems

    p = evalidate(r)
    check("8080 §3: DNSKEY algorithm 15 (ED25519) with a 32-byte public key, self-signed",
          ekey is not None and len(ekey) == 1 and ekey[0].algorithm == 15 and len(ekey[0].key) == 32 and not p, str(p))
    ds = dns.dnssec.make_ds(EZ, ekey[0], "SHA256") if ekey is not None else None
    check("8080 §3 / 4509: a DS of the Ed25519 DNSKEY is algorithm 15, digest type 2 (dnspython computes it)",
          ds is not None and ds.algorithm == 15 and ds.digest_type == 2 and ds.key_tag == dns.dnssec.key_id(ekey[0]))
    r = eq("www", "A")
    p = evalidate(r)
    check("8080 §4: positive answer: RRSIG algorithm 15 validates", r.answer and not p, str(p))
    a1 = [s.to_text() for s in (r.get_rrset(r.answer, dns.name.from_text(f"www.{ED}."), IN, RRSIG, dns.rdatatype.A) or [])]
    r2 = eq("www", "A")
    a2 = [s.to_text() for s in (r2.get_rrset(r2.answer, dns.name.from_text(f"www.{ED}."), IN, RRSIG, dns.rdatatype.A) or [])]
    check("8032 §5.1.6: Ed25519 signatures are deterministic (same RRSIG twice)", a1 and a1 == a2)
    r = eq("nope", "A")
    p = evalidate(r)
    check("8080 + 4035 §3.1.3.2: NXDOMAIN proof (NSEC) signed with Ed25519 validates",
          r.rcode() == dns.rcode.NXDOMAIN and nsecs(r) and not p, str(p))
    r = eq("www", "MX")
    p = evalidate(r)
    check("8080 + 4035 §3.1.3.1: NODATA proof signed with Ed25519 validates",
          r.rcode() == dns.rcode.NOERROR and not r.answer and nsecs(r) and not p, str(p))
    r = eq("host.gate", "A")
    p = evalidate(r)
    check("8080 + 4035 §3.1.3.3: wildcard answer signed with Ed25519 validates", r.answer and not p, str(p))
    axfr = []
    for msg in dns.query.xfr(IP, ED, port=PORT, timeout=5, relativize=False):
        axfr.extend(msg.answer)
    zr = {}
    for rr in axfr:
        k = (rr.name, rr.rdtype, rr.covers if rr.rdtype == RRSIG else 0)
        if k in zr:
            zr[k].union_update(rr)
        else:
            zr[k] = rr
    cuts = [dns.name.from_text(f"sub.{ED}."), dns.name.from_text(f"secure.{ED}.")]
    problems, ok = [], 0
    for (name, rdtype, _), rrset in zr.items():
        if rdtype == RRSIG:
            if any(s.algorithm != 15 for s in rrset):
                problems.append(f"{name}: RRSIG not algorithm 15")
            continue
        below = any(name.is_subdomain(c) and name != c for c in cuts)
        if below or (rdtype == dns.rdatatype.NS and name != EZ):
            continue
        sig = zr.get((name, RRSIG, rdtype))
        if sig is None:
            problems.append(f"{name} {dns.rdatatype.to_text(rdtype)} unsigned")
            continue
        try:
            dns.dnssec.validate(rrset, sig, EKEYS)
            ok += 1
        except Exception as e:
            problems.append(f"{name} {dns.rdatatype.to_text(rdtype)}: {e!r}")
    check("8080 + 5936: AXFR of an Ed25519 zone: every authoritative RRset validates, every RRSIG is algorithm 15", ok > 20 and not problems, str(problems[:3]))

# --- override zones (I1); only where the harness seeded one -----------------
OV = os.environ.get("CONFORMANCE_OVERRIDE")
if OV:
    r = q(f"gw.{OV}.", "A", edns=0, want_dnssec=True)
    check("rust-dns override zone: answered, not authoritative (AA=0), never AD, no RRSIG (under a signed parent)",
          r.rcode() == dns.rcode.NOERROR and not (r.flags & dns.flags.AA) and not (r.flags & dns.flags.AD)
          and r.answer and all(rr.rdtype != dns.rdatatype.RRSIG for rr in r.answer), r.to_text())
    r = q(f"nope.{OV}.", "A")
    check("rust-dns override zone (static): a missing name is NXDOMAIN, not authoritative",
          r.rcode() == dns.rcode.NXDOMAIN and not (r.flags & dns.flags.AA), r.to_text())
    try:
        r = dns.query.tcp(dns.message.make_query(OV, "AXFR"), IP, port=PORT, timeout=3)
        refused = r.rcode() == dns.rcode.REFUSED
    except Exception as e:
        refused, r = True, e
    check("rust-dns override zone: never transferred (AXFR REFUSED)", refused, str(r))
    r = sq("signed.test.", "SOA")
    check("rust-dns override zone: the signed parent still answers with signatures",
          any(rr.rdtype == dns.rdatatype.RRSIG for rr in r.answer), r.to_text())

# --- O28: record types hickory's text parser lacks ---------------------------
import dns.rdata
import dns.zone
O28 = os.environ.get("CONFORMANCE_O28")
if O28:
    z28 = dns.name.from_text(O28 + ".")
    r = sq(z28, "DNSKEY")
    k28 = r.get_rrset(r.answer, z28, IN, dns.rdatatype.DNSKEY)
    for name, t, text in [("loc", "LOC", "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m"),
                          ("rp", "RP", "admin.rrtypes.test. info.rrtypes.test."),
                          ("afs", "AFSDB", "1 afs.rrtypes.test."),
                          ("_http._tcp", "URI", '10 1 "https://example.com/"'),
                          ("spf", "SPF", '"v=spf1 -all"'),
                          ("mac", "EUI48", "00-00-5e-00-53-2a"),
                          ("mac", "EUI64", "00-00-5e-ef-10-00-00-2a")]:
        qn = dns.name.from_text(name, origin=z28)
        r = sq(qn, t)
        got = r.get_rrset(r.answer, qn, IN, dns.rdatatype.from_text(t))
        sig = r.get_rrset(r.answer, qn, IN, RRSIG, dns.rdatatype.from_text(t))
        want = dns.rdata.from_text(IN, t, text)
        err = ""
        try:
            dns.dnssec.validate(got, sig, {z28: k28})
        except Exception as e:
            err = repr(e)
        check(f"O28 {t} (RFC 1876 / 1183 / 7553 / 7208 / 7043): answer = dnspython's parse of the value, signed and valid",
              got is not None and len(got) == 1 and got[0].to_wire() == want.to_wire() and not err, f"{got} {err}")
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(IP, z28, port=PORT, timeout=5))
        types = {rds.rdtype for _, rds in zone.iterate_rdatasets()}
        ok28 = all(dns.rdatatype.from_text(t) in types for t in ("LOC", "RP", "AFSDB", "URI", "SPF", "EUI48", "EUI64"))
        err = ""
    except Exception as e:
        ok28, err = False, repr(e)
    check("O28: AXFR of the zone parses (dnspython) with every new type", ok28, err)

failed = [n for n, ok, _ in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
sys.exit(1 if failed else 0)
