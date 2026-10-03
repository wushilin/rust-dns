#!/usr/bin/env python3
"""Byte-level equivalence check of two rust-dns binaries (BASE vs NEW).

Proves that a refactor of the DNS query path does not change a single byte
on the wire. Usage (normally through scripts/equivalence-local.sh):

    equivalence.py --base BASE_BIN --new NEW_BIN [--keep] [--workdir DIR]

What it does
------------
1. Seed. One BASE instance is started on a temporary database and seeded
   through the HTTP API: scripts/seed-conformance.py (example.test,
   0.0.10.in-addr.arpa, signed.test, two TSIG keys) plus extra zones and
   records (child zones, a signed reverse zone, an ip6.arpa zone, CNAMEs
   out of our zones, DNAMEs, wildcards, a CNAME loop, auto-PTR targets) and
   two TSIG keys whose secrets the server generates (read back from the
   create response). DNSSEC signing is turned on through the API. The
   instance is then stopped (SIGINT, clean shutdown) and its database
   (with -wal/-shm) is copied twice, so both servers under test hold the
   same data, the same DNSSEC keys and the same signing epoch.
2. Main phase. BASE runs on copy A and NEW on copy B, each forwarding to
   its own instance of a deterministic fake upstream (in this process).
   Thousands of queries (names x types x EDNS variants x UDP/TCP, RD
   on/off, classes, opcodes, QDCOUNT 0/2, garbage, zone transfers, TSIG)
   are sent, each to A and then at once to B with the same message ID,
   and the raw replies are compared.
3. Rate-limit phase (5 queries/s, slip 2): a UDP burst from one socket;
   the sequence of answered / dropped / slipped replies must match.
4. cookies_required phase: strict-cookie behaviour must match.

Normalisations (the ONLY bytes allowed to differ; everything else must be
byte-identical):
  * RRSIG: the signature field (ECDSA P-256 signatures are randomised).
    Every other RRSIG field (type covered, algorithm, labels, original TTL,
    expiration, inception, key tag, signer) is compared.
  * EDNS COOKIE option: bytes after the 8-byte client cookie (the server
    cookie is keyed by a per-process random secret and the current time).
  * TSIG: time signed, MAC and other data (clock dependent). The MACs are
    verified separately against the key (RFC 8945 digest, including the
    chained digests of multi-message zone transfers).
  * TTLs of forwarded answers served from the forwarding cache may differ
    by at most 1 second (A and B are queried back to back, so they only
    differ when a second boundary falls between the two queries). Applied
    only to queries for names the server forwards.
"""

import argparse
import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import random
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zlib

try:
    import dns.flags
    import dns.message
    import dns.name
    import dns.rcode
    import dns.rdataclass
    import dns.rdatatype
    import dns.rrset
    import dns.tsig
except ImportError:  # pragma: no cover
    sys.exit("equivalence.py needs dnspython (pip install dnspython)")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT_PASSWORD = "ci-root-password"
NSID = "ns1.equiv.test"
FWD_SUFFIX = "upstream.test."
FORWARD_TIMEOUT_MS = 400
CSRF = {"X-Requested-With": "rust-dns"}


def log(*a):
    print(*a, flush=True)


# --------------------------------------------------------------------------
# Process management: everything started is stopped on exit.
# --------------------------------------------------------------------------

PROCS = []


def stop_proc(p, sig=signal.SIGINT, wait=10.0):
    if p.poll() is not None:
        return
    try:
        p.send_signal(sig)
        p.wait(timeout=wait)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
    except ProcessLookupError:
        pass


def stop_all():
    for p in PROCS:
        try:
            stop_proc(p, wait=3.0)
        except Exception:
            pass


def _on_signal(signum, _frame):
    raise SystemExit(128 + signum)


def free_port():
    """A port free for both UDP and TCP on 127.0.0.1 (never 5353)."""
    for _ in range(200):
        t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        t.bind(("127.0.0.1", 0))
        port = t.getsockname()[1]
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            u.bind(("127.0.0.1", port))
        except OSError:
            continue
        finally:
            u.close()
            t.close()
        if port != 5353:
            return port
    raise RuntimeError("no free port")


# --------------------------------------------------------------------------
# Fake upstream resolver (deterministic). One instance per server under test.
# --------------------------------------------------------------------------

UPSTREAM_ZONE = dns.name.from_text(FWD_SUFFIX)
UPSTREAM_TTL = 3600  # long, so nothing expires from the forwarding cache mid-run


class FakeUpstream:
    """UDP+TCP DNS server answering from fixed rules.

    The reply is built from the received query (its ID, flags and question,
    letter case included: rust-dns randomises the case (0x20) and checks
    the echo). Rules, by the first label of the (lower-cased) name:
      nx*      NXDOMAIN + SOA          fail*     SERVFAIL
      timeout* never answered          nodata*   AAAA: NODATA + SOA
      big*     TXT: >1232 bytes; over UDP an empty TC=1 reply
      cname*   CNAME www.upstream.test. (+ its A for A/ANY)
      else     A 192.0.2.N / AAAA 2001:db8:ff::N / TXT / MX / PTR, N from a
               CRC of the name; other types NODATA + SOA.
    """

    def __init__(self):
        self.port = None
        self.stop = threading.Event()
        self.queries = 0

    def start(self):
        for _ in range(50):
            port = free_port()
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                u.bind(("127.0.0.1", port))
                t.bind(("127.0.0.1", port))
            except OSError:
                u.close()
                t.close()
                continue
            t.listen(64)
            self.udp, self.tcp, self.port = u, t, port
            break
        else:
            raise RuntimeError("fake upstream: no port")
        self.udp.settimeout(0.2)
        self.tcp.settimeout(0.2)
        threading.Thread(target=self._udp_loop, daemon=True).start()
        threading.Thread(target=self._tcp_loop, daemon=True).start()
        return self

    def _udp_loop(self):
        while not self.stop.is_set():
            try:
                data, peer = self.udp.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            out = self.answer(data, tcp=False)
            if out is not None:
                self.udp.sendto(out, peer)

    def _tcp_loop(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._tcp_conn, args=(conn,), daemon=True).start()

    def _tcp_conn(self, conn):
        conn.settimeout(5)
        try:
            while True:
                hdr = _recv_exact(conn, 2)
                if not hdr:
                    return
                msg = _recv_exact(conn, struct.unpack("!H", hdr)[0])
                if msg is None:
                    return
                out = self.answer(msg, tcp=True)
                if out is None:
                    time.sleep(3)  # "timeout": hold the connection, say nothing
                    return
                conn.sendall(struct.pack("!H", len(out)) + out)
        except OSError:
            pass
        finally:
            conn.close()

    def answer(self, wire, tcp):
        self.queries += 1
        try:
            q = dns.message.from_wire(wire)
        except Exception:
            q = None
        if q is None or len(q.question) != 1 or q.opcode() != 0 or q.flags & dns.flags.QR:
            if len(wire) < 12:
                return None
            # FORMERR, header only, built from the raw query header.
            return wire[:2] + bytes([0x80 | (wire[2] & 0x79), 0x01]) + b"\x00" * 8
        r = dns.message.make_response(q, recursion_available=True, our_payload=1232)
        qq = q.question[0]
        name, qtype = qq.name, qq.rdtype
        lname = name.to_text().lower()
        first = name.labels[0].lower() if len(name.labels) > 1 else b""
        soa = dns.rrset.from_text(
            UPSTREAM_ZONE, UPSTREAM_TTL, "IN", "SOA",
            "ns1.upstream.test. hostmaster.upstream.test. 1 3600 600 86400 3600")
        T = dns.rdatatype

        def add(rtype, *values, owner=None):
            r.answer.append(dns.rrset.from_text_list(
                owner or name, UPSTREAM_TTL, "IN", rtype, list(values)))

        if first.startswith(b"timeout"):
            return None
        if first.startswith(b"fail"):
            r.set_rcode(dns.rcode.SERVFAIL)
        elif first.startswith(b"nx"):
            r.set_rcode(dns.rcode.NXDOMAIN)
            r.authority.append(soa)
        elif first.startswith(b"nodata") and qtype == T.AAAA:
            r.authority.append(soa)
        elif first.startswith(b"big") and qtype == T.TXT:
            if not tcp:
                r.flags |= dns.flags.TC
            else:
                add("TXT", *['"%s"' % (chr(ord("a") + i) * 250) for i in range(6)])
        elif first.startswith(b"cname"):
            target = dns.name.from_text("www.upstream.test.")
            add("CNAME", "www.upstream.test.")
            if qtype in (T.A, T.ANY):
                add("A", "192.0.2.200", owner=target)
        else:
            n = zlib.crc32(lname.encode()) % 250 + 1
            if qtype in (T.A, T.ANY):
                add("A", "192.0.2.%d" % n)
            elif qtype == T.AAAA:
                add("AAAA", "2001:db8:ff::%x" % n)
            elif qtype == T.TXT:
                add("TXT", '"upstream %s"' % lname)
            elif qtype == T.MX:
                add("MX", "10 mail.upstream.test.")
            elif qtype == T.PTR:
                add("PTR", "ptr-%d.upstream.test." % n)
            else:
                r.authority.append(soa)
        # want_shuffle=False: dnspython shuffles the records of an RRset by
        # default, which would make the two upstreams differ.
        return r.to_wire(want_shuffle=False)


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# --------------------------------------------------------------------------
# rust-dns instances
# --------------------------------------------------------------------------

class Server:
    def __init__(self, label, binary, workdir, db, upstream_port,
                 rate=0, slip=0, cookies_required=False):
        self.label, self.binary, self.db = label, binary, db
        self.dir = workdir
        self.port = free_port()
        self.web = free_port()
        self.upstream_port = upstream_port
        self.rate, self.slip, self.cookies_required = rate, slip, cookies_required
        self.proc = None
        self.log_path = os.path.join(workdir, f"{label}.log")

    def config(self):
        return f"""# generated by scripts/equivalence.py
[server]
bind = ["127.0.0.1"]
port = {self.port}
udp = true
tcp = true
nsid = "{NSID}"
cookies = true
cookies_required = {str(self.cookies_required).lower()}
auto_ptr = true

[forwarding]
upstreams = ["127.0.0.1:{self.upstream_port}"]
timeout_ms = {FORWARD_TIMEOUT_MS}
allowed_clients = ["127.0.0.0/8"]

[rate_limit]
max_resolutions_per_second_per_address = {self.rate}
slip = {self.slip}

[transfer]
allow = ["127.0.0.0/8"]

[database]
path = "{self.db}"

[backup]
dir = ""

[web_console]
bind = "127.0.0.1:{self.web}"

[root]
username = "root"
password = "{ROOT_PASSWORD}"

[logging]
level = "warn"
"""

    def start(self):
        cfg = os.path.join(self.dir, f"{self.label}.toml")
        with open(cfg, "w") as f:
            f.write(self.config())
        self.logf = open(self.log_path, "ab")
        self.proc = subprocess.Popen([self.binary, "--config", cfg], stdout=self.logf,
                                     stderr=subprocess.STDOUT, cwd=self.dir)
        PROCS.append(self.proc)
        return self

    def wait_ready(self, timeout=30):
        deadline = time.time() + timeout
        url = f"http://127.0.0.1:{self.web}/api/health"
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.label} exited early:\n{self.tail()}")
            try:
                with urllib.request.urlopen(url, timeout=1) as r:
                    if r.status == 200:
                        # DNS listener up too?
                        w = build_query(1, "version.bind.", 16, 3)
                        if udp_exchange(self.port, w, 0.5) is not None:
                            return self
            except Exception:
                pass
            time.sleep(0.1)
        raise RuntimeError(f"{self.label} did not become ready:\n{self.tail()}")

    def stop(self):
        if self.proc:
            stop_proc(self.proc)
            self.logf.close()

    def tail(self, n=30):
        try:
            with open(self.log_path, errors="replace") as f:
                return "".join(f.readlines()[-n:])
        except OSError:
            return ""


# --------------------------------------------------------------------------
# Seeding through the HTTP API
# --------------------------------------------------------------------------

class Api:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def req(self, path, payload=None, method=None):
        body = None if payload is None else json.dumps(payload).encode()
        h = dict(CSRF)
        if body is not None:
            h["Content-Type"] = "application/json"
        r = urllib.request.Request(self.base + path, data=body, headers=h, method=method)
        try:
            with self.opener.open(r, timeout=10) as resp:
                data = resp.read()
                return resp.status, (json.loads(data) if data else None)
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"{path}: HTTP {e.code}: {e.read().decode(errors='replace')}")


def rec(n, t, v, ttl=None):
    d = {"name": n, "type": t, "value": v}
    if ttl is not None:
        d["ttl"] = ttl
    return d


EXTRA_ZONES = [
    # More shapes in the unsigned zone (merged into the conformance fixture).
    {"name": "example.test", "records": [
        rec("secure", "NS", "ns.secure.example.test."),
        rec("ns.secure", "A", "10.0.0.62"),
        rec("secure", "DS", "54321 13 2 " + "cd" * 32),
        rec("out", "CNAME", "www.upstream.test."),
        rec("outnx", "CNAME", "nxhost.upstream.test."),
        rec("chain", "CNAME", "alias.example.test."),
        rec("loop", "CNAME", "loop2.example.test."),
        rec("loop2", "CNAME", "loop.example.test."),
        rec("www2", "A", "10.0.0.1"),
        rec("v6only", "AAAA", "2001:db8::99"),
        rec("kid", "NS", "ns1.kid.example.test."),
        rec("ns1.kid", "A", "10.0.0.70"),
        rec("dn2", "DNAME", "upstream.test."),
        rec("*.wild", "TXT", "wild"),
        rec("*.wild", "A", "10.0.0.11"),
        rec("multi", "A", "10.0.0.31"),
        rec("multi", "A", "10.0.0.32"),
        rec("multi", "A", "10.0.0.33"),
        rec("ttl5", "A", "10.0.0.5", 5),
        rec("cnwild", "CNAME", "foo.apps.example.test."),
    ]},
    {"name": "signed.test", "records": [
        rec("out", "CNAME", "www.upstream.test."),
        rec("kid", "NS", "ns1.kid.signed.test."),
        rec("ns1.kid", "A", "10.1.0.70"),
        rec("loop", "CNAME", "loop.signed.test."),
        rec("*.wild", "TXT", "signed wild"),
        rec("cnwild", "CNAME", "foo.gate.signed.test."),
    ]},
    # Child zones hosted here as well (DS at their apex comes from the parent).
    {"name": "kid.example.test", "soa_mname": "ns1.kid.example.test.",
     "soa_rname": "hostmaster.kid.example.test.", "default_ttl": 600, "records": [
        rec("@", "NS", "ns1.kid.example.test."),
        rec("ns1", "A", "10.0.0.70"),
        rec("www", "A", "10.0.0.71"),
     ]},
    {"name": "kid.signed.test", "soa_mname": "ns1.kid.signed.test.",
     "soa_rname": "hostmaster.kid.signed.test.", "default_ttl": 600, "records": [
        rec("@", "NS", "ns1.kid.signed.test."),
        rec("ns1", "A", "10.1.0.70"),
        rec("www", "A", "10.1.0.71"),
        rec("www", "TXT", "kid"),
     ]},
    # A signed reverse zone (no auto-PTR inside a signed zone) ...
    {"name": "0.1.10.in-addr.arpa", "soa_mname": "ns1.signed.test.",
     "soa_rname": "hostmaster.signed.test.", "records": [
        rec("@", "NS", "ns1.signed.test."),
        rec("1", "PTR", "signed.test."),
     ]},
    # ... and an unsigned ip6.arpa zone with one explicit PTR.
    {"name": "8.b.d.0.1.0.0.2.ip6.arpa", "soa_mname": "ns1.example.test.",
     "soa_rname": "hostmaster.example.test.", "records": [
        rec("@", "NS", "ns1.example.test."),
        rec("9.9.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0", "PTR", "v6only.example.test."),
     ]},
]


def seed(api_url, workdir):
    """Seed the seeding instance; returns the TSIG keys {name: (alg, secret_b64)}."""
    env = dict(os.environ)
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "seed-conformance.py"), api_url],
                       capture_output=True, text=True, env=env)
    if r.returncode != 0:
        raise RuntimeError(f"seed-conformance.py failed:\n{r.stdout}\n{r.stderr}")
    api = Api(api_url)
    api.req("/api/auth/login", {"username": "root", "password": ROOT_PASSWORD})
    doc = {"version": 1, "exported_at": "2026-01-01T00:00:00Z", "zones": EXTRA_ZONES}
    st, res = api.req("/api/import?mode=merge", doc)
    if st != 200:
        raise RuntimeError(f"extra import failed: {st} {res}")
    for z in ("kid.signed.test", "0.1.10.in-addr.arpa"):
        st, res = api.req(f"/api/zones/{z}/dnssec", {"enabled": True}, "PUT")
        if st != 200 or res.get("state") != "signing":
            raise RuntimeError(f"DNSSEC not on for {z}: {st} {res}")
    keys = {
        # Created by seed-conformance.py with these fixed secrets.
        "conformance-key.": ("hmac-sha256", "Y29uZm9ybWFuY2UtdHNpZy1rZXktMzItYnl0ZXMhISE="),
        "conformance-other.": ("hmac-sha512",
                               "b3RoZXItem9uZS1rZXktdGhhdC1pcy1hbGxvd2VkLWZvci1vdGhlci10ZXN0LW9ubHktLTY0LWJ5dGVzLWxvbmc="),
    }
    for body in ({"name": "equiv-gen.", "algorithm": "hmac-sha256"},
                 {"name": "equiv-limited.", "algorithm": "hmac-sha512", "zones": ["example.test"]}):
        st, res = api.req("/api/tsig/keys", body)
        if st != 201 or not res.get("secret"):
            raise RuntimeError(f"TSIG key {body['name']} not created: {st} {res}")
        keys[body["name"]] = (body["algorithm"], res["secret"])
    return keys


# --------------------------------------------------------------------------
# Wire building
# --------------------------------------------------------------------------

def name_wire(name):
    """Uncompressed wire form, letter case preserved."""
    return dns.name.from_text(name).to_wire()


def opt_rr(payload=1232, version=0, do=False, options=(), owner=b"\x00"):
    ttl = (version << 16) | (0x8000 if do else 0)
    rdata = b"".join(struct.pack("!HH", c, len(d)) + d for c, d in options)
    return owner + struct.pack("!HHIH", 41, payload, ttl, len(rdata)) + rdata


def build_query(qid, name, qtype, qclass=1, rd=True, opcode=0, edns=None, flags=0,
                questions=None, authority=b"", nscount=0):
    f = ((opcode & 0xF) << 11) | (0x0100 if rd else 0) | flags
    qs = questions if questions is not None else [(name, qtype, qclass)]
    body = b"".join(name_wire(n) + struct.pack("!HH", t, c) for n, t, c in qs)
    ar = 0 if edns is None else 1
    return struct.pack("!HHHHHH", qid, f, len(qs), 0, nscount, ar) + body + authority + (edns or b"")


def soa_rr(zone, serial):
    rdata = b"\x00\x00" + struct.pack("!IIIII", serial, 0, 0, 0, 0)
    return name_wire(zone) + struct.pack("!HHIH", 6, 1, 0, len(rdata)) + rdata


# --------------------------------------------------------------------------
# Wire walking and normalisation
# --------------------------------------------------------------------------

class WireError(Exception):
    pass


def skip_name(w, i):
    while True:
        if i >= len(w):
            raise WireError("name runs past end")
        ln = w[i]
        if ln == 0:
            return i + 1
        if ln & 0xC0 == 0xC0:
            return i + 2
        if ln & 0xC0:
            raise WireError("bad label type")
        i += 1 + ln


def walk(w):
    """Yield (section, start, rtype, ttl_offset, rdata_start, rdata_end) per RR."""
    if len(w) < 12:
        raise WireError("short")
    qd, an, ns, ar = struct.unpack("!HHHH", w[4:12])
    i = 12
    for _ in range(qd):
        i = skip_name(w, i) + 4
    out = []
    for sec, cnt in ((1, an), (2, ns), (3, ar)):
        for _ in range(cnt):
            start = i
            i = skip_name(w, i)
            if i + 10 > len(w):
                raise WireError("rr header runs past end")
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", w[i:i + 10])
            rd = i + 10
            if rd + rdlen > len(w):
                raise WireError("rdata runs past end")
            out.append((sec, start, rtype, i + 4, rd, rd + rdlen))
            i = rd + rdlen
    return out


def normalise(w):
    """Zero the legitimately random bytes. Returns (bytes, set of tags)."""
    tags = set()
    try:
        rrs = walk(w)
    except WireError:
        return w, tags
    b = bytearray(w)
    for _sec, _start, rtype, _ttl, rd, end in rrs:
        if rtype == 46:  # RRSIG: keep the 18 fixed bytes and the signer
            p = skip_name(w, rd + 18)
            if p < end:
                b[p:end] = bytes(end - p)
                tags.add("rrsig-signature")
        elif rtype == 41:  # OPT: server part of COOKIE
            p = rd
            while p + 4 <= end:
                code, ln = struct.unpack("!HH", w[p:p + 4])
                if code == 10 and ln > 8:
                    b[p + 4 + 8:p + 4 + ln] = bytes(ln - 8)
                    tags.add("server-cookie")
                p += 4 + ln
        elif rtype == 250:  # TSIG: time signed, MAC, other data
            p = skip_name(w, rd)
            b[p:p + 6] = bytes(6)
            p += 8
            (macsize,) = struct.unpack("!H", w[p:p + 2])
            b[p + 2:p + 2 + macsize] = bytes(macsize)
            p += 2 + macsize + 4
            (olen,) = struct.unpack("!H", w[p:p + 2])
            b[p + 2:p + 2 + olen] = bytes(olen)
            tags.add("tsig-time/mac/other")
    return bytes(b), tags


def ttls_zeroed(w):
    """(bytes with every non-OPT TTL zeroed, list of TTLs) or None."""
    try:
        rrs = walk(w)
    except WireError:
        return None
    b = bytearray(w)
    ttls = []
    for _sec, _start, rtype, t, _rd, _end in rrs:
        if rtype != 41:
            ttls.append(struct.unpack("!I", w[t:t + 4])[0])
            b[t:t + 4] = bytes(4)
    return bytes(b), ttls


# --------------------------------------------------------------------------
# TSIG
# --------------------------------------------------------------------------

HASHES = {"hmac-sha256": hashlib.sha256, "hmac-sha512": hashlib.sha512,
          "hmac-sha384": hashlib.sha384, "hmac-sha1": hashlib.sha1}


def tsig_fields(w):
    """Parse the TSIG RR (last in additional) of a message, or None."""
    rrs = walk(w)
    if not rrs or rrs[-1][2] != 250:
        return None
    _sec, start, _t, _ttl, rd, _end = rrs[-1]
    key, _ = dns.name.from_wire(w, start)
    alg, used = dns.name.from_wire(w, rd)
    p = rd + used
    time48 = w[p:p + 6]
    fudge = w[p + 6:p + 8]
    (macsize,) = struct.unpack("!H", w[p + 8:p + 10])
    mac = w[p + 10:p + 10 + macsize]
    p += 10 + macsize
    orig_id, error, olen = struct.unpack("!HHH", w[p:p + 6])
    other = w[p + 6:p + 6 + olen]
    return dict(start=start, key=key, alg=alg, time48=time48, fudge=fudge, mac=mac,
                orig_id=orig_id, error=error, other=other)


def tsig_verify(msgs, secret_b64, alg, request_mac):
    """Verify the MAC of each message of a reply (RFC 8945 §4.3.3, §5.3.1).

    Returns None when all verify, else a string describing the problem.
    Unsigned error replies (MAC size 0: BADKEY, BADSIG) are accepted.
    """
    secret = base64.b64decode(secret_b64)
    h = HASHES[alg]
    prior = request_mac
    for i, w in enumerate(msgs):
        try:
            t = tsig_fields(w)
        except Exception as e:
            return f"message {i}: unparsable TSIG ({e})"
        if t is None:
            return f"message {i}: no TSIG record"
        if not t["mac"]:
            if t["error"] == 0:
                return f"message {i}: empty MAC with NOERROR"
            continue  # unsigned error reply
        body = bytearray(w[:t["start"]])
        body[0:2] = struct.pack("!H", t["orig_id"])
        (arcount,) = struct.unpack("!H", w[10:12])
        body[10:12] = struct.pack("!H", arcount - 1)
        data = struct.pack("!H", len(prior)) + prior + bytes(body)
        if i == 0:
            data += (t["key"].to_digestable() + struct.pack("!HI", 255, 0) + t["alg"].to_digestable()
                     + t["time48"] + t["fudge"] + struct.pack("!HH", t["error"], len(t["other"]))
                     + t["other"])
        else:
            data += t["time48"] + t["fudge"]
        want = hmac.new(secret, data, h).digest()
        if not hmac.compare_digest(want, t["mac"]):
            return f"message {i}: MAC does not verify"
        prior = t["mac"]
    return None


def tsig_sign(wire, keyname, alg, secret_b64, at=None, fudge=300):
    """Append a TSIG record (RFC 8945 §4.3.3 request digest) to a query.

    Done by hand rather than with dnspython so that deliberately odd
    queries (bad cookies, EDNS version 1, ...) can be signed unchanged.
    Returns (wire, request MAC)."""
    key = dns.name.from_text(keyname)
    algn = dns.name.from_text(alg)
    t = int(time.time() if at is None else at)
    time48 = struct.pack("!HI", t >> 32, t & 0xFFFFFFFF)
    timers = time48 + struct.pack("!H", fudge)
    variables = (key.to_digestable() + struct.pack("!HI", 255, 0) + algn.to_digestable()
                 + timers + struct.pack("!HH", 0, 0))
    mac = hmac.new(base64.b64decode(secret_b64), wire + variables, HASHES[alg]).digest()
    rdata = (algn.to_wire() + timers + struct.pack("!H", len(mac)) + mac
             + wire[:2] + struct.pack("!HH", 0, 0))
    rr = key.to_wire() + struct.pack("!HHIH", 250, 255, 0, len(rdata)) + rdata
    (ar,) = struct.unpack("!H", wire[10:12])
    out = wire[:10] + struct.pack("!H", ar + 1) + wire[12:] + rr
    return out, mac


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------

def udp_exchange(port, wire, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(wire, ("127.0.0.1", port))
        data, _ = s.recvfrom(65535)
        return data
    except socket.timeout:
        return None
    finally:
        s.close()


def tcp_exchange(port, frames, timeout=6.0):
    """Send length-prefixed frames, half-close, read every reply until EOF.

    Half-closing lets rust-dns finish what it was asked and then see EOF,
    so "no reply" and multi-message transfers need no guessing timeout.
    """
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    # Abortive close (RST) once everything is read: thousands of connections
    # would otherwise sit in TIME_WAIT and exhaust the ephemeral ports.
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    try:
        for f in frames:
            if isinstance(f, tuple):  # raw bytes, no length prefix
                s.sendall(f[0])
            else:
                s.sendall(struct.pack("!H", len(f)) + f)
        s.shutdown(socket.SHUT_WR)
        buf = b""
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            except ConnectionResetError:
                break
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    msgs, i = [], 0
    while i + 2 <= len(buf):
        (n,) = struct.unpack("!H", buf[i:i + 2])
        msgs.append(buf[i + 2:i + 2 + n])
        i += 2 + n
    if i != len(buf):
        msgs.append(b"<trailing:" + buf[i:] + b">")
    return msgs


# --------------------------------------------------------------------------
# Cases and comparison
# --------------------------------------------------------------------------

class Case:
    __slots__ = ("label", "proto", "wire", "fwd", "tsig", "timeout", "frames")

    def __init__(self, label, proto, wire, fwd=False, tsig=None, timeout=1.0, frames=None):
        self.label = label
        self.proto = proto
        self.wire = wire        # bytes, or (wire_for_A, wire_for_B)
        self.fwd = fwd          # forwarded name: TTL +-1 tolerance
        self.tsig = tsig        # (alg, secret_b64, request_mac) to verify replies
        self.timeout = timeout  # UDP: how long to wait for a reply
        self.frames = frames    # TCP: several frames on one connection

    def wire_for(self, idx):
        return self.wire[idx] if isinstance(self.wire, tuple) else self.wire


class Stats:
    def __init__(self):
        self.cases = 0
        self.queries = 0
        self.identical = 0
        self.normalised = 0
        self.tags = {}
        self.both_silent = 0
        self.diffs = []
        self.tsig_verified = 0


def send(port, case, idx):
    if case.proto == "udp":
        r = udp_exchange(port, case.wire_for(idx), case.timeout)
        return [] if r is None else [r]
    frames = case.frames if case.frames is not None else [case.wire_for(idx)]
    return tcp_exchange(port, frames)


def compare_msgs(a, b, fwd):
    """Returns (verdict, tags): 'identical' | 'normalised' | 'different'."""
    if a == b:
        return "identical", set()
    na, ta = normalise(a)
    nb, tb = normalise(b)
    if na == nb:
        return "normalised", ta | tb
    if fwd:
        za, zb = ttls_zeroed(na), ttls_zeroed(nb)
        if za and zb and za[0] == zb[0] and all(abs(x - y) <= 1 for x, y in zip(za[1], zb[1])):
            return "normalised", ta | tb | {"forwarded-ttl+-1"}
    return "different", set()


def run_case(case, A, B, st):
    ra = send(A.port, case, 0)
    rb = send(B.port, case, 1)
    st.cases += 1
    st.queries += 2
    problem = None
    tags = set()
    verdict = "identical"
    if not ra and not rb:
        st.both_silent += 1
    elif len(ra) != len(rb):
        problem = f"reply count differs: A={len(ra)} B={len(rb)}"
    else:
        for x, y in zip(ra, rb):
            v, t = compare_msgs(x, y, case.fwd)
            tags |= t
            if v == "different":
                problem = "reply bytes differ"
                break
            if v == "normalised":
                verdict = "normalised"
    if problem is None and case.tsig and ra:
        alg, secret, mac = case.tsig
        for who, msgs in (("A", ra), ("B", rb)):
            err = tsig_verify(msgs, secret, alg, mac)
            if err:
                problem = f"TSIG verification failed on {who}: {err}"
                break
        else:
            st.tsig_verified += 2
    if problem:
        st.diffs.append((case, ra, rb, problem))
    elif verdict == "normalised":
        st.normalised += 1
        for t in tags:
            st.tags[t] = st.tags.get(t, 0) + 1
    else:
        st.identical += 1
    return ra, rb


def decode(w):
    try:
        m = dns.message.from_wire(w, keyring=lambda *_: False, ignore_trailing=True,
                                  one_rr_per_rrset=True)
        return m.to_text()
    except Exception as e:
        return f"(undecodable: {e})"


def hexdiff(a, b):
    lines = []
    n = max(len(a), len(b))
    for off in range(0, n, 16):
        x, y = a[off:off + 16], b[off:off + 16]
        mark = " " if x == y else "!"
        lines.append(f"{mark} {off:04x}  {x.hex(' '):<47}  |  {y.hex(' ')}")
    return "\n".join(lines)


def report_diff(i, case, ra, rb, problem):
    log("=" * 78)
    log(f"DIFFERENCE #{i}: {case.label} [{case.proto}] -- {problem}")
    q = case.wire_for(0)
    log(f"query ({len(q)} bytes): {q.hex()}")
    if isinstance(case.wire, tuple):
        log(f"query to B: {case.wire_for(1).hex()}")
    for k in range(max(len(ra), len(rb))):
        a = ra[k] if k < len(ra) else None
        b = rb[k] if k < len(rb) else None
        log(f"--- message {k}: A ({'none' if a is None else len(a)} bytes) ---")
        log(decode(a) if a is not None else "(no reply)")
        log(f"--- message {k}: B ({'none' if b is None else len(b)} bytes) ---")
        log(decode(b) if b is not None else "(no reply)")
        if a is not None and b is not None and a != b:
            log("--- hex (normalised) A | B, '!' marks differing lines ---")
            log(hexdiff(normalise(a)[0], normalise(b)[0]))
    if not ra and not rb:
        log("(no reply from either)")


# --------------------------------------------------------------------------
# Query matrix
# --------------------------------------------------------------------------

AUTH_NAMES = [
    # example.test (unsigned)
    "example.test.", "www.example.test.", "alias.example.test.", "chain.example.test.",
    "ext.example.test.", "out.example.test.", "outnx.example.test.", "mail.example.test.",
    "a.b.example.test.", "b.example.test.", "apps.example.test.", "x.apps.example.test.",
    "foo.apps.example.test.", "deep.foo.apps.example.test.", "*.apps.example.test.",
    "sub.example.test.", "host.sub.example.test.", "ns.sub.example.test.",
    "secure.example.test.", "www.secure.example.test.", "kid.example.test.",
    "www.kid.example.test.", "nope.kid.example.test.", "old.example.test.",
    "x.old.example.test.", "a.b.old.example.test.", "dn2.example.test.", "www.dn2.example.test.",
    "nxhost.dn2.example.test.", "xn--mnchen-3ya.example.test.", "big.example.test.",
    "_sip._tcp.example.test.", "_tcp.example.test.", "_443._tcp.www.example.test.",
    "loop.example.test.", "nope.example.test.", "nope.nope.example.test.", "www2.example.test.",
    "v6only.example.test.", "a.wild.example.test.", "wild.example.test.", "x.y.wild.example.test.",
    "multi.example.test.", "ttl5.example.test.", "cnwild.example.test.",
    "WwW.ExAmPlE.TeSt.", "ALIAS.example.TEST.", "FOO.APPS.example.test.", "X.OLD.Example.Test.",
    # signed.test
    "signed.test.", "www.signed.test.", "alias.signed.test.", "ext.signed.test.",
    "out.signed.test.", "gate.signed.test.", "foo.gate.signed.test.", "x.y.gate.signed.test.",
    "a.b.deep.signed.test.", "b.deep.signed.test.", "deep.signed.test.", "_dmarc.signed.test.",
    "old.signed.test.", "x.old.signed.test.", "sub.signed.test.", "host.sub.signed.test.",
    "ns.sub.signed.test.", "secure.signed.test.", "www.secure.signed.test.", "kid.signed.test.",
    "www.kid.signed.test.", "nope.kid.signed.test.", "big.signed.test.", "many.signed.test.",
    "nope.signed.test.", "zzz.signed.test.", "aaa.signed.test.", "loop.signed.test.",
    "a.wild.signed.test.", "cnwild.signed.test.", "*.gate.signed.test.", "MaNy.SiGnEd.TeSt.",
    # reverse / auto-PTR
    "0.0.10.in-addr.arpa.", "25.0.0.10.in-addr.arpa.", "1.0.0.10.in-addr.arpa.",
    "53.0.0.10.in-addr.arpa.", "99.0.0.10.in-addr.arpa.", "0.1.10.in-addr.arpa.",
    "1.0.1.10.in-addr.arpa.", "80.0.1.10.in-addr.arpa.", "7.1.1.10.in-addr.arpa.",
    "62.0.0.10.in-addr.arpa.",
    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
    "9.9.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
    "0.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
]
FWD_NAMES = [
    "www.upstream.test.", "cname.upstream.test.", "nxhost.upstream.test.",
    "nodata.upstream.test.", "big.upstream.test.", "fail.upstream.test.",
    "MiXeD.UpStReAm.TeSt.", "upstream.test.", "8.7.6.5.in-addr.arpa.", "example.org.", ".",
]
TYPES = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "DNAME", "DS", "DNSKEY", "NSEC",
         "RRSIG", "PTR", "SRV", "CAA", "HTTPS", "NSEC3PARAM", "ANY", "TYPE65280"]
CC = b"equivCC1"  # client cookie (8 bytes)


def is_fwd(name):
    n = name.lower()
    return n in [x.lower() for x in FWD_NAMES]


def edns_variants(cookies):
    """name -> function(server_index) -> OPT RR bytes (or None for no EDNS).

    `cookies` holds the valid server cookie (24 bytes) obtained from each
    server for CC; the 'cookie-valid' variant sends each server its own.
    """
    return {
        "plain": lambda i: None,
        "edns": lambda i: opt_rr(1232),
        "do": lambda i: opt_rr(4096, do=True),
        "edns512": lambda i: opt_rr(512),
        "payload0": lambda i: opt_rr(0),
        "do512": lambda i: opt_rr(512, do=True),
        "edns-v1": lambda i: opt_rr(1232, version=1),
        "nsid": lambda i: opt_rr(1232, options=[(3, b"")]),
        "cookie-client": lambda i: opt_rr(1232, options=[(10, CC)]),
        "cookie-valid": lambda i: opt_rr(1232, options=[(10, cookies[i])]),
        "cookie-bogus": lambda i: opt_rr(1232, options=[(10, CC + b"\x01\x00\x00\x00" + bytes(12))]),
        "cookie-malformed": lambda i: opt_rr(1232, options=[(10, b"short")]),
        "unknown-opt": lambda i: opt_rr(1232, options=[(65001, b"\x01\x02")]),
        "combo": lambda i: opt_rr(1232, do=True, options=[(3, b""), (10, cookies[i])]),
    }


class IdGen:
    def __init__(self):
        self.n = 0x1000

    def __call__(self):
        self.n = (self.n * 1103515245 + 12345) & 0xFFFF  # varied, deterministic
        return self.n


def qcase(nid, label, proto, name, qtype, variant, ev, qclass=1, rd=True, opcode=0, flags=0,
          timeout=1.0):
    qid = nid()
    t = dns.rdatatype.from_text(qtype) if isinstance(qtype, str) else qtype
    wa = build_query(qid, name, t, qclass, rd, opcode, ev[variant](0), flags)
    wb = build_query(qid, name, t, qclass, rd, opcode, ev[variant](1), flags)
    wire = wa if wa == wb else (wa, wb)
    return Case(f"{label} {name} {qtype} class={qclass} {variant} rd={int(rd)}", proto, wire,
                fwd=is_fwd(name), timeout=timeout)


def get_cookie(port):
    w = build_query(0x4242, "example.test.", 6, edns=opt_rr(1232, options=[(10, CC)]))
    r = udp_exchange(port, w, 1.0)
    if r is None:
        raise RuntimeError("no reply while fetching a server cookie")
    for _s, _st, rtype, _t, rd, end in walk(r):
        if rtype == 41:
            p = rd
            while p + 4 <= end:
                code, ln = struct.unpack("!HH", r[p:p + 4])
                if code == 10:
                    return r[p + 4:p + 4 + ln]
                p += 4 + ln
    raise RuntimeError("no COOKIE in reply")


def main_matrix(A, B, keys, serials):
    nid = IdGen()
    ev = edns_variants((get_cookie(A.port), get_cookie(B.port)))
    names = AUTH_NAMES + FWD_NAMES
    cases = []
    add = cases.append

    # 1. Every name x every type, three EDNS shapes, UDP and TCP.
    for proto in ("udp", "tcp"):
        for variant in ("plain", "edns", "do"):
            for name in names:
                for t in TYPES:
                    add(qcase(nid, "matrix", proto, name, t, variant, ev))
    # 2. Every name x a few types x the other EDNS shapes (UDP; TCP for A).
    others = ["edns512", "payload0", "do512", "edns-v1", "nsid", "cookie-client", "cookie-valid",
              "cookie-bogus", "cookie-malformed", "unknown-opt", "combo"]
    for variant in others:
        for name in names:
            for t in ("A", "ANY", "TXT", "DNSKEY"):
                add(qcase(nid, "edns", "udp", name, t, variant, ev))
            add(qcase(nid, "edns", "tcp", name, "A", variant, ev))
    # 3. RD=0 (forwarded names are REFUSED without RD), CD/AD bits.
    for name in names:
        for t in ("A", "SOA", "PTR"):
            for variant in ("plain", "do"):
                add(qcase(nid, "rd0", "udp", name, t, variant, ev, rd=False))
        add(qcase(nid, "cd", "udp", name, "A", "do", ev, flags=0x0010))
        add(qcase(nid, "ad", "udp", name, "A", "edns", ev, flags=0x0020))
        add(qcase(nid, "z-bit", "udp", name, "A", "plain", ev, flags=0x0040))
    # 4. Classes: CHAOS, HS, NONE, ANY.
    for proto in ("udp", "tcp"):
        for variant in ("plain", "edns", "do", "nsid"):
            for name, t in (("version.bind.", "TXT"), ("VERSION.BIND.", "TXT"), ("version.bind.", "ANY"),
                            ("version.bind.", "A"), ("version.server.", "TXT"), ("hostname.bind.", "TXT"),
                            ("id.server.", "TXT"), ("www.example.test.", "TXT")):
                add(qcase(nid, "chaos", proto, name, t, variant, ev, qclass=3))
            for cls in (4, 254, 255, 2, 65280):
                for name in ("www.example.test.", "www.signed.test.", "nope.example.test.",
                             "www.upstream.test.", "example.test."):
                    for t in ("A", "SOA", "ANY"):
                        add(qcase(nid, f"class{cls}", proto, name, t, variant, ev, qclass=cls))
    # 5. Odd types: OPT as qtype, meta types, unknown.
    for proto in ("udp", "tcp"):
        for name in ("www.example.test.", "www.upstream.test.", "nope.signed.test."):
            for t in (41, 249, 250, 251, 252, 253, 254, 0, 65535, 65280):
                for variant in ("plain", "edns"):
                    add(qcase(nid, "qtype", proto, name, t, variant, ev))
    # 6. Opcodes other than QUERY.
    for proto in ("udp", "tcp"):
        for op in (1, 2, 3, 4, 5, 6, 15):
            for name, t in (("example.test.", "SOA"), ("www.example.test.", "A"),
                            ("www.upstream.test.", "A")):
                for variant in ("plain", "edns", "cookie-client", "edns-v1"):
                    add(qcase(nid, f"opcode{op}", proto, name, t, variant, ev, opcode=op))
    # 7. QDCOUNT 0 and 2, header oddities.
    for proto in ("udp", "tcp"):
        for variant in ("plain", "edns", "nsid"):
            o = ev[variant](0)
            for qs in ([], [("www.example.test.", 1, 1), ("www.example.test.", 28, 1)],
                       [("www.upstream.test.", 1, 1), ("www.upstream.test.", 1, 1)],
                       [("www.example.test.", 1, 1), ("www.upstream.test.", 1, 1)]):
                qid = nid()
                add(Case(f"qdcount={len(qs)} {qs} {variant}", proto,
                         build_query(qid, None, 0, edns=o, questions=qs)))
            for fl, what in ((0x8000, "QR=1 (a response)"), (0x0200, "TC=1"), (0x0400, "AA=1"),
                             (0x000F, "rcode=15 in query"), (0x0080, "RA=1")):
                add(Case(f"flags {what} {variant}", proto,
                         build_query(nid(), "www.example.test.", 1, edns=o, flags=fl)))
            # A query carrying an answer record.
            qid = nid()
            ans = name_wire("www.example.test.") + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([1, 2, 3, 4])
            w = struct.pack("!HHHHHH", qid, 0x0100, 1, 1, 0, 0) + name_wire("www.example.test.") + \
                struct.pack("!HH", 1, 1) + ans
            add(Case(f"query with ANCOUNT=1 {variant}", proto, w))
    # 8. Garbage.
    rng = random.Random(4242)
    garbage = [
        ("empty", b""), ("1 byte", b"\x00"), ("11 bytes", bytes(range(11))),
        ("header only qd=0", struct.pack("!HHHHHH", 0x1111, 0x0100, 0, 0, 0, 0)),
        ("header qd=1 no question", struct.pack("!HHHHHH", 0x1112, 0x0100, 1, 0, 0, 0)),
        ("truncated name", struct.pack("!HHHHHH", 0x1113, 0x0100, 1, 0, 0, 0) + b"\x03www\x07exam"),
        ("no qtype", struct.pack("!HHHHHH", 0x1114, 0x0100, 1, 0, 0, 0) + name_wire("www.example.test.")),
        ("pointer loop", struct.pack("!HHHHHH", 0x1115, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"),
        ("forward pointer", struct.pack("!HHHHHH", 0x1116, 0x0100, 1, 0, 0, 0) + b"\xc0\x20\x00\x01\x00\x01"),
        ("label 64", struct.pack("!HHHHHH", 0x1117, 0x0100, 1, 0, 0, 0) + b"\x40" + b"a" * 64 + b"\x00\x00\x01\x00\x01"),
        ("label type 0x80", struct.pack("!HHHHHH", 0x1118, 0x0100, 1, 0, 0, 0) + b"\x81a\x00\x00\x01\x00\x01"),
        ("arcount=1 missing", build_query(0x1119, "www.example.test.", 1)[:4] + b"\x00\x01\x00\x00\x00\x00\x00\x01"
         + build_query(0x1119, "www.example.test.", 1)[12:]),
        ("two OPT", build_query(0x111a, "www.example.test.", 1)[:10] + b"\x00\x02"
         + build_query(0x111a, "www.example.test.", 1)[12:] + opt_rr() + opt_rr()),
        ("OPT with owner", build_query(0x111b, "www.example.test.", 1, edns=opt_rr(owner=name_wire("x.")))),
        ("OPT bad option len", build_query(0x111c, "www.example.test.", 1,
                                           edns=b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 4) + b"\x00\x0a\x00\x08")),
        ("trailing junk", build_query(0x111d, "www.example.test.", 1) + b"junkjunk"),
        ("response to forwarded", build_query(0x111e, "www.upstream.test.", 1, flags=0x8000)),
        ("response with EDNS", build_query(0x111f, "www.example.test.", 1, edns=opt_rr(), flags=0x8080)),
        ("max name", build_query(0x1120, ".".join(["a" * 63] * 3 + ["b" * 61]) + ".", 1)),
    ]
    for k in range(40):
        garbage.append((f"random #{k}", bytes(rng.getrandbits(8) for _ in range(rng.randint(12, 96)))))
    for k in range(20):  # a valid header with random body
        body = bytes(rng.getrandbits(8) for _ in range(rng.randint(4, 60)))
        garbage.append((f"random body #{k}", struct.pack("!HHHHHH", 0x2000 + k, 0x0100, 1, 0, 0, rng.randint(0, 2)) + body))
    for label, w in garbage:
        add(Case(f"garbage: {label}", "udp", w, timeout=0.3))
        if w:
            add(Case(f"garbage: {label}", "tcp", w))
    add(Case("garbage: tcp zero-length frame", "tcp", b"", frames=[b""]))
    add(Case("garbage: tcp short frame", "tcp", b"", frames=[(b"\x00\x30\x12\x34",)]))
    add(Case("tcp: two queries on one connection", "tcp", b"",
             frames=[build_query(0x3001, "www.example.test.", 1), build_query(0x3002, "www.upstream.test.", 1)]))
    add(Case("tcp: garbage then a query", "tcp", b"",
             frames=[b"\x01\x02\x03", build_query(0x3003, "www.example.test.", 1)]))
    add(Case("tcp: response then a query", "tcp", b"",
             frames=[build_query(0x3004, "www.example.test.", 1, flags=0x8000),
                     build_query(0x3005, "www.signed.test.", 1)]))

    # 9. Forwarding timeout (upstream never answers): SERVFAIL after timeout_ms.
    for proto in ("udp", "tcp"):
        for variant in ("plain", "edns", "do"):
            for t in ("A", "TXT"):
                add(qcase(nid, "fwd-timeout", proto, "timeout.upstream.test.", t, variant, ev, timeout=3.0))
                cases[-1].fwd = True

    # 10. Zone transfers.
    zones = ["example.test.", "signed.test.", "0.0.10.in-addr.arpa.", "kid.example.test.",
             "kid.signed.test.", "0.1.10.in-addr.arpa.", "8.b.d.0.1.0.0.2.ip6.arpa."]
    for z in zones:
        serial = serials[z]
        for variant in ("plain", "edns", "do", "cookie-client"):
            o = ev[variant](0)
            add(Case(f"AXFR {z} {variant}", "tcp", build_query(nid(), z, 252, edns=o, rd=False)))
            add(Case(f"AXFR {z} {variant}", "udp", build_query(nid(), z, 252, edns=o, rd=False)))
            for s in (serial - 1, serial, serial + 1):
                for proto in ("tcp", "udp"):
                    add(Case(f"IXFR {z} serial={s} {variant}", proto,
                             build_query(nid(), z, 251, edns=o, rd=False, authority=soa_rr(z, s), nscount=1)))
            add(Case(f"IXFR {z} no SOA {variant}", "tcp", build_query(nid(), z, 251, edns=o)))
        add(Case(f"AXFR {z} class CH", "tcp", build_query(nid(), z, 252, qclass=3)))
        add(Case(f"AXFR {z} class ANY", "tcp", build_query(nid(), z, 252, qclass=255)))
    for n in ("www.example.test.", "upstream.test.", "sub.example.test.", "EXAMPLE.test.", "."):
        add(Case(f"AXFR {n}", "tcp", build_query(nid(), n, 252)))
        add(Case(f"IXFR {n}", "tcp", build_query(nid(), n, 251, authority=soa_rr(n, 1), nscount=1)))

    # 11. TSIG.
    for keyname, (alg, secret) in keys.items():
        for name, t, variant, proto in (
                ("www.example.test.", "A", "plain", "udp"), ("www.example.test.", "A", "edns", "tcp"),
                ("www.signed.test.", "A", "do", "udp"), ("nope.signed.test.", "AAAA", "do", "tcp"),
                ("www.upstream.test.", "A", "edns", "udp"), ("nxhost.upstream.test.", "A", "plain", "tcp"),
                ("many.signed.test.", "A", "do512", "udp"), ("big.example.test.", "TXT", "plain", "udp"),
                ("big.upstream.test.", "TXT", "edns", "udp"), ("version.bind.", "TXT", "plain", "udp"),
                ("www.example.test.", "A", "cookie-client", "udp"), ("www.example.test.", "A", "edns-v1", "udp"),
                ("www.example.test.", "A", "cookie-malformed", "udp")):
            qid = nid()
            base = build_query(qid, name, dns.rdatatype.from_text(t),
                               3 if name == "version.bind." else 1, edns=ev[variant](0))
            w, mac = tsig_sign(base, keyname, alg, secret)
            add(Case(f"TSIG {keyname} {name} {t} {variant}", proto, w, fwd=is_fwd(name),
                     tsig=(alg, secret, mac)))
        for z in zones:
            w, mac = tsig_sign(build_query(nid(), z, 252, rd=False), keyname, alg, secret)
            add(Case(f"TSIG {keyname} AXFR {z}", "tcp", w, tsig=(alg, secret, mac)))
            w, mac = tsig_sign(build_query(nid(), z, 251, rd=False, authority=soa_rr(z, serials[z] - 1),
                                           nscount=1), keyname, alg, secret)
            add(Case(f"TSIG {keyname} IXFR {z}", "udp", w, tsig=(alg, secret, mac)))
    alg, secret = keys["equiv-gen."]
    for name, t, proto in (("www.example.test.", 1, "udp"), ("www.example.test.", 1, "tcp"),
                           ("www.upstream.test.", 1, "udp"), ("example.test.", 252, "tcp")):
        base = build_query(nid(), name, t)
        # Unknown key.
        w, mac = tsig_sign(base, "no-such-key.", "hmac-sha256", base64.b64encode(b"k" * 32).decode())
        add(Case(f"TSIG unknown key {name} {t}", proto, w, tsig=(alg, secret, mac)))
        # Bad MAC: flip the last MAC byte.
        w, mac = tsig_sign(base, "equiv-gen.", alg, secret)
        f = tsig_fields(w)
        pos = w.index(f["mac"]) + len(f["mac"]) - 1
        bad = w[:pos] + bytes([w[pos] ^ 0xFF]) + w[pos + 1:]
        add(Case(f"TSIG bad MAC {name} {t}", proto, bad, tsig=(alg, secret, tsig_fields(bad)["mac"])))
        # Bad time: an hour in the past / future.
        for skew in (-3600, 3600):
            w, mac = tsig_sign(base, "equiv-gen.", alg, secret, at=time.time() + skew)
            add(Case(f"TSIG bad time {skew:+d}s {name} {t}", proto, w, tsig=(alg, secret, mac)))
        # Truncated MAC (BADTRUNC / FORMERR territory): MAC size 10.
        w, mac = tsig_sign(base, "equiv-gen.", alg, secret)
        f = tsig_fields(w)
        rd, end = walk(w)[-1][4:6]
        cut = len(f["mac"]) - 10
        i = w.index(f["mac"])
        short = (w[:rd - 2] + struct.pack("!H", end - rd - cut) + w[rd:i - 2] + struct.pack("!H", 10)
                 + f["mac"][:10] + w[i + len(f["mac"]):])
        add(Case(f"TSIG short MAC {name} {t}", proto, short))
    # A TSIG record that is not the last one, and one with a mangled length.
    w, _ = tsig_sign(build_query(nid(), "www.example.test.", 1), "equiv-gen.", alg, secret)
    add(Case("TSIG then OPT", "udp", w[:10] + struct.pack("!H", 2) + w[12:] + opt_rr()))
    add(Case("TSIG cut short", "udp", w[:-5]))
    return cases


def ratelimit_phase(A, B, st):
    """Burst over the limit (5/s, slip 2) from one UDP socket; compare the
    replied / dropped / slip sequence. Retried when a burst straddles a
    rate-limit window boundary (the windows are counted from each process's
    start, so a boundary can fall inside one burst and not the other)."""
    names = ["www.example.test.", "www.signed.test.", "www.upstream.test.", "nope.example.test."]

    def burst(port, base_id):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.4)
        wires = [build_query(base_id + k, names[k % len(names)], 1, edns=opt_rr() if k % 2 else None)
                 for k in range(14)]
        t0 = time.monotonic()
        for w in wires:
            s.sendto(w, ("127.0.0.1", port))
        # Then at once one TCP query (over the limit: REFUSED), in the same
        # window; the UDP replies wait in the socket buffer meanwhile.
        tcp = tcp_exchange(port, [build_query(base_id + 99, "www.example.test.", 1)])
        spent = time.monotonic() - t0
        got = {}
        while True:
            try:
                d, _ = s.recvfrom(65535)
            except socket.timeout:
                break
            got[struct.unpack("!H", d[:2])[0]] = d
        s.close()
        seq = [got.get(base_id + k) for k in range(14)]
        return seq, tcp, spent

    last = None
    for attempt in range(4):
        time.sleep(1.1)  # a fresh window for both servers
        sa, ta, da = burst(A.port, 0x5000 + attempt * 0x100)
        time.sleep(1.1)
        sb, tb, db = burst(B.port, 0x5000 + attempt * 0x100)
        st.queries += 30
        pattern = lambda seq: "".join("." if r is None else ("s" if r[2] & 0x02 else "R") for r in seq)
        pa, pb = pattern(sa), pattern(sb)
        ok = pa == pb and len(ta) == len(tb)
        bad = []
        if ok:
            for k, (x, y) in enumerate(zip(sa + ta, sb + tb)):
                if x is not None and compare_msgs(x, y, True)[0] == "different":
                    bad.append(k)
        log(f"  rate-limit burst attempt {attempt + 1}: A {pa} TCP={len(ta)}  B {pb} TCP={len(tb)}"
            f"  (sent in {da * 1000:.1f} / {db * 1000:.1f} ms)")
        if ok and not bad:
            st.cases += 1
            st.identical += 1
            return
        last = (pa, pb, sa, sb, ta, tb, bad)
    st.cases += 1
    pa, pb, sa, sb, ta, tb, bad = last
    case = Case("rate-limit burst (14 UDP + 1 TCP, limit 5/s, slip 2)", "udp", b"")
    st.diffs.append((case, [x or b"" for x in sa + ta], [x or b"" for x in sb + tb],
                     f"replied/dropped/slip sequence differs: A={pa} B={pb} bad={bad}"))


def cookies_required_matrix(A, B):
    nid = IdGen()
    nid.n = 0x777
    ev = edns_variants((get_cookie(A.port), get_cookie(B.port)))
    cases = []
    for proto in ("udp", "tcp"):
        for variant in ("plain", "edns", "do", "nsid", "cookie-client", "cookie-valid", "cookie-bogus",
                        "cookie-malformed", "combo", "edns-v1"):
            for name in ("example.test.", "www.example.test.", "www.signed.test.", "nope.signed.test.",
                         "www.upstream.test.", "nxhost.upstream.test.", "1.0.0.10.in-addr.arpa."):
                for t in ("A", "SOA", "ANY"):
                    cases.append(qcase(nid, "cookies_required", proto, name, t, variant, ev))
            cases.append(qcase(nid, "cookies_required", proto, "version.bind.", "TXT", variant, ev, qclass=3))
            qid = nid()
            wa, wb = (build_query(qid, "example.test.", 252, edns=ev[variant](i)) for i in (0, 1))
            cases.append(Case(f"cookies_required AXFR example.test {variant}", proto,
                              wa if wa == wb else (wa, wb)))
    return cases


def zone_serials(port, zones):
    out = {}
    for z in zones:
        r = udp_exchange(port, build_query(7, z, 6), 1.0)
        m = dns.message.from_wire(r)
        out[z] = m.answer[0][0].serial
    return out


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def self_test_perturb(cases):
    """--self-test: send B a slightly different query in a few cases (another
    message ID; another letter case in the name; RD cleared; DO set) so the
    replies must differ. Returns the perturbed cases."""
    picked = []

    def pick(pred, change):
        for c in cases:
            if c not in picked and c.frames is None and not isinstance(c.wire, tuple) \
                    and c.tsig is None and len(c.wire) >= 12 and pred(c):
                c.wire = (c.wire, change(c.wire))
                picked.append(c)
                return

    other_id = lambda w: bytes([w[0] ^ 0x01]) + w[1:]
    pick(lambda c: c.proto == "udp" and "www.example.test. A " in c.label, other_id)
    pick(lambda c: c.proto == "tcp" and "AXFR signed.test." in c.label, other_id)
    # (Not a forwarded name: the forwarding cache keeps the letter case of
    # the query that filled it, so that would change later answers too.)
    pick(lambda c: c.proto == "udp" and "matrix www.example.test. AAAA " in c.label,
         lambda w: w[:13] + w[13:16].upper() + w[16:])  # "www" -> "WWW"
    pick(lambda c: c.proto == "tcp" and "matrix www.signed.test. A " in c.label,
         lambda w: w[:2] + bytes([w[2] & ~0x01]) + w[3:])  # RD off
    pick(lambda c: c.proto == "udp" and "matrix many.signed.test. A " in c.label and " edns " in c.label,
         lambda w: w[:-4] + bytes([w[-4] | 0x80]) + w[-3:])  # DO on
    log(f"self-test: perturbed {len(picked)} cases: " + "; ".join(c.label for c in picked))
    return picked


def run_cases(cases, A, B, st, title):
    t0 = time.monotonic()
    before = (st.identical, st.normalised, st.both_silent, len(st.diffs))
    for c in cases:
        run_case(c, A, B, st)
    i, n, s, d = (x - y for x, y in zip((st.identical, st.normalised, st.both_silent, len(st.diffs)), before))
    log(f"  {title}: {len(cases)} cases in {time.monotonic() - t0:.1f}s "
        f"(identical {i}, normalised {n}, no reply from either {s}, differences {d})")


def start_pair(base, new, work, db_a, db_b, ups, **kw):
    A = Server("A-base", base, work, db_a, ups[0].port, **kw).start()
    B = Server("B-new", new, work, db_b, ups[1].port, **kw).start()
    A.wait_ready()
    B.wait_ready()
    return A, B


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", required=True, help="baseline rust-dns binary (seeds the data, server A)")
    ap.add_argument("--new", required=True, help="rust-dns binary under test (server B)")
    ap.add_argument("--keep", action="store_true", help="keep the temporary directory")
    ap.add_argument("--workdir", help="parent directory for the temporary directory")
    ap.add_argument("--show", type=int, default=25, help="differences printed in full (default 25)")
    ap.add_argument("--new-resolver", metavar="JSON",
                    help="PUT this JSON to B's /api/settings/resolver before the matrix (e.g. "
                         "'{\"domain_needed\":false,\"bogus_priv\":false}' to compare a version "
                         "with the phase I filters against one without them, all switched off)")
    ap.add_argument("--self-test", action="store_true",
                    help="perturb the query sent to B in a few cases and check that exactly those "
                         "are reported (proves the comparison detects differences)")
    args = ap.parse_args()
    for b in (args.base, args.new):
        if not (os.path.isfile(b) and os.access(b, os.X_OK)):
            sys.exit(f"not an executable: {b}")
    base, new = os.path.abspath(args.base), os.path.abspath(args.new)

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    if args.workdir:
        os.makedirs(args.workdir, exist_ok=True)
    work = tempfile.mkdtemp(prefix="rust-dns-equiv-", dir=args.workdir)
    started = time.monotonic()
    ups = [FakeUpstream().start(), FakeUpstream().start()]
    st = Stats()
    try:
        # ---- 1. seed one BASE instance, stop it, copy its database twice
        log(f"workdir: {work}")
        seed_dir = os.path.join(work, "seed")
        os.makedirs(seed_dir)
        seed_db = os.path.join(seed_dir, "rust-dns.db")
        S = Server("seed", base, work, seed_db, ups[0].port).start().wait_ready()
        keys = seed(f"http://127.0.0.1:{S.web}", work)
        zones = ["example.test.", "signed.test.", "0.0.10.in-addr.arpa.", "kid.example.test.",
                 "kid.signed.test.", "0.1.10.in-addr.arpa.", "8.b.d.0.1.0.0.2.ip6.arpa."]
        S.stop()
        if S.proc.returncode not in (0, -signal.SIGINT, 130):
            log(f"warning: seed instance exit status {S.proc.returncode}")
        dbs = []
        for tag in ("a", "b"):
            d = os.path.join(work, f"db-{tag}")
            os.makedirs(d)
            for suffix in ("", "-wal", "-shm"):
                if os.path.exists(seed_db + suffix):
                    shutil.copy2(seed_db + suffix, os.path.join(d, "rust-dns.db" + suffix))
            dbs.append(os.path.join(d, "rust-dns.db"))
        log(f"seeded: {len(zones)} zones, TSIG keys {', '.join(keys)}; database copied twice")

        # ---- 2. main phase
        A, B = start_pair(base, new, work, dbs[0], dbs[1], ups)
        if args.new_resolver:
            # Stored in B's database: applies to every later phase too.
            api = Api(f"http://127.0.0.1:{B.web}")
            api.req("/api/auth/login", {"username": "root", "password": ROOT_PASSWORD})
            code, res = api.req("/api/settings/resolver", json.loads(args.new_resolver), method="PUT")
            if code != 200:
                raise RuntimeError(f"B: PUT /api/settings/resolver: {code} {res}")
            log(f"B: resolver settings {json.dumps(res['settings'])}")
        serials = zone_serials(A.port, zones)
        if zone_serials(B.port, zones) != serials:
            log("warning: zone serials differ between A and B")
        cases = main_matrix(A, B, keys, serials)
        perturbed = self_test_perturb(cases) if args.self_test else []
        log(f"main phase: {len(cases)} cases (A={A.port} B={B.port})")
        run_cases(cases, A, B, st, "main phase")
        A.stop()
        B.stop()

        # ---- 3. rate limit phase
        log("rate-limit phase (5/s, slip 2)")
        A, B = start_pair(base, new, work, dbs[0], dbs[1], ups, rate=5, slip=2)
        ratelimit_phase(A, B, st)
        A.stop()
        B.stop()

        # ---- 4. cookies_required phase
        A, B = start_pair(base, new, work, dbs[0], dbs[1], ups, cookies_required=True)
        cases = cookies_required_matrix(A, B)
        run_cases(cases, A, B, st, "cookies_required phase")
        A.stop()
        B.stop()
    except Exception as e:
        import traceback
        traceback.print_exc()
        log(f"ERROR: {e}")
        stop_all()
        if args.keep:
            log(f"temporary files kept at {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)
        return 2
    finally:
        for u in ups:
            u.stop.set()
        stop_all()

    # ---- report
    for i, (case, ra, rb, problem) in enumerate(st.diffs[:args.show], 1):
        report_diff(i, case, ra, rb, problem)
    if len(st.diffs) > args.show:
        log("=" * 78)
        log(f"... and {len(st.diffs) - args.show} more differences:")
        for case, _ra, _rb, problem in st.diffs[args.show:]:
            log(f"  {case.label} [{case.proto}]: {problem}")
    log("=" * 78)
    log("SUMMARY")
    log(f"  base: {base}")
    log(f"  new:  {new}")
    log(f"  cases (query pairs)       {st.cases}")
    log(f"  queries sent              {st.queries}")
    log(f"  byte-identical            {st.identical}  (of which no reply from either: {st.both_silent})")
    log(f"  identical after normalising {st.normalised}")
    for t, n in sorted(st.tags.items()):
        log(f"      {t:<24} {n} cases")
    log(f"  TSIG MACs verified        {st.tsig_verified}")
    log(f"  upstream queries          A={ups[0].queries} B={ups[1].queries}")
    log(f"  DIFFERENCES               {len(st.diffs)}")
    log("  normalised fields: RRSIG signature; COOKIE bytes after the 8-byte client cookie;")
    log("  TSIG time signed / MAC / other data (MACs verified); forwarded-cache TTLs +-1s.")
    log(f"  runtime {time.monotonic() - started:.1f}s")
    if args.keep:
        log(f"temporary files kept at {work}")
    else:
        shutil.rmtree(work, ignore_errors=True)
    if args.self_test:
        found = sorted(c.label + " [" + c.proto + "]" for c, *_ in st.diffs)
        want = sorted(c.label + " [" + c.proto + "]" for c in perturbed)
        ok = found == want
        log(f"SELF-TEST {'PASSED' if ok else 'FAILED'}: perturbed {len(want)} cases, "
            f"{len(found)} differences reported")
        return 0 if ok else 1
    return 1 if st.diffs else 0


if __name__ == "__main__":
    sys.exit(main())
