#!/usr/bin/env python3
"""Seed the temporary instance started by conformance-local.sh."""
import http.cookiejar
import json
import sys
import time
import urllib.error
import urllib.request

base = sys.argv[1].rstrip("/")
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def csrf_of(opener):
    """O7: the session's CSRF token (rdns_csrf cookie), sent with cookie writes."""
    for h in opener.handlers:
        for c in getattr(h, "cookiejar", None) or []:
            if c.name in ("rdns_csrf", "__Host-rdns_csrf"):
                return c.value
    return ""


def request(path, payload=None, headers=None, method=None):
    body = None if payload is None else json.dumps(payload).encode()
    h = {} if headers is None else dict(headers)
    if "X-Requested-With" in h:
        h["X-CSRF-Token"] = csrf_of(opener)
    if body is not None:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=body, headers=h, method=method)
    try:
        with opener.open(req, timeout=2) as response:
            data = response.read()
            return response.status, json.loads(data) if data else None
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{path}: HTTP {e.code}: {e.read().decode(errors='replace')}") from e


for _ in range(100):
    try:
        request("/rust-dns/api/health")
        break
    except Exception:
        time.sleep(0.15)
else:
    raise SystemExit("rust-dns did not become healthy")

request("/rust-dns/api/auth/login", {"username": "root", "password": "ci-root-password"})

zone = {
    "name": "example.test",
    "soa_mname": "ns1.example.test.",
    "soa_rname": "hostmaster.example.test.",
    "refresh": 3600,
    "retry": 600,
    "expire": 1209600,
    "minimum": 300,
    "default_ttl": 300,
    "records": [],
}


def add(name, rtype, value):
    zone["records"].append({"name": name, "type": rtype, "value": value})


for record in [
    ("@", "NS", "ns1.example.test."),
    ("ns1", "A", "10.0.0.53"),
    ("www", "A", "10.0.0.1"),
    ("www", "AAAA", "2001:db8::1"),
    ("alias", "CNAME", "www.example.test."),
    ("ext", "CNAME", "example.org."),
    ("@", "MX", "10 mail.example.test."),
    ("mail", "A", "10.0.0.25"),
    ("@", "TXT", "v=spf1 -all"),
    ("_sip._tcp", "SRV", "10 20 5060 sip.example.test."),
    ("sip", "A", "10.0.0.54"),
    ("a.b", "A", "10.0.0.60"),
    ("*.apps", "A", "10.0.0.9"),
    ("x.apps", "A", "10.0.0.10"),
    ("sub", "NS", "ns.sub.example.test."),
    ("ns.sub", "A", "10.0.0.61"),
    ("@", "CAA", '0 issue "letsencrypt.org"'),
    ("@", "HTTPS", "1 . alpn=h2,h3"),
    ("_443._tcp.www", "TLSA", "3 1 1 " + "a" * 64),
    ("www", "SSHFP", "1 1 " + "a" * 40),
    ("old", "DNAME", "www.example.test."),
    ("münchen", "A", "10.0.0.77"),
    ("big", "TXT", "x" * 1200),
]:
    add(*record)

reverse = {
    "name": "0.0.10.in-addr.arpa",
    "soa_mname": "ns1.0.0.10.in-addr.arpa.",
    "soa_rname": "hostmaster.0.0.10.in-addr.arpa.",
    "records": [{"name": "25", "type": "PTR", "value": "mail.example.test."}],
}
# A DNSSEC-signed zone (signing is turned on below through the API).
signed = {
    "name": "signed.test",
    "soa_mname": "ns1.signed.test.",
    "soa_rname": "hostmaster.signed.test.",
    "minimum": 300,
    "default_ttl": 3600,
    "records": [{"name": n, "type": t, "value": v} for (n, t, v) in [
        ("@", "NS", "ns1.signed.test."),
        ("@", "A", "10.1.0.1"),
        ("@", "MX", "10 mail.signed.test."),
        ("@", "TXT", "v=spf1 -all"),
        ("ns1", "A", "10.1.0.53"),
        ("mail", "A", "10.1.0.25"),
        ("www", "A", "10.1.0.80"),
        ("www", "AAAA", "2001:db8:1::80"),
        ("alias", "CNAME", "www.signed.test."),
        ("ext", "CNAME", "example.org."),
        ("gate", "A", "10.1.0.2"),
        ("*.gate", "A", "10.1.0.3"),
        ("a.b.deep", "TXT", "below two empty non-terminals"),
        ("_dmarc", "TXT", "v=DMARC1; p=none"),
        ("old", "DNAME", "gate.signed.test."),
        ("sub", "NS", "ns.sub.signed.test."),
        ("ns.sub", "A", "10.1.0.61"),
        ("secure", "NS", "ns.secure.signed.test."),
        ("ns.secure", "A", "10.1.0.62"),
        ("secure", "DS", "12345 13 2 " + "ab" * 32),
        ("big", "TXT", "y" * 700),
    ] + [("many", "A", f"10.1.1.{i}") for i in range(1, 31)]],
}
doc = {"version": 1, "exported_at": "2026-01-01T00:00:00Z", "zones": [zone, reverse, signed]}
status, result = request(
    "/rust-dns/api/import?mode=replace",
    doc,
    {"X-Requested-With": "rust-dns"},
)
if status != 200 or result.get("records_added", 0) < 20:
    raise SystemExit(f"fixture import was incomplete: {result}")
print(f"seeded {result['records_added']} records in {result['zones_created']} zones")

status, st = request("/rust-dns/api/zones/signed.test/dnssec", {"enabled": True}, {"X-Requested-With": "rust-dns"}, "PUT")
if status != 200 or st.get("state") != "signing":
    raise SystemExit(f"DNSSEC was not turned on for signed.test: {status} {st}")
print(f"signed.test: DNSSEC on, key tag {st['key']['key_tag']}")

# TSIG keys (RFC 8945) with fixed secrets known to conformance.py.
TSIG_KEYS = [
    {"name": "conformance-key.", "algorithm": "hmac-sha256",
     "secret": "Y29uZm9ybWFuY2UtdHNpZy1rZXktMzItYnl0ZXMhISE="},
    {"name": "conformance-other.", "algorithm": "hmac-sha512",
     "secret": "b3RoZXItem9uZS1rZXktdGhhdC1pcy1hbGxvd2VkLWZvci1vdGhlci10ZXN0LW9ubHktLTY0LWJ5dGVzLWxvbmc=",
     "zones": ["other.test"]},
]
for key in TSIG_KEYS:
    status, created = request("/rust-dns/api/tsig/keys", key, {"X-Requested-With": "rust-dns"})
    if status != 201 or created.get("secret") != key["secret"]:
        raise SystemExit(f"TSIG key {key['name']} was not created: {status}")
print(f"created {len(TSIG_KEYS)} TSIG keys")
