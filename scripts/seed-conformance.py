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


def request(path, payload=None, headers=None):
    body = None if payload is None else json.dumps(payload).encode()
    h = {} if headers is None else dict(headers)
    if body is not None:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=body, headers=h)
    try:
        with opener.open(req, timeout=2) as response:
            data = response.read()
            return response.status, json.loads(data) if data else None
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{path}: HTTP {e.code}: {e.read().decode(errors='replace')}") from e


for _ in range(100):
    try:
        request("/api/health")
        break
    except Exception:
        time.sleep(0.15)
else:
    raise SystemExit("rust-dns did not become healthy")

request("/api/auth/login", {"username": "root", "password": "ci-root-password"})

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
doc = {"version": 1, "exported_at": "2026-01-01T00:00:00Z", "zones": [zone, reverse]}
status, result = request(
    "/api/import?mode=replace",
    doc,
    {"X-Requested-With": "rust-dns"},
)
if status != 200 or result.get("records_added", 0) < 20:
    raise SystemExit(f"fixture import was incomplete: {result}")
print(f"seeded {result['records_added']} records in {result['zones_created']} zones")

# TSIG keys (RFC 8945) with fixed secrets known to conformance.py.
TSIG_KEYS = [
    {"name": "conformance-key.", "algorithm": "hmac-sha256",
     "secret": "Y29uZm9ybWFuY2UtdHNpZy1rZXktMzItYnl0ZXMhISE="},
    {"name": "conformance-other.", "algorithm": "hmac-sha512",
     "secret": "b3RoZXItem9uZS1rZXktdGhhdC1pcy1hbGxvd2VkLWZvci1vdGhlci10ZXN0LW9ubHktLTY0LWJ5dGVzLWxvbmc=",
     "zones": ["other.test"]},
]
for key in TSIG_KEYS:
    status, created = request("/api/tsig/keys", key, {"X-Requested-With": "rust-dns"})
    if status != 201 or created.get("secret") != key["secret"]:
        raise SystemExit(f"TSIG key {key['name']} was not created: {status}")
print(f"created {len(TSIG_KEYS)} TSIG keys")
