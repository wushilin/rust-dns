#!/usr/bin/env python3
"""Complete the conformance fixture for the zone checkers and DNSViz (run.sh).

  python3 seed-interop.py <web-console-url> [root-password]

Two fixture zones have no NS records of their own, so rust-dns serves one
synthesized from the SOA MNAME (ns1.<zone>), a name without an address.
named-checkzone refuses such a zone ("NS ... has no address records"), so
here the reverse zone gets an explicit NS with an address (in example.test)
and rrtypes.test an address for its name server. conformance.py does not
check either, so this only runs in the interop container.
"""
import http.cookiejar
import json
import sys
import urllib.request

base = sys.argv[1].rstrip("/")
password = sys.argv[2] if len(sys.argv) > 2 else "ci-root-password"
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def req(path, body=None, method=None):
    tok = next((c.value for c in jar if c.name in ("rdns_csrf", "__Host-rdns_csrf")), "")
    data = None if body is None else json.dumps(body).encode()
    r = urllib.request.Request(base + path, data=data, method=method, headers={
        "Content-Type": "application/json", "X-Requested-With": "rust-dns", "X-CSRF-Token": tok})
    with opener.open(r, timeout=5) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else None


req("/rust-dns/api/auth/login", {"username": "root", "password": password})
req("/rust-dns/api/zones/0.0.10.in-addr.arpa/records", {"name": "@", "type": "NS", "value": "ns1.example.test."})
# DNSViz queries a zone's name servers at their own addresses: ns1 of the
# signed zones is this server (127.0.0.1), not the fixture's 10.1.0.53.
req("/rust-dns/api/zones/rrtypes.test/records", {"name": "ns1", "type": "A", "value": "127.0.0.1"})
for zone in ("signed.test", "nsec3.test", "ed25519.test"):
    page = req(f"/rust-dns/api/zones/{zone}/records?q=ns1&limit=5000")
    for r in page["records"]:
        if r["name"] == "ns1" and r["type"] == "A":
            req(f"/rust-dns/api/zones/{zone}/records/{r['id']}", {"value": "127.0.0.1"}, "PUT")
print("completed the fixture for the zone checkers")
