#!/usr/bin/env python3
"""Seed rust-dns with bench.test (N A records) via the import API."""
import http.cookiejar, json, sys, time, urllib.request
base, n = sys.argv[1], int(sys.argv[2])
jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
def req(path, payload=None, write=False, method=None):
    h = {"Content-Type": "application/json"}
    if write:
        h["X-Requested-With"] = "rust-dns"
        h["X-CSRF-Token"] = next((c.value for c in jar if c.name.endswith("rdns_csrf")), "")
    r = urllib.request.Request(base + path, None if payload is None else json.dumps(payload).encode(), h, method=method)
    with op.open(r, timeout=30) as resp:
        d = resp.read(); return json.loads(d) if d else None
for _ in range(200):
    try: req("/rust-dns/api/health"); break
    except Exception: time.sleep(0.1)
req("/rust-dns/api/auth/login", {"username": "root", "password": "bench-root-password"})
zone = {"name": "bench.test", "soa_mname": "ns1.bench.test.", "soa_rname": "hostmaster.bench.test.",
        "refresh": 3600, "retry": 600, "expire": 1209600, "minimum": 300, "default_ttl": 300,
        "records": [{"name": "@", "type": "NS", "value": "ns1.bench.test."},
                    {"name": "ns1", "type": "A", "value": "10.0.0.53"}] +
                   [{"name": f"h{i}", "type": "A", "value": f"10.{i//65536%256}.{i//256%256}.{i%256}"} for i in range(n)]}
r = req("/rust-dns/api/import?mode=replace", {"version": 1, "exported_at": "2026-01-01T00:00:00Z", "zones": [zone]}, True)
print("seeded", r.get("records_added"))
