#!/usr/bin/env python3
"""Seed the extra conformance zones, after scripts/seed-conformance.py.

  python3 scripts/seed-conformance-extra.py <web-console-url> [root-password]

An override zone under signed.test (CONFORMANCE_OVERRIDE), rrtypes.test
with the record types hickory's text parser lacks, signed (O28), and two
copies of signed.test: nsec3.test signed with NSEC3 (O24) and ed25519.test
signed with an Ed25519 key (O25). Used by conformance-local.sh and
interop-local.sh, so both check the same data.
"""
import http.cookiejar, json, sys, urllib.request
base = sys.argv[1]
jar = http.cookiejar.CookieJar()
o = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
def req(path, body):
    tok = next((c.value for c in jar if c.name in ("rdns_csrf", "__Host-rdns_csrf")), "")
    r = urllib.request.Request(base + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", "X-Requested-With": "rust-dns", "X-CSRF-Token": tok})
    o.open(r, timeout=5).read()
req("/rust-dns/api/auth/login", {"username": "root", "password": sys.argv[2] if len(sys.argv) > 2 else "ci-root-password"})
req("/rust-dns/api/zones", {"name": "vpn.signed.test", "override": {"mode": "static"}})
# O28: records of the types hickory's text parser lacks, in a signed zone.
req("/rust-dns/api/zones", {"name": "rrtypes.test"})
for name, t, v in [("loc", "LOC", "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m"),
                   ("rp", "RP", "admin.rrtypes.test. info.rrtypes.test."),
                   ("afs", "AFSDB", "1 afs.rrtypes.test."),
                   ("_http._tcp", "URI", '10 1 "https://example.com/"'),
                   ("spf", "SPF", '"v=spf1 -all"'),
                   ("mac", "EUI48", "00-00-5e-00-53-2a"),
                   ("mac", "EUI64", "00-00-5e-ef-10-00-00-2a")]:
    req("/rust-dns/api/zones/rrtypes.test/records", {"name": name, "type": t, "value": v})
r = urllib.request.Request(base + "/rust-dns/api/zones/rrtypes.test/dnssec", data=json.dumps({"enabled": True}).encode(), method="PUT",
    headers={"Content-Type": "application/json", "X-Requested-With": "rust-dns", "X-CSRF-Token": next((c.value for c in jar if c.name in ("rdns_csrf", "__Host-rdns_csrf")), "")})
o.open(r, timeout=5).read()
req("/rust-dns/api/zones/vpn.signed.test/records", {"name": "gw", "type": "A", "value": "10.8.0.1"})
# O24: a copy of signed.test signed with NSEC3 (CONFORMANCE_NSEC3).
r = o.open(urllib.request.Request(base + "/rust-dns/api/zones/signed.test/export"), timeout=5).read()
doc = json.loads(r)
z = doc["zones"][0]
z["name"] = "nsec3.test"
for k in ("soa_mname", "soa_rname"):
    z[k] = z[k].replace("signed.test", "nsec3.test")
for rec in z["records"]:
    rec["value"] = rec["value"].replace("signed.test", "nsec3.test")
    rec.pop("id", None)
req("/rust-dns/api/import?mode=merge", doc)
r = urllib.request.Request(base + "/rust-dns/api/zones/nsec3.test/dnssec", data=json.dumps({"enabled": True, "denial": "nsec3"}).encode(), method="PUT",
    headers={"Content-Type": "application/json", "X-Requested-With": "rust-dns", "X-CSRF-Token": next((c.value for c in jar if c.name in ("rdns_csrf", "__Host-rdns_csrf")), "")})
st = json.loads(o.open(r, timeout=5).read())
assert st["state"] == "signing" and st["denial"] == "nsec3", st
# O25: another copy signed with an Ed25519 key (CONFORMANCE_ED25519).
z["name"] = "ed25519.test"
for k in ("soa_mname", "soa_rname"):
    z[k] = z[k].replace("nsec3.test", "ed25519.test")
for rec in z["records"]:
    rec["value"] = rec["value"].replace("nsec3.test", "ed25519.test")
req("/rust-dns/api/import?mode=merge", doc)
r = urllib.request.Request(base + "/rust-dns/api/zones/ed25519.test/dnssec", data=json.dumps({"enabled": True, "algorithm": 15}).encode(), method="PUT",
    headers={"Content-Type": "application/json", "X-Requested-With": "rust-dns", "X-CSRF-Token": next((c.value for c in jar if c.name in ("rdns_csrf", "__Host-rdns_csrf")), "")})
st = json.loads(o.open(r, timeout=5).read())
assert st["state"] == "signing" and st["key"]["algorithm"] == 15, st
print("seeded the extra conformance zones")
