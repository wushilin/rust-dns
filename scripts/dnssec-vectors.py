#!/usr/bin/env python3
"""Regenerate the DNSSEC known-answer vectors pinned in src/dnssec/vectors.rs.

dnspython (with cryptography) signs RRsets, written the way rust-dns serves
them, with a fixed ECDSA P-256 key, and prints the canonical signed data and
the RRSIG RDATA; BIND's dnssec-dsfromkey computes the DS for the same key.
The Rust test checks its canonical form byte for byte against these and
verifies dnspython's signatures.

  pip install dnspython cryptography
  python3 scripts/dnssec-vectors.py [key.pk8]   # BIND tools on PATH or in /opt/homebrew/opt/bind/bin

The key file is created on first use; keep it to reproduce the vectors.
"""
import sys
import base64, subprocess, os
import dns.dnssec, dns.name, dns.rrset, dns.rdata, dns.rdataclass, dns.rdatatype, dns.rdtypes.ANY.DNSKEY
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

PK8_FILE = sys.argv[1] if len(sys.argv) > 1 else "dnssec-vectors-key.pk8"
if not os.path.exists(PK8_FILE):
    k = ec.generate_private_key(ec.SECP256R1())
    open(PK8_FILE, "wb").write(k.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
der = open(PK8_FILE, "rb").read()
priv = serialization.load_der_private_key(der, None)
origin = dns.name.from_text("example.net.")
dnskey = dns.dnssec.make_dnskey(priv.public_key(), dns.dnssec.Algorithm.ECDSAP256SHA256, flags=257)
tag = dns.dnssec.key_id(dnskey)
print("PKCS8", base64.b64encode(der).decode())
print("DNSKEY", dnskey.to_text())
print("TAG", tag)
for alg in ("SHA256", "SHA384"):
    print("DS", alg, dns.dnssec.make_ds(origin, dnskey, alg).to_text())
# BIND's view of the same key
open("Kexample.net.key", "w").write(f"example.net. 3600 IN DNSKEY {dnskey.to_text()}\n")
for a in ("-2", "-a SHA-384"):
    out = subprocess.run(f"$(command -v dnssec-dsfromkey || echo /opt/homebrew/opt/bind/bin/dnssec-dsfromkey) {a} Kexample.net.key", shell=True, capture_output=True, text=True).stdout.strip()
    print("BINDDS", out)

INCEPTION, EXPIRATION = 1790000000, 1791209600
cases = [
    ("www.example.net.", 300, "A", ["192.0.2.1", "192.0.2.2"]),
    ("example.net.", 3600, "MX", ["10 Mail.Example.NET."]),
    ("example.net.", 3600, "SOA", ["NS1.Example.net. Hostmaster.EXAMPLE.net. 7 3600 600 1209600 300"]),
    ("_sip._tcp.example.net.", 3600, "SRV", ["10 20 5060 Sip.Example.net."]),
    ("txt.example.net.", 3600, "TXT", ['"' + "a" * 255 + '" "' + "b" * 255 + '" "' + "c" * 90 + '"']),
    ("*.gate.example.net.", 1800, "A", ["192.0.2.3"]),
    ("old.example.net.", 3600, "DNAME", ["Other.Example.ORG."]),
    ("example.net.", 3600, "CAA", ['0 issue "letsencrypt.org"']),
    ("n.example.net.", 3600, "NAPTR", ['100 10 "S" "SIP+D2U" "" _Sip._udp.Example.net.']),
    ("example.net.", 300, "NSEC", ["a.example.net. A NS SOA MX TXT RRSIG NSEC DNSKEY"]),
    ("secure.example.net.", 3600, "DS", ["12345 13 2 " + "AB" * 32]),
    ("example.net.", 3600, "NS", ["NS1.example.net.", "ns2.EXAMPLE.net."]),
    ("alias.example.net.", 300, "CNAME", ["WWW.Example.NET."]),
]
for owner, ttl, t, values in cases:
    rrset = dns.rrset.from_text_list(owner, ttl, "IN", t, values)
    sig = dns.dnssec.sign(rrset, priv, origin, dnskey, inception=INCEPTION, expiration=EXPIRATION, origin=origin)
    data = dns.dnssec._make_rrsig_signature_data(rrset, sig, origin)
    dns.dnssec.validate_rrsig(rrset, sig, {origin: dns.rrset.from_rdata(origin, 3600, dnskey)}, now=INCEPTION + 10)
    print("CASE", owner, ttl, t, "|".join(values))
    print("  DATA", data.hex())
    print("  RRSIG", sig.to_wire().hex() if hasattr(sig, "to_wire") else sig.to_digestable().hex())
