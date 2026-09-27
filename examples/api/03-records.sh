#!/usr/bin/env bash
# Add one record of every supported type, then update, search and delete.
# Record names are relative to the zone: "@" is the apex, "www" is www.<zone>.
# Names inside values may be absolute ("mail.example.com") or end with a dot.
# "ttl" is optional; omit it (or send null) to use the zone default.
set -euo pipefail
source "$(dirname "$0")/_env.sh"
R="/zones/$ZONE/records"

echo "== A and AAAA (IPv4 / IPv6 address)"
api POST "$R" '{"name": "@",   "type": "A",    "value": "192.0.2.10"}'
api POST "$R" '{"name": "@",   "type": "AAAA", "value": "2001:db8::10"}'
api POST "$R" '{"name": "api", "type": "A",    "value": "192.0.2.11", "ttl": 60}'

echo "== CNAME (alias; must be the only record at its name)"
api POST "$R" '{"name": "www", "type": "CNAME", "value": "'"$ZONE"'"}'

echo "== NS (delegate a subdomain) with glue"
api POST "$R" '{"name": "lab",     "type": "NS", "value": "ns.lab.'"$ZONE"'"}'
api POST "$R" '{"name": "ns.lab",  "type": "A",  "value": "192.0.2.60"}'

echo "== MX (mail) and the mail host"
api POST "$R" '{"name": "@",    "type": "MX", "value": "10 mail.'"$ZONE"'"}'
api POST "$R" '{"name": "mail", "type": "A",  "value": "192.0.2.25"}'

echo "== TXT (SPF, DMARC, domain verification). Long text is split into 255-byte strings automatically."
api POST "$R" '{"name": "@",      "type": "TXT", "value": "v=spf1 mx -all"}'
api POST "$R" '{"name": "_dmarc", "type": "TXT", "value": "v=DMARC1; p=reject; rua=mailto:dmarc@'"$ZONE"'"}'

echo "== SRV (service location): priority weight port target"
api POST "$R" '{"name": "_sip._tcp", "type": "SRV", "value": "10 60 5060 sip.'"$ZONE"'"}'
api POST "$R" '{"name": "sip",       "type": "A",   "value": "192.0.2.30"}'

echo "== wildcard: anything.apps.$ZONE"
api POST "$R" '{"name": "*.apps", "type": "A", "value": "192.0.2.40"}'

echo "== CAA (which CAs may issue certificates)"
api POST "$R" '{"name": "@", "type": "CAA", "value": "0 issue \"letsencrypt.org\""}'

echo "== HTTPS (RFC 9460: tells browsers about HTTP/3 and address hints)"
api POST "$R" '{"name": "@", "type": "HTTPS", "value": "1 . alpn=h2,h3 ipv4hint=192.0.2.10"}'

echo "== SVCB (generic service binding)"
api POST "$R" '{"name": "_dns", "type": "SVCB", "value": "1 dns.'"$ZONE"'. alpn=dot port=853"}'

echo "== TLSA (DANE certificate pin for TCP/443 on www)"
api POST "$R" '{"name": "_443._tcp.www", "type": "TLSA", "value": "3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}'

echo "== SSHFP (SSH host key fingerprint)"
api POST "$R" '{"name": "mail", "type": "SSHFP", "value": "4 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}'

echo "== NAPTR (used by SIP / ENUM)"
api POST "$R" '{"name": "@", "type": "NAPTR", "value": "100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.'"$ZONE"'."}'

echo "== HINFO (host information)"
api POST "$R" '{"name": "mail", "type": "HINFO", "value": "\"x86_64\" \"Linux\""}'

echo "== DNAME (redirect a whole subtree: *.old.$ZONE -> *.$ZONE)"
api POST "$R" '{"name": "old", "type": "DNAME", "value": "'"$ZONE"'"}'

echo "== PTR in the IPv4 reverse zone: 192.0.2.25 -> mail.$ZONE"
api POST "/zones/2.0.192.in-addr.arpa/records" '{"name": "25", "type": "PTR", "value": "mail.'"$ZONE"'"}'

echo "== PTR in the IPv6 reverse zone: 2001:db8::10 -> $ZONE"
# The name is the address nibbles, reversed, relative to 8.b.d.0.1.0.0.2.ip6.arpa
api POST "/zones/8.b.d.0.1.0.0.2.ip6.arpa/records" \
  '{"name": "0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0", "type": "PTR", "value": "'"$ZONE"'"}'
# With [server].auto_ptr = true, PTR answers are also generated automatically
# from A/AAAA records, so explicit PTRs are only needed to override them.

echo "== internationalised name (stored as punycode xn--mnchen-3ya)"
api POST "$R" '{"name": "münchen", "type": "A", "value": "192.0.2.50"}'

echo "== expiring record (self-registration): stops answering after 24h unless renewed"
api POST "$R" '{"name": "laptop-42", "type": "A", "value": "192.0.2.42", "expires_in": 86400}'
echo "== renew: post the identical record with a new expiry (HTTP 200, same id)"
api POST "$R" '{"name": "laptop-42", "type": "A", "value": "192.0.2.42", "expires_in": 172800}'
echo "== make it permanent: clear the expiry"
id=$(api GET "$R?q=laptop-42" | python3 -c 'import json,sys; print(json.load(sys.stdin)["records"][0]["id"])')
api PUT "$R/$id" '{"expires_at": null}'

echo "== search records (server-side, paged)"
api GET "$R?q=mail&limit=20"

echo "== update: change the api address and TTL"
id=$(api GET "$R?q=api" | python3 -c 'import json,sys; print([r["id"] for r in json.load(sys.stdin)["records"] if r["name"]=="api" and r["type"]=="A"][0])')
api PUT "$R/$id" '{"value": "192.0.2.12", "ttl": 120}'

echo "== delete a record"
id=$(api GET "$R?q=hinfo" | python3 -c 'import json,sys; print(json.load(sys.stdin)["records"][0]["id"])')
api DELETE "$R/$id"

echo "== validation errors come back as 400/409 with a message, e.g.:"
api POST "$R" '{"name": "bad", "type": "A", "value": "not-an-ip"}' || true
api POST "$R" '{"name": "www", "type": "A", "value": "192.0.2.99"}' || true   # conflicts with the CNAME
