# Examples

Every file here is tested against a live server: the configs pass
`rust-dns --check`, and the API scripts run end to end, with the resulting
records queried over both UDP and TCP.

## Configs (`config/`)

| File | Use it for |
|---|---|
| `minimal.toml` | Trying rust-dns locally. DNS on 127.0.0.1:5300, console on http://127.0.0.1:8053. |
| `homelab.toml` | LAN DNS: authoritative for internal zones, forwarding for LAN clients only, query log with rotation. |
| `public-primary.toml` | Internet-facing primary for your own domains: no forwarding, AXFR + NOTIFY to a secondary, MFA for root, console behind TLS. |
| `behind-proxy.toml` | TCP DNS and console behind HAProxy or a load balancer using PROXY protocol v2. |

The `[root].password` in each file is plaintext on purpose. rust-dns replaces it
with an Argon2 hash the first time it starts, rewriting the file, so start
from a copy:

```
cp examples/config/minimal.toml rust-dns.toml
rust-dns --check --config rust-dns.toml
rust-dns --config rust-dns.toml
```

`proxy/nginx.conf` and `proxy/haproxy.cfg` are the proxy side of
`public-primary.toml` and `behind-proxy.toml`. They are templates: replace the
host names, addresses and certificate paths.

## API scripts (`api/`)

Run them in order against a test instance. They need `curl` and `python3`.

```
export RDNS_URL=http://127.0.0.1:8053
export RDNS_TOKEN=$(RDNS_PASSWORD=change-me-please examples/api/01-token.sh)
examples/api/02-zones.sh
examples/api/03-records.sh
examples/api/04-access.sh
examples/api/05-import-export.sh
examples/api/06-operations.sh
examples/api/99-cleanup.sh        # removes everything the scripts created
```

| Script | Shows |
|---|---|
| `01-token.sh` | Sign in (with TOTP if enabled) and create an API token. |
| `02-zones.sh` | Create a forward zone and IPv4 / IPv6 reverse zones, list, update SOA timers. |
| `03-records.sh` | One record of every type: A, AAAA, CNAME, NS, MX, TXT, SRV, wildcard, CAA, HTTPS, SVCB, TLSA, SSHFP, NAPTR, HINFO, DNAME, PTR (v4 and v6), an internationalised name. Then search, update, delete, and two validation errors. |
| `04-access.sh` | Users, editor / viewer access per zone, ownership transfer, sign-out, disable. |
| `05-import-export.sh` | Export one zone or every zone as JSON; import a JSON document. |
| `06-operations.sh` | Health, status, change log, metrics, config reload, integrity check. |

Set `ZONE=yourzone.example` to use a zone name other than `example.com`.

## Record API in one page

All record types use the same endpoints. `name` is relative to the zone
(`@` is the apex). `ttl` is optional.

```
# add
curl -H "Authorization: Bearer $RDNS_TOKEN" -H "Content-Type: application/json" \
     -d '{"name":"www","type":"A","value":"192.0.2.10","ttl":300}' \
     $RDNS_URL/rust-dns/api/zones/example.com/records

# list / search (paged)
curl -H "Authorization: Bearer $RDNS_TOKEN" "$RDNS_URL/rust-dns/api/zones/example.com/records?q=www&limit=100"

# update (send only the fields you change)
curl -X PUT -H "Authorization: Bearer $RDNS_TOKEN" -H "Content-Type: application/json" \
     -d '{"value":"192.0.2.11"}' $RDNS_URL/rust-dns/api/zones/example.com/records/<id>

# delete
curl -X DELETE -H "Authorization: Bearer $RDNS_TOKEN" $RDNS_URL/rust-dns/api/zones/example.com/records/<id>
```

| Type | `value` example |
|---|---|
| A | `192.0.2.10` |
| AAAA | `2001:db8::10` |
| CNAME | `target.example.com` |
| PTR | `host.example.com` (record name is the reversed address inside a reverse zone) |
| NS | `ns1.example.com` |
| MX | `10 mail.example.com` |
| TXT | `v=spf1 mx -all` (no quotes needed; long values are split automatically) |
| SRV | `10 60 5060 sip.example.com` (priority weight port target) |
| CAA | `0 issue "letsencrypt.org"` |
| HTTPS | `1 . alpn=h2,h3 ipv4hint=192.0.2.10` |
| SVCB | `1 dns.example.com. alpn=dot port=853` |
| TLSA | `3 1 1 <sha256 hex>` |
| SSHFP | `4 2 <sha256 hex>` |
| NAPTR | `100 10 "S" "SIP+D2U" "" _sip._udp.example.com.` |
| HINFO | `"x86_64" "Linux"` |
| DNAME | `other.example.com` |

Expiring records (for self-registration): add `"expires_in": 86400` (seconds)
or `"expires_at": "2026-10-01T00:00:00Z"` when creating. The record stops
answering at that time, stays visible as expired, and is deleted after
`[expiry].retention_days` (default 30). Posting the identical record again with
a new expiry renews it (HTTP 200, same id); `{"expires_at": null}` on update
makes it permanent.

Notes:
- A CNAME must be the only record at its name, and cannot be at the apex.
- With `[server].auto_ptr = true` (the default), reverse lookups are answered
  from A / AAAA records automatically. Add PTR records only to override that.
- An NS record below the apex delegates that subdomain: queries under it get a
  referral (NS in the authority section), not an answer.
- API tokens need no CSRF header. Browser sessions must send
  `X-Requested-With: rust-dns` on writes.
- The full API reference is served at `/rust-dns/api/openapi.json`.
