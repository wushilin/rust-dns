# rust-dns

A lightweight, SQLite-backed authoritative DNS server with a realtime web
console, a token-secured REST API, and a WAL-style changelog. Built to be the
primary nameserver for your own domains, or the DNS for a homelab, without the
last-century feel.

Single static binary, one SQLite file, one TOML config. Zero JavaScript build.

## Features

**DNS**
- Authoritative for any number of zones, including `.` as a private root.
- A, AAAA, CNAME, PTR, NS, MX, TXT, SRV, CAA, HTTPS/SVCB, TLSA, SSHFP, NAPTR,
  HINFO, DNAME and DS. SOA and apex NS are synthesized from zone settings when
  not set explicitly.
- DNSSEC online signing per zone (off by default): ECDSA P-256 (or
  Ed25519) combined signing key, NSEC or NSEC3 denial, signatures renewed automatically, DS records for
  the registrar and a pre-publication check in the console (see
  [DNSSEC](#dnssec)).
- CNAME chasing, RFC 4592 wildcards, delegations with glue, RFC 2308 negative
  answers, empty non-terminals, RFC 8482 minimal ANY, EDNS with BADVERS,
  truncation with TCP fallback, CHAOS `version.bind`.
- Automatic PTR answers synthesized from A/AAAA records (no separate reverse
  zone maintenance; not inside DNSSEC-signed zones).
- UDP and TCP on any set of bind addresses and any port, IPv4 and IPv6.
- Optional forwarding of foreign names to upstream resolvers, restricted to an
  allow-list of client networks so you never become an open resolver.
- dnsmasq-style resolver features, set from the console (see
  [Resolver features](#resolver-features)): override zones (local names and
  conditional forwarding), domain-needed, bogus-priv, rebinding protection,
  serve-stale, upstream strategies with health, blocklists, filtered record
  types, EDNS Client Subnet, hosts-file import and following interfaces.
- Per-client rate limiting (N queries per second per IPv4 address or IPv6 /64)
  in a fixed-size counter table: memory is bounded and a flood from many
  (spoofed) sources cannot reset a limited client. Every Nth limited UDP query
  gets an empty truncated answer ("slip") so real clients can retry over TCP.
- DNS over TCP with per-read and per-write timeouts, per-connection query and
  age limits, and a per-client connection cap.
- PROXY protocol v1/v2 for DNS-over-TCP behind HAProxy or a cloud NLB.
- DNS Cookies (RFC 7873), EDNS NSID, outbound AXFR and NOTIFY for secondaries (TSIG-authenticated, RFC 8945),
  plus IDN zone and record names.
- Config reload on SIGHUP or `POST /api/admin/reload`; listener, database, log
  target, and PROXY listener settings require a restart.

**Console and API**
- Realtime web console over a websocket: record edits by other users, and
  every query the server answers, appear live.
- Users with password + optional TOTP (Google Authenticator, 1Password, etc.).
  MFA can be required per user; enrollment is forced at the next sign-in.
- Root user from the config file (plaintext password hashed in place with
  Argon2id on first start). Admins manage users; each zone has an owner who
  grants `editor` or `viewer` access to other users.
- Per-user API tokens for scripts and automation.
- JSON export/import of everything (transactional). BIND zone-file import and
  export were removed.
- Server side search and paging for large zones, and an
  OpenAPI 3.1 document at `/api/openapi.json`, generated from the code (see
  [API documentation](#api-documentation)).
- Recovery codes for MFA, session lists and revocation, and an admin action to
  sign a user out everywhere. Cookie-authenticated writes require
  `X-Requested-With: rust-dns` as the CSRF check.
- Changelog with monotonic offsets (resume with `after=<offset>`, like a WAL),
  pruned by a retention window. The websocket resumes from an offset too.
  Every committed change is logged in the same transaction; rolled-back
  operations never appear. Each payload is the exact fact, so the log can be
  replayed to rebuild identical data.
- Audit log of account and security changes (sign-ins, users, MFA, recovery
  codes, sessions, API tokens), with the same transactional guarantee.
- One permission table drives both enforcement and the "effective rights" view
  (zone permissions by role; account permissions that need an administrator or
  a browser session). API tokens act as their owner; click a token's owner in
  the console to see exactly what it can do.
- Optional per-record expiry (`expires_in` / `expires_at`) for self-registration:
  records stop answering at expiry (changelog entry, serial bump, NOTIFY) and
  are deleted after a retention period (default 30 days). Re-posting the same
  record with a new expiry renews it.
- Real client IP behind proxies: PROXY protocol, then `X-Forwarded-For`, then
  `X-Real-IP`, then the socket address, honoured only from the proxies listed
  in `proxy_trust` (nothing is trusted by default).
- Prometheus metrics at `/metrics`, structured logs (text or JSON).
- Standby (follow) mode: a second server mirrors zones, records, users,
  MFA, API tokens, settings and TSIG keys over HTTPS, answers DNS while the
  primary is down, and is promoted by hand (see
  [Standby / follow mode](#standby--follow-mode)).

## Quick start

```
cargo build --release
./target/release/rust-dns --init-config rust-dns.toml   # mode 0600, random root password printed once
./target/release/rust-dns --config rust-dns.toml
```

(Starting without a config file also creates one with a random password; it is
printed once on stderr and never logged.)

Open http://127.0.0.1:8053, sign in as `root`, create a zone, add records:

```
dig @127.0.0.1 www.example.com
```

Port 53 needs privileges on Linux: see `deploy/` for a systemd unit that grants
`CAP_NET_BIND_SERVICE`, and a Dockerfile.

## Configuration

`rust-dns --print-sample-config` prints the annotated default. The important
parts:

```toml
[server]
bind = ["::"]                 # "::" also serves IPv4 on Linux/macOS
port = 53
udp = true
tcp = true
auto_ptr = true
default_primary_ns = "ns1.example.com"     # SOA MNAME for new zones
default_hostmaster = "hostmaster@example.com"

[forwarding]
upstreams = ["1.1.1.1:53"]    # empty = foreign names are REFUSED
allowed_clients = ["10.0.0.0/8", "192.168.0.0/16", "fc00::/7"]
cache_entries = 10000
cache_max_ttl = 86400         # cap on how long an answer is cached (never raises TTLs)
cache_negative_max_ttl = 3600 # cap for NXDOMAIN / no-data answers
open_resolver = false         # true = deliberate open resolver; see "Running an open resolver"
open_resolver_max_udp_payload = 512  # open resolver: bigger forwarded UDP answers are sent TC=1
open_resolver_rate_per_second = 20   # open resolver: forwarded queries/s per client; 0 = no extra limit
max_inflight = 1024           # forwarded queries waiting for an upstream at once (over it: UDP dropped, TCP SERVFAIL)

[rate_limit]
max_resolutions_per_second_per_address = 500   # per IPv4 address / IPv6 /64
max_tracked_addresses = 10000                  # fixed table size
slip = 2                      # every 2nd limited UDP query gets an empty TC=1 answer; 0 = drop

[tcp_dns]                     # PROXY protocol for DNS over TCP (UDP has none)
proxy_on = false
proxy_version = 2             # 1 or 2
proxy_trust = "10.0.0.10/32"  # the proxy's own address; required with proxy_on

[web_console]
bind = "127.0.0.1:8053"
proxy_on = false              # PROXY protocol on the console listener
proxy_version = 2
proxy_trust = ""              # proxies whose PROXY header / X-Forwarded-* are believed; empty = none
secure_cookies = false        # force Secure cookies (automatic when a trusted proxy says HTTPS)
login_attempts_per_minute = 10
login_backoff_after = 5       # failed attempts per account and network before waits start
token_creation_requires_session = false  # true: API tokens only from a signed-in browser session
request_header_timeout_secs = 60
max_connections = 512

[backup]
dir = "backups"                # empty disables scheduled online backups
interval_hours = 24
keep = 7

[root]
username = "root"
password = "..."              # plaintext is replaced by an Argon2 hash at start; "change-me" and "" are refused
mfa_required = false

[changelog]
retention_days = 30
account_retention_days = 3   # payloads of account/settings/TSIG changes (secrets) are scrubbed after this

[logging]
format = "text"               # or "json"
level = "info"
log_queries = false
file = ""                    # empty = stdout
max_size_mb = 50
max_files = 10
compress = true              # gzip rotated files
```

Put the console behind a TLS reverse proxy for anything beyond localhost
(`examples/proxy/nginx.conf`, `examples/proxy/haproxy.cfg`). The live console
(sidebar shows "live", changelog and live queries update without reloading)
needs the proxy to pass the websocket at `/api/ws` (`Upgrade` / `Connection`
headers, long read timeout). To check a proxy: open the console through it,
change a record in a second tab, and the first tab's changelog shows the new
row at once; or `curl -i -N -H 'Connection: Upgrade' -H 'Upgrade: websocket'
-H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGVzdHRlc3R0ZXN0dGVzdA=='
-H 'Origin: https://<console host>' -b '<session cookie>' https://<console host>/api/ws`
answers `101 Switching Protocols` (a `400`/`426` or a closed connection means
the proxy dropped the upgrade).
`rust-dns --check --config rust-dns.toml` parses and validates a config without
starting listeners or changing the file.
Scheduled backups use SQLite's online backup API; the configured number of
timestamped database snapshots is retained.

## Security

Before exposing rust-dns to the internet, note:

- **No default password.** `--init-config` (and a first start without a
  config) generates a random root password, stores only its Argon2 hash and
  writes the file with mode 0600. `--check` and startup refuse an empty root
  password and the sample's `change-me` placeholder. Files the server creates
  (config rewrites, database, backups, logs) are owner-only (umask 0077); the
  systemd units add `UMask=0077` and the usual sandboxing.
- **Proxy trust is explicit.** `X-Forwarded-For`, `X-Real-IP`,
  `X-Forwarded-Proto` and PROXY protocol headers are believed only from the
  addresses in `proxy_trust`; an empty list trusts nobody (earlier versions
  trusted every private address when it was empty). `proxy_on = true` without
  `proxy_trust` is a configuration error. Name the proxy itself (e.g.
  `127.0.0.1/32`), not a whole network: a startup warning flags entries wider
  than /24 (IPv4) or /64 (IPv6), since every host on such a network (for
  example all containers on a Docker bridge) could claim any client address.
- **Cookies.** Over plain HTTP the session cookie is `rdns_session`
  (HttpOnly, SameSite=Lax), so LAN use keeps working. When a trusted proxy
  sends `X-Forwarded-Proto: https`, or `secure_cookies = true`, it is
  `__Host-rdns_session` with `Secure`. Existing `rdns_session` sessions keep
  working until they expire. Cookie-authenticated writes need the session's
  CSRF token in `X-CSRF-Token` as well as `X-Requested-With: rust-dns`
  (the console sends both; the token comes with the sign-in response,
  `GET /api/auth/session` and the `rdns_csrf` cookie). Scripts that sign in
  with a cookie must send it, or set `[web_console] csrf_token_required =
  false`; API-token scripts are unaffected. Send HSTS at the TLS proxy (rust-dns adds
  `Strict-Transport-Security` itself only on requests a trusted proxy marks
  as HTTPS).
- **Sign-in protection.** Per client (IPv4 address / IPv6 /64) request
  limits; per account and network, exponential waits after
  `login_backoff_after` failures (up to 15 minutes); per account from all
  networks, waits capped at one minute (a distributed attack is slowed, the
  owner is never locked out for long); these counters are stored (local
  table `login_failures`), so a restart does not reset them; 5 wrong
  codes end an MFA-pending or signed-in session. Failed passwords and
  codes are audited (`login.failure`, `mfa.failure`; never the secret);
  the console's Audit log -> Sign-in log (`GET /api/audit/sign-ins`) lists
  sign-ins, failures, second factors and sign-outs, filtered by user,
  address and result.
- **Administrator MFA enrollment.** Users -> Edit -> "Set up MFA for this
  user" (`POST /api/users/{id}/mfa/enroll`) generates the user's
  authenticator and shows its QR code, `otpauth://` link and secret once,
  for delivery out of band (MFA becomes required, recovery codes are
  removed, the user is signed out). The secret replicates like any
  enrollment; it is never logged or audited. Users -> Account security ->
  "Only administrators enroll authenticators" (console setting
  `security`, `mfa_enrollment = "admin"`) refuses enrollment at sign-in
  and from the account page, so someone who only knows a password cannot
  enroll their own authenticator. Root is exempt.
- **Password policy and lockout** (Users -> Account security, same
  setting): minimum length (default 8), character classes, a history of
  previous passwords that may not be reused (stored with the user and
  replicated; set it only once every standby runs this version), and an
  optional account lockout after N failed attempts from anywhere (off by
  default: anyone who knows a user name could lock that user out; an
  administrator's password reset or re-enabling the account lifts it).
  The policy applies to new passwords; root (config file) is exempt. TOTP codes are single-use (the last accepted time step
  is stored). Replacing an enrolled authenticator needs the current code or
  password. Changing your password signs out your other sessions; API tokens
  keep working unless you tick "Also revoke my API tokens" (`revoke_tokens`;
  an administrator's password reset has the same option). With
  `token_creation_requires_session = true` API tokens can only be created
  from a signed-in browser session, so a leaked token cannot mint more. Argon2 runs on a small bounded
  worker pool; when it is saturated sign-ins get 503 with `Retry-After`
  instead of slowing DNS.
- **Websocket.** Streams close (1008) at once when their session or token
  is revoked or the account is disabled or deleted (a local signal on the
  event bus, also on a standby when it applies such a change), and
  re-check the session/token and zone rights every 10 seconds and on
  membership changes as a backstop. Cookie
  upgrades must come from the same origin. Scripts pass the token as the
  subprotocol `rust-dns.bearer.<token>`; `?token=` still works but is
  deprecated (URLs end up in proxy logs).
- **Forwarding.** Upstream queries use a fresh random ID and 0x20 case
  randomisation; replies must match ID, QR, opcode and question exactly.
  Forwarded answers are truncated to the client's UDP size. ACLs that would
  make an open resolver (a /0, or anything shorter than /8 IPv4 or /16 global
  IPv6, or entries covering more than 1/16 of IPv4 together) are refused in
  the config file and the console, unless open resolver mode is turned on on
  purpose (see [Running an open resolver](#running-an-open-resolver)).
- **Web listener.** Request headers must arrive within
  `request_header_timeout_secs`, at most `max_connections` connections are
  served, and pages are served with a strict Content-Security-Policy (scripts
  by hash, no inline handlers, `object-src 'none'`, `frame-ancestors 'self'`).
- **TSIG is unaffected** by these changes.
- **BIND zone-file import and export were removed** (the parser followed
  `$INCLUDE` to files on the server). JSON import/export remains.

## Console productivity

- **Search** (Zones page, `GET /api/search?q=&type=&zone=`): records in
  every zone you may view whose name, type or value contains the text; a
  hit opens its zone and highlights the record.
- **Bulk edit** (zone page): "Paste records" takes one record per line
  (`name [ttl] type value`), previews the result (nothing is written) and
  applies it as one change; row checkboxes and "Delete selected" delete
  several records at once (`POST /api/zones/{zone}/records/bulk`).
- **Clone and rename** (zone page, administrators): a copy with the same
  settings and records, or a new name for the zone (a signed zone only
  once the parent publishes no DS for it; only while every standby runs a
  version that can follow a rename).
- **Sorting and shortcuts**: click a column header to sort the records;
  `/` search, `n` add record, `p` paste records, `g z` zones, `?` help.

## Resolver features

Queries run through a pipeline of filters (`src/dns/pipeline.rs`, order and
contract in its module docs): EDNS and request checks, special queries,
transfers, own zones, override zones, the forwarding ACL, then the resolver
filters below and the forwarder. Every filter is counted in `/metrics`
(`rustdns_filter_queries_total{filter,outcome}`) and `/api/status`
(`pipeline`); the live query view shows which filter answered. Settings are
console settings (Server settings -> Resolver, and the Blocklists page),
replicated to standbys, applied without a restart.

- **Override zones**: a zone created with type *override* is not
  authoritative. It answers only clients allowed to use forwarding, never
  sets AA or AD, is never signed, transferred or announced by NOTIFY. Names
  and types it defines are answered from it; everything else under it goes
  to its own upstreams (*transparent*, the default) or gets NXDOMAIN
  (*static*, for blocking). With no records it is conditional forwarding
  (dnsmasq `server=/example.com/10.8.0.1`). The longest zone wins between
  own and override zones. Under a DNSSEC-signed parent the parent's data and
  signatures do not change, but a validating resolver asking through this
  server sees the parent deny the override names: use override zones under
  a signed parent only for clients that do not validate them.
- **domain-needed** (on by default): single-label names (`wpad`, `printer`)
  are never forwarded; NXDOMAIN unless an own or override zone has them.
- **bogus-priv** (on by default): reverse lookups for private and special
  ranges (RFC 6303) are never forwarded; NXDOMAIN unless an own reverse zone
  or automatic PTR covers the address.
- **Rebinding protection** (off by default): forwarded answers with private,
  loopback, link-local, CGNAT, ULA, `0.0.0.0` or `::` addresses are refused,
  except for allowlisted domains; the console lists recently refused names.
- **Serve stale** (RFC 8767, off by default): when every upstream fails, an
  expired cached answer (up to `max_stale_age_secs`) is returned with TTL 30.
- **Upstream strategy**: `in_order` (default, as before), `fastest`, or
  `parallel`; per-upstream latency, failures and a down state (3 failures in a
  row, probed again every 30 s) on the Server settings page.
- **Blocklists**: hosts files, plain domain lists and Adblock `||domain^`
  lists, downloaded by each server (the URLs replicate, the downloads do
  not), matched by suffix, with an allowlist and NXDOMAIN or null-address
  answers; forwarded queries only. About 8 bytes of memory per entry.
- **Filtered types** (`filter-AAAA`): listed types get NODATA, never forwarded.
- **EDNS Client Subnet** (off by default): the client's subnet (/24, /56 by
  default; not for private clients unless chosen) is sent upstream and
  answers are cached per subnet.
- **Hosts-file import**: Import / Export -> Hosts file, or
  `POST /api/zones/{zone}/import/hosts` (preview, then one transaction).
- **Following interfaces**: `[server] interfaces = ["eth0"]` listens on that
  interface's addresses and follows them as they change (on Linux at once,
  through netlink; elsewhere, or if netlink is unavailable, polled every
  `interface_poll_secs`); per server, not replicated.

## Running an open resolver

By default rust-dns refuses to become an open resolver: forwarding is limited
to `allowed_clients`, and a list that covers the internet (see *Forwarding*
above) is rejected. If you really want a public recursive resolver, turn on
**open resolver mode** explicitly, either in the config file:

```toml
[forwarding]
upstreams = ["1.1.1.1:53", "[2606:4700:4700::1111]:53"]
open_resolver = true
allowed_clients = ["0.0.0.0/0", "::/0"]   # list them: an empty list still means nobody
open_resolver_max_udp_payload = 512      # optional (512 to 4096)
open_resolver_rate_per_second = 20       # optional; 0 = only [rate_limit] applies
```

or in the console (*Server settings -> Forwarding -> Turn on open resolver
mode*, a two-step confirmation that can also set the allowed clients to
`0.0.0.0/0` and `::/0`), or with the API (`PUT /api/settings/forwarding` with
`"open_resolver": true`). The mode only lifts the guard on `allowed_clients`;
it does not add anything to the list. A console/API setting overrides the
file like the other forwarding settings (and always records the mode it was
saved with, so editing the file later cannot silently drop the safeguards).
Turning it on or off is recorded in the audit log
(`settings.forwarding.update`, before/after) and is replicated to standbys.

**Risks.** An open resolver answers anyone. Expect:

- **Reflection and amplification:** attackers send small queries with a
  victim's spoofed source address; the (larger) answers flood the victim.
  Your server becomes part of the attack and your bandwidth pays for it.
- **Abuse reports and blocklists:** internet-wide scanners (Shadowserver,
  the Open Resolver Project and others) find open resolvers within hours and
  report them to your network's abuse contact.
- **Cloud provider notices:** many providers forbid open resolvers in their
  acceptable-use policy, send abuse tickets, throttle UDP/53 or suspend the
  instance.
- **Upstream limits:** the upstream resolvers see all of your users' traffic
  as yours; public resolvers rate-limit or block heavy sources, which then
  hurts your own lookups too.
- Cache poisoning attempts and resource exhaustion from anyone on the
  internet (the forwarding cache and upstream sockets are shared).

**Safeguards** (only while open resolver mode is in effect; otherwise
nothing changes):

- **UDP size cap.** Forwarded answers larger than
  `open_resolver_max_udp_payload` (default 512 bytes) are sent over UDP
  truncated (TC=1, answer sections emptied), whatever EDNS size the client
  offers. Real clients retry over TCP, which cannot be spoofed; a reflected
  answer is never much larger than the query. This removes most of the
  amplification.
- **No forwarded ANY.** `ANY` queries for names this server is not
  authoritative for are not forwarded. They get the RFC 8482 minimal answer
  (a synthesized `HINFO "RFC8482" ""`, TTL 3789), as authoritative names
  already do with `minimal_any`. Chosen over REFUSED/NOTIMP because it is
  what RFC 8482 §4.2 prescribes (and what large public resolvers answer), it
  is just as small, and RFC 8482-aware clients treat it as a normal answer
  rather than a server failure. ANY is the classic amplification query.
- **Per-client forwarding limit.** `open_resolver_rate_per_second` (default
  20) forwarded queries (upstream or cache) per second per client (IPv4
  address / IPv6 /64), on top of the global `[rate_limit]`. It uses the same
  flood-proof count-min limiter and `slip`: over the limit, UDP queries are
  dropped (every `slip`-th gets an empty TC=1 answer), TCP gets REFUSED.
  Authoritative answers are not affected.
- **DNS cookies** (RFC 7873, `[server].cookies`, on by default) stay on.
- **Loud.** A WARN log line at startup, on every reload (SIGHUP or
  `POST /api/admin/reload`) and when the mode changes; `--check` prints a
  `WARNING:` line; the gauge `rustdns_open_resolver` is 1;
  `/api/status` has `forwarding.open_resolver: true` and the counters
  `dns.open_resolver_truncated`, `dns.open_resolver_any` and
  `dns.open_resolver_rate_limited` (also in `/metrics` as
  `rustdns_open_resolver_*_total`); the console shows an *Open resolver*
  badge on the dashboard and on Server settings.

Consider also a lower `[rate_limit].max_resolutions_per_second_per_address`,
monitoring the counters above and your provider's abuse mailbox, and, where
possible, restricting UDP/53 to known networks at the firewall instead.

## DNSSEC

Signing is **off by default** and turned on per zone (console: zone page ->
**DNSSEC**, or `PUT /api/zones/{zone}/dnssec`). With signing off nothing
changes; the only protocol difference in this version for every zone is that
the DO bit of a query is now copied into the response (RFC 3225).

**What is signed.** One combined signing key per zone (flags 257, SEP,
algorithm 13 = ECDSA P-256 / SHA-256 by default, or 15 = Ed25519, see
**Ed25519** below), generated on this server the first time signing is
turned on. Denial of existence is NSEC by default, or NSEC3 per
zone (see **NSEC3** below). Every
authoritative RRset is signed: SOA, apex NS, DNSKEY, every record set and
every NSEC; a DS RRset at a delegation point is signed (DS records can be
added in the record editor); the NS RRset at a delegation and glue below it
are not. Names below a DNAME are occluded (the DNAME answers for them) and
not signed. The NSEC chain links every authoritative name in canonical order
(wildcard owners such as `*.gate.example.net.` included; empty non-terminals
have no NSEC of their own, the previous NSEC's next name proves them).
Expired records are not served, so they are not in the chain either.

**Answers.** Only a query with the DO bit gets DNSSEC records: RRSIGs for
answer and authority RRsets; NXDOMAIN with the SOA, an NSEC covering the name
and one covering the wildcard at the closest encloser; NODATA with the NSEC at
the name (or the covering NSEC of an empty non-terminal); wildcard answers
with the wildcard's RRSIG (its labels field marks the expansion) and the NSEC
proving the next closer name does not exist; wildcard NODATA with both;
referrals with the signed DS or the NSEC proving there is none; DS queries at
a cut answered authoritatively from the parent side (RFC 4035 3.1.4.1).
DNAME is signed, the synthesized CNAME is not (RFC 6672). `ANY` with DO on a
signed zone returns one real RRset with its RRSIG instead of the synthesized
HINFO (which could not be validated). Queries without DO get the same answers
as for an unsigned zone. A UDP answer that does not fit first loses its
additional section, then is truncated (TC, nothing partial); TCP answers are
complete. Zone transfers of a signed zone carry the DNSKEY, every RRSIG and
NSEC (TSIG-signed as usual). **Automatic PTR answers are not synthesized in a
signed zone** (they could not be signed); auto-PTR for names outside any zone
is unchanged.

**NSEC3.** Per zone, `denial: "nsec3"` (console: DNSSEC tab -> **Switch to
NSEC3**, or when turning signing on; API: `PUT /api/zones/{zone}/dnssec` with
`{"enabled": true, "denial": "nsec3"}`; `"nsec"` switches back) signs the zone
with NSEC3 (RFC 5155) using the RFC 9276 parameters: hash SHA-1, no extra
iterations, no salt, no opt-out (flags 0), and an `NSEC3PARAM 1 0 0 -` at the
apex. Every authoritative name, every delegation point and every empty
non-terminal has an NSEC3 (owner `<base32hex hash>.<zone>`, TTL as the NSEC
records: min(SOA minimum, zone TTL)); names below a cut or a DNAME have none.
Answers carry the RFC 5155 section 7.2 proofs: NXDOMAIN with the closest
encloser proof (the NSEC3 matching the closest encloser, the one covering the
next closer name) and the NSEC3 covering the wildcard at the closest
encloser; NODATA (and empty non-terminals, and DS queries at a cut without
DS) with the matching NSEC3; wildcard answers with the NSEC3 covering the next
closer name; wildcard NODATA with all three. A query for an NSEC3 owner name
is NXDOMAIN (section 7.2.8); an NSEC query is NODATA. Zone transfers carry the
NSEC3PARAM, every NSEC3 and their RRSIGs instead of the NSEC records.
Switching between NSEC and NSEC3 is one atomic re-sign with the **same key**
(a serial bump): no DS change at the registrar, and every answer validates
before, during and after it (both chains are signed by the DNSKEY the DS
points to; algorithm 13 is defined for both, the NSEC3-only algorithm numbers
of RFC 5155 section 2 concern RSA/SHA-1 aliases 6 and 7). A resolver that
cached an NSEC proof keeps a valid proof until it expires. Standbys sign with
NSEC3 too (their own signatures; the NSEC3 records are identical). Choosing
NSEC3 is refused (409) while a standby of an older version follows (it would
sign the zone with NSEC); upgrade standbys first. NSEC3 hides names from
casual zone walking but not from an offline dictionary attack on the hashes
(RFC 9276); it is not a secrecy feature.

**Ed25519.** The algorithm is chosen for a **new key**: the first time
signing is turned on, or when it is turned on again with a new key
(console: the "Algorithm of a new key" choice in the turn-on dialog; API:
`PUT /api/zones/{zone}/dnssec` with `{"enabled": true, "algorithm": 15}`,
plus `"new_key": true` to replace a kept key). 13 (ECDSA P-256 / SHA-256)
stays the default; a replaced key keeps the old key's algorithm unless
another is given. 15 is Ed25519 (RFC 8080): a 32-byte public key, 64-byte
deterministic signatures (a standby's RRSIGs are byte-identical to the
primary's), DS digest type 2 as usual. Both validate with current
resolvers (RFC 8624: 13 and 15 are MUST/RECOMMENDED to validate); check that
the registrar accepts algorithm 15 DS records before choosing it. The key
rollover wizard rolls to a new key of the **same** algorithm, for 13 and 15
alike. Asking for another algorithm than the existing key's is refused
(409). Choosing Ed25519 is refused (409) while a standby of an older
version follows (it cannot load the key and would serve the zone
unsigned); while a zone is signed with Ed25519, such a standby is refused
by the replication endpoints too (it stays `refused`, keeps its data and
does not halt). Upgrade standbys first.

**Algorithm rollover (13 <-> 15) is not automated.** Changing the algorithm
of a zone whose DS is published needs a double-signature rollover (RFC 6781
section 4.1.4, RFC 7583 section 3.3.4): the zone must be signed with BOTH
algorithms (every RRset carries an RRSIG of each, RFC 4035 section 2.2 /
RFC 6840 section 5.11) before the new DNSKEY and DS appear, and the old
algorithm's signatures may only go after the old DS is gone from every
cache. This server signs a zone with one key, so the safe ways are:
1. **Without a DS published** (or after removing it and waiting the DS
   TTL, so the zone is insecure for a while): turn signing off, turn it on
   with `{"enabled": true, "new_key": true, "algorithm": 15}`, check
   (DNSSEC -> Check), publish the new DS.
2. **Without an insecure period**: move the zone's DNS to a signer that
   supports multi-algorithm signing for the rollover, or ask for it to be
   added here; replacing the key in place while the old DS is published
   makes the zone fail for validating resolvers.

**Signatures and re-signing.** The zone is signed in memory whenever the
catalog is built after a change, and the signed view is cached until the zone
changes. Inception = one hour before the zone's last change (`updated_at`),
expiration = inception + `signature_validity_days` (default 14). The primary
re-signs a zone when its signatures expire within `resign_before_days`
(default 7): a `zone_resigned` change and a serial bump (so secondaries
transfer fresh signatures and NOTIFY goes out). If signatures come within half
of `resign_before_days` of expiry without a serial bump (a primary that was
stopped, a standby cut off from it), the server signs in memory from the
current hour instead.

```toml
[dnssec]
signature_validity_days = 14  # 2..365
resign_before_days = 7        # 1..(validity - 1)
```

**Standbys** receive the signing flag, the key (an account-class change: never
in the changelog API, the websocket, the audit log or the logs; scrubbed after
`account_retention_days`) and the re-sign serial bumps, and sign in memory
with their own copy of the key. ECDSA signatures are randomised, so a
standby's RRSIGs differ from the primary's (Ed25519 ones are identical),
but both verify with the same DNSKEY and every response is self-consistent, which is all resolvers and
AXFR/IXFR secondaries need. A standby never writes or re-signs by itself; its
replicated-table checksums do not include signatures. **Upgrade every standby
before turning signing on** (an older standby cannot apply the new change
kinds and halts).

**Publishing (registrar).** Turning signing on changes nothing for validating
resolvers until the parent zone publishes a DS record. The console's DNSSEC
tab shows the DS (SHA-256, digest type 2; SHA-384 as well) with copy buttons
and the individual fields registrars ask for, and:

1. **Check before adding DS** (`GET /api/zones/{zone}/dnssec/check`): queries
   this server's own answers with DO (DNSKEY, SOA, NS, a sample of names,
   wildcards, a missing name and type) and validates every signature and
   denial proof with the key.
2. Make sure every nameserver of the zone serves the signed zone (secondaries
   by zone transfer; standbys sign themselves).
3. Publish the DS at the registrar.
4. **Is the DS published at the parent?** (`GET /api/zones/{zone}/dnssec/parent`):
   looks the DS up through the first forwarding upstream (RD, CD, DO) and
   reports `present` (matches the key), `absent`, `mismatch` (validating
   resolvers fail the zone) or `unknown` (no upstream, no answer).

**Turning signing off** while a DS is published breaks the zone for every
validating resolver, so it is refused (409 `ds_published`) unless the parent
check says `absent`. Remove the DS at the registrar, wait until the parent's
DS TTL has passed, then turn signing off. The API accepts `force: true` to skip
the check (the console does not offer it). The key is kept when signing is
turned off; turning it on again reuses it.

**Key rollover wizard** (zone -> DNSSEC -> Key rollover; `GET/POST
/api/zones/{zone}/dnssec/rollover`, `.../ds-added`, `.../cancel`,
`.../check`). A pre-publish rollover of the combined signing key for
registrars without an API: the DS change is always done by hand, and the
wizard says exactly what to change and verifies it before moving on. The
zone never depends on a DS the parent does not serve.
1. **Start**: a new key (same algorithm) is published next to the old one,
   which keeps signing (a serial bump). Wait the DNSKEY TTL (the zone's
   default TTL; the console counts down).
2. **Add the new DS** shown (key tag, algorithm, digest type and digest as
   separate fields with copy buttons, plus the one-line record) at the
   registrar NEXT TO the old one; do not remove the old DS. Press "I've
   added it".
3. The primary asks every server of the parent zone directly (it finds them
   through the forwarding upstream, then asks each with RD=0, every
   `[dnssec].rollover_check_secs`, default 300 s) until all return the new
   DS. A DS that matches neither key is shown with the field that differs.
   Then it waits the parent's DS TTL (read from the answers; 86400 for
   `.net`).
4. **Switch**: the new key signs; the old DNSKEY stays published. The
   self-check runs with the new key. No cancel from here on.
5. **Delete the old DS** shown at the registrar. Once no parent server
   returns it and the DS TTL has passed, the old key is unpublished (a
   serial bump): done.
Cancel is possible until the switch (the new key is dropped; remove its DS
at the registrar if you added it). Signing cannot be turned off during a
rollover. Every stage is a `dnssec_key_set` of the key row (the other key
inside, a secret like the signing key), so a standby signs with the same
key set; only the primary moves stages on, and the state survives
restarts. Starting is refused while a following standby is too old to
represent a rollover (its version lacks `+dnssec-rollover`). Needs a
forwarding upstream (to find the parent's servers). Test-only knobs:
`[dnssec] rollover_max_wait_secs` (caps the waits) and `parent_port`.

**API** (all with `#[utoipa::path]`, see `/docs`): `GET /api/zones/{zone}/dnssec`
(status, key, DS, signature window), `PUT /api/zones/{zone}/dnssec`
(`enabled`, `force`, `new_key`; owner role), `GET /api/zones/{zone}/dnssec/ds`,
`GET /api/zones/{zone}/dnssec/check`, `GET /api/zones/{zone}/dnssec/parent`,
and the rollover endpoints above.

## Securing zone transfers with TSIG

For a public zone run rust-dns as a *hidden primary*: it is not listed in the
zone's NS records, and one or more secondaries (Hurricane Electric's free
secondary service, a BIND/NSD box, ...) pull the zone by AXFR and answer the
internet. Transfers and NOTIFY are then authenticated with TSIG (RFC 8945)
shared keys in addition to the address allow-list.

1. In the console open **Admin → TSIG keys → New key**. Name the key (a DNS
   name, e.g. `hn-secondary.`), pick the algorithm (hmac-sha256 unless the
   secondary needs another; hmac-sha1 is offered only as legacy), and either
   **Generate** a secret or **Import** the base64 secret the provider
   generated. Optionally limit the key to the zones that secondary serves.
   The secret is shown once, with a ready-to-paste BIND `key`/`zone`
   configuration and a `dig -y ... AXFR` test command. Showing it again later
   (`POST /api/tsig/keys/{name}/reveal`) is recorded in the audit log; the
   secret itself never appears in the audit log, changelog or server logs.
2. Configure the policy in the config file and reload (SIGHUP or
   `POST /api/admin/reload`):

```toml
[transfer]
allow = ["216.218.133.2/32", "2001:470:600::2/128"]  # the secondary's transfer addresses
require_tsig = true           # unsigned transfer requests are refused
notify_key = "hn-secondary."  # signs NOTIFY; empty = unsigned
notify = ["216.218.130.2:53"] # or [{ address = "203.0.113.5:53", key = "other-secondary." }]
```

A transfer (AXFR, or IXFR which is answered with the full zone) is served only
when the client address is in `allow` **and**, if the request is signed or
`require_tsig` is on, the signature verifies with a key that covers the zone.
A signed request with an unknown key gets NOTAUTH/BADKEY, a bad MAC
NOTAUTH/BADSIG (both unsigned), a clock more than 300 s off NOTAUTH/BADTIME
(signed, with the server's time); it is never treated as unsigned. Signed
requests get signed answers, and every message of a multi-message AXFR is
signed with MAC chaining (RFC 8945 §5.3.1). Signed NOTIFY responses are
verified and failures are logged. `require_tsig` defaults to `false` for
existing setups; it is recommended to turn it on. The console shows the policy
in effect on the TSIG keys page. Keys are stored in the database (as backups
are), so protect database files and backups accordingly.

On a BIND secondary:

```
key "hn-secondary." { algorithm hmac-sha256; secret "<base64 secret>"; };
zone "example.com" {
    type secondary;
    file "example.com.db";
    primaries { 192.0.2.1 key "hn-secondary."; };
};
```

Test from an allowed address with
`dig -y hmac-sha256:hn-secondary.:<secret> @192.0.2.1 example.com AXFR`.

## Standby / follow mode

A second rust-dns can mirror the primary so that it answers **all DNS
queries while the primary is down**. The standby refuses every change and is
promoted to primary by hand when you decide the primary is gone. It is a
failover standby, not a load-balanced cluster: there is one writable server
at a time, and no automatic failover.

### Setting up a standby

1. On the primary, sign in as an administrator and create an API token
   (*API tokens -> New token*). The token must belong to an **administrator**
   (the `replicate` permission): the standby checks this on every connection
   and stops (state `refused`) when the token is invalid, revoked or not an
   admin's.
2. Put the primary's console behind HTTPS (the TLS reverse proxy you already
   use). The replication stream carries password hashes, TOTP secrets, token
   hashes and TSIG secrets, so a plain `http://` primary URL is refused unless
   `allow_insecure_http = true` (loopback addresses are always allowed).
   Certificates are checked against the operating system's trust store,
   or, when the primary's certificate comes from a private CA, against
   that CA only: `ca_file = "/etc/rust-dns/primary-ca.pem"` in `[follow]`
   (PEM, one or more CA certificates; `[peer]` takes a `ca_file` too, for
   the standby's certificate). `--check` refuses a missing or non-PEM file.
3. On the second server, start from a normal config (see
   `examples/config/standby.toml`) and add:

```toml
[follow]
primary = "https://dns1.example.net:8053"   # the primary's web API
instance_id = "dns2"                        # required: this standby's name on the primary
token = "rdns_..."                          # administrator token on the primary
reconcile_interval_secs = 3600
allow_insecure_http = false
timeout_secs = 30
```

4. Start it (its database must be new or fresh, see below). It loads a snapshot of the primary, then tails its changelog
   (a long-poll, answered as soon as a change commits) and shows a banner on
   every console page: *Standby of https://dns1... - read-only - in sync*.
   **Admin -> Replication** shows the details (applied offset, lag, last
   error, last snapshot and reconcile).
5. On the primary, add `[peer] url = "https://dns2.example.net:8053"` (the
   standby). A primary with `[peer]` asks the standby at startup and every
   `check_interval_secs` whether it was promoted away from its history; if so
   it runs **read-only** ("fenced") instead of accepting writes. Without it, an
   old primary that comes back after a failover accepts writes (split brain).

`rust-dns --check` prints the role a config gives the server.

Snapshots are sent gzip-compressed when the standby asks for it
(`Accept-Encoding: gzip`, which this version does); older standbys and
primaries simply exchange plain JSON.

### Cascading standbys

A standby can serve other standbys: point a third server's `[follow]
primary` at the standby's URL (with a token of an administrator, which the
standby has as a copy of the primary's accounts). It copies the standby's
data with the primary's offsets and history, and the standby lists it under
*Admin -> Replication* (*Standbys following this standby*). Rules through
the chain:

- A standby serves standbys only once it has loaded its primary's data,
  and never while halted. When it halts, the standbys that follow it halt
  too (`upstream_halted`): their copy came from it. Rebuild the upstream
  standby first, then them (`--prepare-standby --yes`).
- Promoting a standby in the middle of a chain works as for a standby of a
  primary: the standbys that follow it adopt its new history and continue.
- A standby that follows another standby must use the same `[root]
  username` (each server keeps its own root account local); otherwise it
  is refused with that explanation. Versions before this one do not serve
  standbys and cannot follow one (refused, not halted).

### What is replicated

| Replicated | Not replicated (local to each server) |
|---|---|
| Zones, records (including expiry state), zone members | Sessions (users sign in again on the standby) |
| Users: password hashes, admin flag, disabled, MFA secret and last used TOTP step, recovery codes | API token `last_used_at` / `last_used_ip` |
| API tokens (hashes, tags, revocation) | The config file: listeners, `[forwarding]` defaults, `[transfer]`, rate limits, logging, backups |
| Forwarding settings saved from the console (the `settings` override) | The audit log (each server audits its own actions; the standby adds `replication.*` rows) |
| TSIG keys | The standby's own `[root]` (see below) |
| DNSSEC: the per-zone signing flag, the signing keys (private keys as account-class changes), re-sign serial bumps | The signatures themselves: each server signs in memory |

**Every mutation is a change.** DNS changes *and* account, settings and TSIG
changes (users, password and MFA changes, accepted TOTP steps, recovery
codes, API tokens, the forwarding override, TSIG keys) are typed facts written
to the changelog in the same transaction as the data and its audit row, in one
ordered sequence. The standby replays them in order and stores them with the
**same offsets**, so a promoted standby continues the same sequence. A
snapshot (used to start, and after a gap) is the same kind of facts
(`user_created`, `zone_created`, `record_created`, ...) loaded through the
same replay code, so its format does not depend on the storage engine.

**The console on a standby (and everywhere else).** Every button and form
action in the console declares the permission it needs or that it is safe on
a read-only server; anything undeclared is disabled, so a new control cannot
slip through (a test fails the build otherwise). A control is enabled only
when the server would accept it: the signed-in user's effective rights come
from `GET /api/users/{id}/rights` (the same permission table every API check
uses), the standby allowlist from `GET /api/status`
(`replication.standby_writable`), and object state the page knows (your own
account, the root account, a DS still published at the parent). Disabled
controls say why in their tooltip; on a standby that is "Read-only standby:
make changes on the primary (<primary url>)". Per-server actions still work
there: test upstreams, flush the forwarding cache, download blocklists now,
test a name against the blocklists, show a TSIG secret, sign sessions out,
promote. As a second line, the console's API wrapper refuses any other write
on a standby before sending it; the server refuses it anyway (409
`read_only_standby`).

Account changes carry password hashes, TOTP and TSIG secrets. They never
appear in `GET /api/changelog` or the websocket (not even for
administrators), only in the admin-only replication API, and their payloads
are scrubbed after `[changelog].account_retention_days` (default 3); a
standby further behind than that loads a snapshot. The changelog API
therefore shows DNS offsets with holes where account changes were.

**Snapshot once, then the changelog.** A standby loads a snapshot only when
it connects and cannot continue from its own offset (a fresh database, or
the changes it needs were pruned); the snapshot carries the offset it
corresponds to, and from there everything is fetched by offset from
`GET /api/replication/changes` in batches of whole transactions (a standby
that is far behind fast-forwards batch by batch). Facts are complete new
state, so re-applying changes from an earlier offset is harmless.

Every `reconcile_interval_secs` the standby compares a checksum of every
replicated table (per-server columns such as token last use, and its own
root account, left out) and of every zone with the primary at the same
offset. A difference means a change was lost or misapplied: replication
**halts** (see "Halted" below). Primary and standby must speak the same replication protocol
(2 since this version): a standby refuses an older primary with a clear
error; upgrade the primary first.

Record expiry is decided by the primary: `record_expired` / `record_reaped`
arrive in its changelog (expired records stop being served at their
`expires_at` on both servers anyway). The standby's expiry sweeper does not
run. The standby **does** send NOTIFY to its own `[transfer].notify` targets
when replicated changes arrive; leave that list empty on the standby if your
secondaries only know the primary.

**Root account.** The standby's `[root]` from its own config always works
locally, so you can sign in to the standby's console while the primary is
down. If the primary has a user with the same name (typically `root`), the two
are merged: the account keeps the primary's id (so its API tokens and zone
ownership apply) but its password, MFA setting, TOTP enrollment and recovery
codes are the standby's own. If the primary has no user with that name, the
standby's root is kept as an extra local account. Other replicated
administrators are ordinary admins on the standby (only the local root is
`root`). Use the same root username on both servers.

**TOTP replay protection** survives a failover: the last accepted time step
is replicated, and a later step used on the standby is kept, so a code used
on the old primary cannot be replayed on the promoted standby (provided the
standby had caught up, as it has within about a second while connected).

**On the standby**, every mutating API call returns `409` with
`code: read_only_standby` and a message naming the primary (documented on
each operation in the OpenAPI document). Still allowed: signing in and out
(forced MFA enrollment only for the local root), managing sessions, reloading
the config, testing upstreams, flushing the forward cache, revealing a TSIG
key, and promotion.

### Promotion runbook (primary is down)

1. Make sure the primary is really gone (or stop it). The console refuses a
   promotion while the primary is reachable unless you tick *Promote anyway*
   (`"force": true`).
2. Promote the standby, either
   - console: **Admin -> Replication -> Promote to primary...** (two clicks in
     the dialog), or
   - API: `POST /api/replication/promote` with `{"confirm": true}`, or
   - stopped server: `rust-dns --promote --config /opt/rust-dns/etc/rust-dns.toml`.

   Promotion removes `[follow]` from the config file (a comment records it; the
   token is not kept), starts a **new history id** whose parent is the old one
   (recording the offset it forked at), and makes the server writable at once:
   the expiry sweeper starts, no restart needed. Removing `[follow]` by hand
   and restarting has the same effect (the next start records the promotion).
3. Point the registrar's NS/glue and your secondaries' primary address at the
   new primary if they named the old one.

### Bringing the old primary back

With `[peer]` pointing at the promoted server, the old primary starts
**fenced** (read-only, role `fenced`) and says why. To make it a standby of
the new primary:

1. Stop it. Replace `[peer]` with a `[follow]` section pointing at the new
   primary (an administrator token; tokens made on the old primary still work,
   they were replicated).
2. Run `rust-dns --prepare-standby --config /opt/rust-dns/etc/rust-dns.toml`.
   Without `--yes` it only lists what would be deleted and exits with status 2.
   With `--yes` it:
   - writes a full online backup next to the database
     (`<db>.pre-standby-<time>`, path printed),
   - writes the changes the new primary does not have to
     `divergent-<time>.json` next to the database (the fork point is asked from
     the new primary's public identity; when it is unknown every retained local
     change is listed; DNS data only, no account data or secrets),
   - deletes zones, records, zone members, the changelog, TSIG keys, console
     settings, API tokens, sessions and every user except the config root, and
     forgets the replication lineage; the audit log is kept and gets a
     `replication.prepare_standby` row naming the backup.
3. Start it: it is fresh, so it copies the new primary and follows it.

Re-apply anything from the divergence file that you still want on the new
primary. To fail back later, promote the old primary the same way and make
the other server its standby (again with `--prepare-standby`).

**Following never discards data implicitly.** A server with `[follow]`
starts following only if its database is a copy of that primary's history
(a standby restarting or reconnecting; a snapshot after a changelog gap
within the same lineage stays automatic, since that data came from the
primary) or if it is **fresh**: no zones, records, zone members,
TSIG keys, console settings, API tokens, and no users besides the config
root. Anything else (an old primary with changes after the fork, a server that
was used on its own, a primary restored from an older backup) is refused:
state `refused`, the error names the data found and the command to run, it is
shown in `/api/replication/status`, the console banner and Replication page,
the log and `rust-dns --check`, and the server keeps serving its local data
read-only.

A standby also refuses (state `refused`) to follow a server it was itself
promoted away from (the stale old primary), so a leftover `[follow]` cannot
make a promoted server discard its own writes.

### Monitoring replicas (on the primary)

Each standby names itself with `[follow].instance_id` (required; a-z, 0-9,
`-`, unique per primary) and sends it, with its version and a per-process
session id, on every replication request (`X-Rust-DNS-Instance`,
`X-Rust-DNS-Version`, `X-Rust-DNS-Session`; data endpoints refuse requests
without it with 400). The primary tracks each instance, Kafka style:

- **applied offset**: the `after` of its last changes request (a standby
  commits a batch before it asks for the next one, so that is what it has);
- **lag** in changes (primary head minus applied offset) and in seconds
  (since it was last caught up);
- last seen, remote address (normal client-IP rules), version, token user.

States, with thresholds in `[replication]` (primary side, reloadable):

| State | Meaning |
|---|---|
| `up_to_date` | lag 0, or caught up within `up_to_date_grace_secs` (10) |
| `catching_up` | behind, within the thresholds |
| `falling_behind` | more than `max_lag_changes` (1000) behind, or not caught up for more than `max_lag_secs` (60) |
| `offline` | no request for `offline_after_secs` (75; keep it above the 25 s long-poll) |
| `bootstrapping` | a snapshot is being served / loaded |
| `halted` | the standby reported that it stopped (divergence, see below) |

`conflict: true` flags one instance id used by two processes at once
(requests interleaving from two addresses or sessions; a restart or a move is
not a conflict); a warning is logged. The list is kept in a local table
(`replicas`, not replicated) so it survives restarts; entries not seen for
`forget_after_days` (30) are dropped, and `DELETE /api/replication/replicas/{id}`
forgets one (audited `replication.replica_forget`; local bookkeeping, not in
the changelog). See **Admin -> Replication** (live table), `GET
/api/replication/replicas`, and the metrics
`rustdns_replication_replica_lag_changes{instance}`,
`rustdns_replication_replica_lag_seconds{instance}`,
`rustdns_replication_replica_state{instance,state}` (1 for the current
state), `rustdns_replication_replicas{state}` and
`rustdns_replication_replica_conflicts`. Example alerts (in
`deploy/prometheus-alerts.yml`):

```yaml
- alert: RustDnsReplicaNotUpToDate
  expr: max by (instance) (rustdns_replication_replica_state{state=~"falling_behind|offline|halted"}) == 1
  for: 5m
- alert: RustDnsReplicaHalted
  expr: max by (instance) (rustdns_replication_replica_state{state="halted"}) == 1
- alert: RustDnsStandbyHalted          # on the standby itself
  expr: rustdns_replication_halted == 1
```

### Halted: divergence is a bug, the standby stops

A standby never changes replicated data by itself (writes are refused by
the write gate, the account tables are written only by the replay path, and
its own sign-ins only touch per-server columns). So when its copy differs
from the primary, that is a bug, and the standby **reports and aborts**
instead of repairing it silently. It halts on:

- `diverged`: the periodic reconcile found a table or zone whose checksum
  differs from the primary's at the same offset;
- `apply_failed`: a change from the primary did not apply;
- `txn_mismatch`: on connecting, its change at its head offset is not the
  primary's (same history, different data);
- `ahead_of_primary`: it has offsets the primary does not (a primary restored
  from an older backup);
- `upstream_halted`: it follows another standby, and that standby halted.

Network errors, timeouts and 5xx are ordinary reconnects, and a pruned
offset (`gap`) within the same history is the automatic snapshot case; none
of those halt.

When halted, the standby stops talking to the primary except to report the
halt once (at the halt and at each start; the primary then lists it as
`halted` with the reason), keeps answering DNS from its last applied state,
and shows it everywhere: a red console banner, `/api/status` and
`/api/replication/status` (`follow.halted` with reason, detail, offset),
`rust-dns --check`, the startup log (error), the metric
`rustdns_replication_halted 1`, and a report `diverged-<time>.json` next to
the database (what differed: tables, zones, both checksums, offsets; no
secrets). The state is stored in the database, so it survives restarts.

To investigate: keep the report and the logs (they are the bug report).
To rebuild: stop the standby and run `rust-dns --prepare-standby --yes`
(backs up the database, empties it); at the next start it copies the primary
again. Promoting a halted standby is possible but promotes its diverged
data; rebuild it first unless the primary is gone.

### Replication API

All under `/api/replication/`, admin only (`replicate`) except `identity`:
`GET status` (both roles), `GET snapshot` (logical entities),
`GET changes?after=&limit=&wait=` (long-poll), `GET checksum` (the data
endpoints are served by a writable primary and by a standby that has loaded
its primary's data; 409 otherwise, with the code `replication_halted` from a
halted standby), `POST promote`, and the public
`GET identity` (role and history ids, no data) used by the `[peer]` check.
Metrics: `rustdns_replication_writable`, `rustdns_replication_standby`, and on
a standby `rustdns_replication_connected`, `rustdns_replication_lag_changes`,
`rustdns_replication_last_applied_offset`,
`rustdns_replication_seconds_since_last_applied`,
`rustdns_replication_reconnects_total`, `rustdns_replication_rebootstraps_total`,
`rustdns_replication_reconcile_mismatches_total`.

## API

Everything the console does goes through `/api`. Authenticate with a session
cookie (the console) or a bearer token (scripts):

```
curl -H "Authorization: Bearer rdns_…" http://127.0.0.1:8053/api/zones
curl -H "Authorization: Bearer rdns_…" -H "content-type: application/json" \
     -d '{"name":"www","type":"A","value":"10.0.0.1","ttl":300}' \
     http://127.0.0.1:8053/api/zones/example.com/records
```

| Method | Path | Notes |
|---|---|---|
| POST | `/api/auth/login`, `/auth/mfa`, `/auth/enroll`, `/auth/logout` | session flow |
| GET | `/api/zones`, `/api/zones/{zone}` | zones visible to the caller, with role |
| POST/PUT/DELETE | `/api/zones`, `/api/zones/{zone}` | admin creates; owner edits/deletes |
| POST/PUT/DELETE | `/api/zones/{zone}/records[/{id}]` | editor or owner |
| PUT/DELETE | `/api/zones/{zone}/members/{username}` | owner grants `editor`/`viewer` |
| GET | `/api/zones/{zone}/export`, `/api/export` | JSON export document |
| POST | `/api/import?mode=merge\|replace` | JSON export document |
| GET | `/api/changelog?after=<offset>&limit=` | DNS changes; rows of one transaction share `txn`. `resync_required` when the cursor fell behind retention |
| GET | `/api/audit?after=<id>&limit=` | account and security changes (admin) |
| GET | `/docs` | interactive API explorer (Swagger UI, bundled); also the console's "API explorer" section |
| GET | `/api/users/{id}/rights?via=session\|token` | effective rights of a user or of their API tokens (self or admin) |
| GET | `/api/ws?after=<offset>&queries=true` | websocket: `change` and `query` events; tokens as subprotocol `rust-dns.bearer.<token>` |
| GET/POST/PUT/DELETE | `/api/users[/{id}]`, `/api/users/{id}/reset-mfa` | admin |
| GET/POST | `/api/users/{id}/sessions`, `/sessions/revoke` | inspect or revoke all user sessions (admin) |
| GET/POST/DELETE | `/api/tokens[/{id}]` | own tokens |
| PUT/POST | `/api/me/password`, `/api/me/mfa/start|confirm|disable` | self service |
| POST | `/api/me/mfa/recovery` | regenerate recovery codes with TOTP |
| GET | `/api/status`, `/metrics`, `/api/health` | |
| GET/PUT/DELETE | `/api/settings/forwarding`, POST `/api/settings/forwarding/cache/flush` | forwarding upstreams, ACL, cache caps; cache stats and flush (admin) |
| GET/POST | `/api/replication/status`, `snapshot`, `changes`, `checksum`, `identity`, `promote` | standby mode (see [Standby / follow mode](#standby--follow-mode)) |

The zone records endpoint accepts `q`, `offset`, and `limit` for server side
search and paging. The console displays 500 records per page by default.

### API documentation

The OpenAPI document is generated from the Rust code with
[utoipa](https://crates.io/crates/utoipa), so it cannot drift from the API:

- Each handler carries a `#[utoipa::path(...)]` annotation (method, path, tag,
  operation id, parameters, request body with examples, every response status).
- Routes are mounted only through `utoipa_axum`'s `OpenApiRouter` with
  `.routes(routes!(handler))` in `src/api/mod.rs`; that one line both registers
  the axum route and adds the operation to the document.
- Request and response bodies are typed structs deriving `ToSchema`
  (`src/api/types.rs`, `src/model.rs`, ...), so the schemas are the serde shapes.
  An `Option` field that always serializes carries `#[schema(required = true)]`
  (required, nullable); one skipped when empty carries `#[schema(nullable = false)]`.
- Info, tags, security schemes and the shared error responses live in
  `src/api/openapi.rs`. The document is serialized once at startup and served
  at `/api/openapi.json`; Swagger UI at `/docs` renders it.

A snapshot is committed at `docs/openapi.json` so API changes are visible in
review. A unit test fails when it is stale; after an intended API change run

```
UPDATE_OPENAPI=1 cargo test --bin rust-dns openapi
```

and commit the updated snapshot with the code.

Record values are text in the usual zone-file form: `10 mail.example.com` for
MX, `10 20 5060 sip.example.com` for SRV. Names inside values are absolute.
Record names are relative to the zone (`@`, `www`, `*.apps`), absolute forms
are accepted.

## Architecture

```
 storage (SQLite, WAL)  ──►  cache (immutable catalog, atomic swap)  ──►  zones (pure lookup)  ──►  dns (udp/tcp)
        ▲                                                                                         │
        │ one write lock, one transaction per mutation                                            │ QueryEvent
   mutation ──► changelog row (offset) ──► events bus (named_queue broadcast) ──► websocket / logging
        ▲
   api (axum): sessions, tokens, RBAC, export/import      ui: single embedded HTML page
```

- DNS lookups never touch the database; they read an immutable in-memory
  catalog that is rebuilt and swapped after each committed mutation.
- Writes are structurally logged. Only the mutation module can open a write
  transaction (it alone can create the `WriteToken` that `Storage::write`
  requires), and the SQL that writes zones, records, members and accounts is
  private to it. Operations receive a `Tx` / `AuditTx` whose write methods each
  record a change; the commit writes those changes to the changelog or audit
  log, and bumps SOA serials, in the same SQLite transaction. A failure
  anywhere rolls everything back and is logged as a warning instead.
- Account, settings and TSIG writes are typed changes too (`AuditTx::record`,
  the only writer of those tables, checked by a test), logged in the same
  changelog sequence (class `account`, never shown by the changelog API).
  Every table is classified as replicated or local in
  `src/replication/tables.rs` (a test fails on an unclassified table).
- The only writes outside that path are bookkeeping: session `last_seen_at`,
  API token `last_used_at`, retention pruning, and schema migration.
- Offsets are exact and never reused, even after retention pruning. Replaying
  the changelog into an empty database reproduces the same data; a randomized
  test checks this over hundreds of operations, including rollbacks.
- The event bus is [`named_queue`](https://crates.io/crates/named_queue)
  broadcasting queues: each subscriber has its own bounded buffer, and a slow
  websocket can never slow the DNS path.

## Testing

```
cargo test --test api_contract    # every operation and example of the served OpenAPI document against a live server, strict schema checks
cargo test --test openapi_spec     # completeness of the generated document (ids, tags, 400/401, request bodies, no bypassed routes)
cargo test --bin rust-dns openapi  # docs/openapi.json equals the document generated from the code (UPDATE_OPENAPI=1 refreshes it)
node tests/ui/duration.test.js     # console duration parser (1m, 1h, 6d12h14s)
node tests/ui/access.test.js       # console access decisions (rights, standby allowlist)
node tests/ui/browser.test.js      # console flows in headless Chrome (sign in, zone, records, viewer, standby, scoped token); needs `cargo build` and Chrome (CHROME_BIN), skips without them unless REQUIRE_BROWSER_TEST=1
cargo test                          # unit tests + end-to-end (spawns the binary, drives API and DNS)
scripts/conformance.py <zone> <ip> <port>   # 123 RFC conformance checks (incl. TSIG and DNSSEC validation) (needs dnspython + cryptography and a seeded zone)
scripts/dnssec-vectors.py                   # regenerates the DNSSEC known-answer vectors (dnspython + BIND dnssec-dsfromkey)
scripts/compliance.sh <zone> <ip> <port>    # ISC DNS Compliance Testing (genreport), builds it on first run
scripts/e2e-dig.sh <zone> <ip> <port>       # human-readable dig walkthrough
scripts/conformance-local.sh                # starts a temporary server, seeds it, runs all probes
scripts/load-test-local.sh                  # short UDP load probe; intended for Linux
scripts/soak.py --bin <binary> ...          # hours-long soak with a standby (see "Soak test")
```

### Soak test

`scripts/soak.py` (Python 3 standard library only) runs a primary and a
standby of the given binary on free loopback ports with throwaway configs
and databases in `--workdir`, seeds a DNSSEC-signed zone, and for
`--duration` sends a mixed UDP query load to both (existing names, NODATA,
NXDOMAIN, SOA/NS/TXT/DNSKEY, 30% with DO) while records on the primary are
created, changed, deleted and given short expiries through the API. Every
`--interval` it appends to `samples.jsonl`: per server RSS, CPU seconds,
open file descriptors (Linux), p50/p95/p99/max latency, timeouts and wrong
answers; the standby's lag, state and last reconcile. At the end it writes
`summary.json` and exits 1 when the error rate exceeds `--max-error-rate`
(default 0.1%; a name created a moment ago and queried on the standby
before it arrived counts, so expect a handful), the standby halted or did
not catch up, a server died, or RSS grew more than `--max-rss-growth`
(default 50%) after warm-up.

```
cargo build --release
scripts/soak.py --bin target/release/rust-dns --duration 6h --qps 500 --change-rate 6 --interval 60
```

On the test host (LXD `home:dns-test`, only with the owner's go-ahead):
copy a release build there (e.g. the GitHub release artifact, or a
`cargo zigbuild` musl build) to a scratch directory, not over
`/opt/rust-dns`; the script binds only 127.0.0.1 on free high ports, so the
installed instance and port 53 are untouched. Run it under `nohup` or
`tmux` and watch `samples.jsonl`:

```
mkdir -p ~/soak && cd ~/soak    # rust-dns and soak.py copied here
nohup python3 soak.py --bin ./rust-dns --duration 12h --qps 500 --change-rate 6 --workdir ~/soak/run > soak.out 2>&1 &
tail -f soak.out                # one line per interval; summary at the end
```

Memory: the Linux release builds (static musl) use mimalloc as their
allocator. With musl's own allocator the resident memory grew without a
plateau under this load while the live heap stayed flat (fragmentation,
found by the first soak; plan.md O13a). `/metrics` shows the allocator
(`rustdns_build_info{allocator="mimalloc"}`) and, on Linux, the resident
memory (`rustdns_process_resident_memory_bytes`).

What to look at: RSS flat after warm-up (no growth over hours), p99
latency stable, zero timeouts, `lag` back to 0 between changes,
`reconcile` "ok ...", `halted` null throughout. Python's sender sustains a
few thousand queries per second per server; for more, run several copies
against the same servers or use `scripts/load-test.py`.

Current status: the Rust suite passes (unit tests, end-to-end tests in
`tests/e2e.rs`, `tests/tsig.rs`, `tests/forwarding.rs` and
`tests/follow.rs` (standby mode: two servers, bootstrap, replication,
failover, promotion, fencing, rejoin with divergence), `tests/hardening.rs` (security regressions: TCP pinning, init-config,
password logging, TOTP replay across restarts, websocket revocation and
origin, cookies, slow clients, CSP), API contract and OpenAPI document
tests, and `tests/dnssec.rs`). The seeded conformance runner passes 123/123, and ISC genreport reports
all protocol and record-type probes as `ok`.
CI runs formatting, clippy, the Rust test suite, conformance, and a short Linux
UDP load probe.

**DNSSEC is validated by independent implementations**, not by the server's
own code: `src/dnssec/vectors.rs` pins canonical signed data and signatures
from dnspython and DS digests from BIND `dnssec-dsfromkey`;
`scripts/conformance.py` validates every signed answer (positive, wildcard,
NXDOMAIN, NODATA, empty non-terminal, DNAME, referrals, AXFR and the NSEC
chain) with `dns.dnssec.validate`; `tests/dnssec.rs` runs BIND
`dnssec-verify -z` on the transferred zone, `delv` ("fully validated") for 40
query cases including 0x20 names and TCP, a negative control with a wrong
trust anchor, and, when `named` is installed, a validating BIND resolver that
must set AD on every answer; `tests/follow.rs` runs `delv` and
`dnssec-verify` against a standby. The BIND parts are skipped when the tools
are missing unless `REQUIRE_BIND_TOOLS=1` (CI installs `bind9-utils` and
`bind9-dnsutils` and sets it).

Example Prometheus alert rules for rate limiting, refused answers, errors, and
bad DNS cookies are in `deploy/prometheus-alerts.yml`.

Throughput on a laptop (release build): DNS over TCP ~240k queries/s with 8
clients; over UDP the server matches a bare UDP echo on the same host, so the
ceiling is the OS loopback path, not the server. Resident memory stays around
30 MB under load.

## Not yet

- DNSSEC: NSEC3 opt-out and salts / extra iterations (RFC 9276 advises
  against them), automated key rollover through CDS/CDNSKEY (the wizard
  above needs the DS change done by hand), algorithms other than 13 and 15,
  automated algorithm rollovers (13 <-> 15, see DNSSEC).
- Inbound NOTIFY / acting as a secondary for zones hosted elsewhere; automatic failover.
- DNS over TLS/HTTPS, response tuple rate limiting (RRL by answer), and per-zone forwarding,
  reverse-zone, transfer ACL, and NOTIFY overrides.
- Console sorting and bulk record tools, WebAuthn, static musl multi-arch
  publishing, Debian packaging, and a Homebrew formula.

## License

Apache-2.0
