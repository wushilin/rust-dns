# rust-dns

A lightweight, SQLite-backed authoritative DNS server with a realtime web
console, a token-secured REST API, and a WAL-style changelog. Built to be the
primary nameserver for your own domains, or the DNS for a homelab, without the
last-century feel.

Single static binary, one SQLite file, one TOML config. Zero JavaScript build.

## Features

**DNS**
- Authoritative for any number of zones, including `.` as a private root.
- A, AAAA, CNAME, PTR, NS, MX, TXT, SRV. SOA and apex NS are synthesized from
  zone settings when not set explicitly.
- CNAME chasing, RFC 4592 wildcards, delegations with glue, RFC 2308 negative
  answers, empty non-terminals, RFC 8482 minimal ANY, EDNS with BADVERS,
  truncation with TCP fallback, CHAOS `version.bind`.
- Automatic PTR answers synthesized from A/AAAA records (no separate reverse
  zone maintenance).
- UDP and TCP on any set of bind addresses and any port, IPv4 and IPv6.
- Optional forwarding of foreign names to upstream resolvers, restricted to an
  allow-list of client networks so you never become an open resolver.
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

[logging]
format = "text"               # or "json"
level = "info"
log_queries = false
file = ""                    # empty = stdout
max_size_mb = 50
max_files = 10
compress = true              # gzip rotated files
```

Put the console behind a TLS reverse proxy for anything beyond localhost.
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
  working until they expire. Send HSTS at the TLS proxy (rust-dns adds
  `Strict-Transport-Security` itself only on requests a trusted proxy marks
  as HTTPS).
- **Sign-in protection.** Per client (IPv4 address / IPv6 /64) request
  limits; per account and network, exponential waits after
  `login_backoff_after` failures (up to 15 minutes); per account from all
  networks, waits capped at one minute (a distributed attack is slowed, the
  owner is never locked out for long); 5 wrong codes end an MFA-pending or
  signed-in session. TOTP codes are single-use (the last accepted time step
  is stored). Replacing an enrolled authenticator needs the current code or
  password. Changing your password signs out your other sessions; API tokens
  are not affected (revoke them separately). Argon2 runs on a small bounded
  worker pool; when it is saturated sign-ins get 503 with `Retry-After`
  instead of slowing DNS.
- **Websocket.** Streams re-check the session/token and zone rights every 10
  seconds and on membership changes, and close (1008) when revoked. Cookie
  upgrades must come from the same origin. Scripts pass the token as the
  subprotocol `rust-dns.bearer.<token>`; `?token=` still works but is
  deprecated (URLs end up in proxy logs).
- **Forwarding.** Upstream queries use a fresh random ID and 0x20 case
  randomisation; replies must match ID, QR, opcode and question exactly.
  Forwarded answers are truncated to the client's UDP size. ACLs that would
  make an open resolver (a /0, or anything shorter than /8 IPv4 or /16 global
  IPv6, or entries covering more than 1/16 of IPv4 together) are refused in
  the config file and the console.
- **Web listener.** Request headers must arrive within
  `request_header_timeout_secs`, at most `max_connections` connections are
  served, and pages are served with a strict Content-Security-Policy (scripts
  by hash, no inline handlers, `object-src 'none'`, `frame-ancestors 'self'`).
- **TSIG is unaffected** by these changes.
- **BIND zone-file import and export were removed** (the parser followed
  `$INCLUDE` to files on the server). JSON import/export remains.

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
cargo test                          # unit tests + end-to-end (spawns the binary, drives API and DNS)
scripts/conformance.py <zone> <ip> <port>   # 86 RFC conformance checks (incl. TSIG) (needs dnspython and a seeded zone)
scripts/compliance.sh <zone> <ip> <port>    # ISC DNS Compliance Testing (genreport), builds it on first run
scripts/e2e-dig.sh <zone> <ip> <port>       # human-readable dig walkthrough
scripts/conformance-local.sh                # starts a temporary server, seeds it, runs all probes
scripts/load-test-local.sh                  # short UDP load probe; intended for Linux
```

Current status: the Rust suite passes (unit tests, end-to-end tests in
`tests/e2e.rs`, `tests/tsig.rs`, `tests/forwarding.rs` and
`tests/hardening.rs` (security regressions: TCP pinning, init-config,
password logging, TOTP replay across restarts, websocket revocation and
origin, cookies, slow clients, CSP), API contract and OpenAPI document
tests). The seeded conformance runner passes 86/86, and ISC genreport reports
all protocol and record-type probes as `ok`.
CI runs formatting, clippy, the Rust test suite, conformance, and a short Linux
UDP load probe.

Example Prometheus alert rules for rate limiting, refused answers, errors, and
bad DNS cookies are in `deploy/prometheus-alerts.yml`.

Throughput on a laptop (release build): DNS over TCP ~240k queries/s with 8
clients; over UDP the server matches a bare UDP echo on the same host, so the
ceiling is the OS loopback path, not the server. Resident memory stays around
30 MB under load.

## Not yet

- DNSSEC signing (NSEC/NSEC3, key management, DS publication).
- Changelog follower mode and inbound NOTIFY/secondary service.
- DNS over TLS/HTTPS, response tuple rate limiting (RRL by answer), and per-zone forwarding,
  reverse-zone, transfer ACL, and NOTIFY overrides.
- Console sorting and bulk record tools, WebAuthn, static musl multi-arch
  publishing, Debian packaging, and a Homebrew formula.

## License

Apache-2.0
