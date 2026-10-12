# rust-dns

**DNS for your own domains and your network, managed from a browser or an
API instead of config files.**

One static binary, one SQLite file, one TOML config. It answers for your
zones, forwards everything else, and gives you a live web console, a REST API,
users with MFA, DNSSEC and a hot standby.

## Why rust-dns

- **Change DNS without touching a file or restarting.** Every record is
  created, changed or deleted in the web console or through the REST API. The
  change is answered at once: no reload, no SIGHUP, no zone-file syntax.
- **A real API.** Everything the console does is an API call, documented
  as OpenAPI 3.1 with a built-in API explorer at `/rust-dns/docs`. Scripts
  use API tokens that can be limited to some zones, to a role, and to an
  expiry date.
- **Records that expire by themselves.** Give a record `expires_in` (seconds)
  or `expires_at` and it stops answering at that moment: useful for
  self-registering hosts, ACME challenges and temporary test names.
  Re-posting the record renews it.
- **TTLs under your control.** Every record has its own TTL (or the zone
  default). For forwarded names, the cache can cap how long answers are kept
  (`cache_max_ttl`, `cache_negative_max_ttl`) without ever raising a TTL, and
  can serve stale answers while an upstream is down.
- **Fast, and queries never wait for changes.** Your zones are served from
  memory, from an immutable snapshot that is swapped in after each change.
  A query never touches the database and never waits for a write. See
  [Benchmarks](#benchmarks).
- **Teams and permissions.** Users with passwords and TOTP (Google
  Authenticator, 1Password, ...), recovery codes, per-zone owners who grant
  `editor` or `viewer` access, and an audit log of every account and security
  change.
- **See it live.** The console shows record changes by other users and every
  query the server answers, as they happen.
- **DNSSEC with one switch.** Online signing per zone, automatic signature
  renewal, and the DS record to give your registrar, with a check before you
  publish it.
- **A hot standby.** A second server mirrors everything (zones, records,
  users, tokens, settings, keys) within moments, keeps answering when the
  primary is down, and is promoted by hand. It verifies its copy against the
  primary and stops loudly rather than serve silently diverged data.
- **The home-network features you expect from dnsmasq**, set from the
  console: local names, conditional forwarding, blocklists, rebinding
  protection, domain-needed, bogus-priv, hosts-file import.
- **Built for the internet too.** Per-client rate limiting and response rate
  limiting (RRL), DNS cookies, TSIG-secured zone transfers and NOTIFY,
  secondary zones, DNS over TLS and DNS over HTTPS, PROXY protocol,
  Prometheus metrics.

## rust-dns and dnsmasq

dnsmasq is an excellent small forwarder and DHCP server. rust-dns covers the
DNS side of it and adds what you need once DNS is something several people
or scripts change.

| | rust-dns | dnsmasq |
|---|---|---|
| Change records | web console, REST API; live at once | edit files, then reload (SIGHUP) or restart |
| API | REST + OpenAPI 3.1, scoped tokens | none (D-Bus for a few operations) |
| Users and permissions | users, TOTP MFA, per-zone roles, audit log | none |
| Records that expire on their own | yes (`expires_in` / `expires_at`) | no |
| Per-record TTL | yes, plus forwarding cache TTL caps | one TTL for local answers (`local-ttl`) |
| DNSSEC | signs your zones | validates answers only |
| Hot standby / replication | built in | no |
| DNS over TLS / HTTPS | yes | no |
| Live view of queries and changes | yes | log file |
| Uses several CPU cores | yes | single-threaded |
| DHCP, TFTP, router advertisements | **no** | yes |

If you need DHCP, keep dnsmasq for DHCP and let rust-dns answer DNS.

## Benchmarks

rust-dns and dnsmasq 2.90 answering the same 1,000 local names, measured
with dnsperf 2.10 (UDP, 16 clients, 500 queries in flight; 80% existing
names, 10% NODATA, 10% NXDOMAIN). Each server was pinned to its cores and
dnsperf to 4 other cores, in a Linux 6.18 arm64 container (8 vCPUs) on an
Apple M3 Max. Median of 3 runs of 15 seconds each:

| Server cores | rust-dns | dnsmasq |
|---|---|---|
| 1 core | 46,000 queries/s | **61,000 queries/s** |
| 4 cores | **126,000 queries/s** (1.3 ms average latency) | 62,000 queries/s (2.6 ms) |
| Memory (RSS) | 32–49 MB | 5 MB |

- **On one core, dnsmasq is faster.** It is a small single-threaded C
  program doing very little per query.
- **Given more cores, rust-dns keeps scaling and dnsmasq does not.**
  dnsmasq is single-threaded, so extra cores don't help it. rust-dns answered
  about twice as many queries on 4 cores, at half the latency, and was not
  at its limit there (the 4-core dnsperf client may have been).
- **Over TCP rust-dns answered 79,000 queries/s on 4 cores** (28,000 on one).
  dnsmasq forks a process per TCP connection, and dnsperf over TCP got almost
  no answers from it, so there is no TCP number for dnsmasq.
- **Why it scales:** rust-dns answers from an immutable in-memory snapshot
  of your zones, read without locks, so every core answers on its own. A
  change builds a new snapshot and swaps it in, and no query waits for a
  write. (The forwarding cache and the rate limiters do use ordinary locks.
  Forwarded queries and queries during changes were not part of this test.)

Run it yourself: `scripts/bench-dnsmasq/run.sh <linux rust-dns binary>`
(needs podman or docker). Benchmarks on macOS directly are misleading: the
loopback path caps UDP at a few thousand queries/s for any server.

## Replication and failover

Run one primary and as many standbys as you like. Every standby holds a
full copy of the primary's data and answers DNS on its own.

- **Live.** A standby streams the primary's changes and applies them as
  they arrive, typically within a second. A new standby copies everything
  first, checks the copy, then follows.
- **Exact.** Every change is captured in the same database transaction as
  the data itself, so nothing can be written without being replicated.
  Changes form a hash chain, and each standby re-checks every table
  against the primary on a schedule.
- **Safe when things go wrong.** If a standby's copy ever disagrees with
  the primary, it stops following and keeps serving its last good data
  until an operator rebuilds it with one click. It never quietly repairs
  itself.
- **Failover by hand.** Promote a standby when the primary is gone. If the
  old primary comes back, it sees it was replaced and goes read-only
  instead of competing.
- **Read-only standbys.** Users can sign in to a standby to look around;
  every change is made on the primary. Sign-outs and password changes on
  the primary apply on every standby.

Setup: add a `[follow]` section with the primary's URL and a token to the
standby's config. See [Standby / follow mode](docs/MANUAL.md#standby--follow-mode).

## Quick start

Download a release for Linux or Windows (x86_64 and ARM64; Linux also as a
`.deb`), or build it:

```
cargo build --release
./target/release/rust-dns --init-config rust-dns.toml   # prints a random root password once
./target/release/rust-dns --config rust-dns.toml
```

Open http://127.0.0.1:8053, sign in as `root`, create a zone, add a record,
and ask for it:

```
dig @127.0.0.1 www.example.com
```

The default config serves DNS on port 53, which needs privileges on Linux:
`deploy/install.sh` installs rust-dns as a systemd service with the right
capability, and `deploy/Dockerfile` builds an image.
`rust-dns --print-sample-config` prints every setting, explained.

## The API in one minute

Create a token in the console (*API tokens -> New token*), then:

```sh
TOKEN=rdns_...
API=http://127.0.0.1:8053/rust-dns/api

# Add a record with a 5-minute TTL
curl -H "Authorization: Bearer $TOKEN" -H "content-type: application/json" \
     -d '{"name":"www","type":"A","value":"10.0.0.1","ttl":300}' \
     $API/zones/example.com/records

# Add a record that disappears by itself after one hour
curl -H "Authorization: Bearer $TOKEN" -H "content-type: application/json" \
     -d '{"name":"_acme-challenge","type":"TXT","value":"token-value","expires_in":3600}' \
     $API/zones/example.com/records

# List the records of a zone
curl -H "Authorization: Bearer $TOKEN" $API/zones/example.com/records
```

Every endpoint, with examples you can run, is in the API explorer at
`http://127.0.0.1:8053/rust-dns/docs`; the document itself is at
`/rust-dns/api/openapi.json` (snapshot: [docs/openapi.json](docs/openapi.json)).

## Learn more

- [The manual](docs/MANUAL.md): every feature and setting, security notes,
  resolver features, DNSSEC, TSIG, DoT/DoH, secondary zones, setting up and
  promoting a standby, the API, architecture and testing.
- [plan.md](plan.md): design decisions, the replication design and the
  release gate.
- [CLAUDE.md](CLAUDE.md): house rules for contributors (how every change is
  captured and replicated).

## License

Apache-2.0
