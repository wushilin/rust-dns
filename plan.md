# Review follow-up plan

From the code review of 2026-10-03 (HEAD 3884ba8). Each step: do, run the
gate, update this file, continue. `wushilin.net` is live and DNSSEC-signed, so
every step must keep answers and signatures valid; nothing here is deployed
until the whole plan has passed the gate.

Gate: `cargo fmt --check`, `cargo clippy --all-targets -D warnings`,
`REQUIRE_BIND_TOOLS=1 cargo test -- --test-threads=1`, UI duration test,
OpenAPI snapshot + validator, conformance (123), smoke-release, cargo-audit.

## Phase A: small correctness fixes

- [x] A1. Catalog rebuilds can overwrite a newer catalog. The DNSSEC re-signer
  (`mutation/mod.rs` `spawn_resigner`), the retry task in `refresh_catalog`
  and `replication/mod.rs` call rebuild without the mutator lock.
  Fix: every rebuild goes through one function that takes the lock; test with
  a concurrent commit.
- [x] A2. `Storage::read_tx` uses manual `BEGIN`/`COMMIT`; a panic in the
  closure leaves the shared connection inside a transaction and every later
  write fails. `with_conn` panics on a poisoned mutex while `write` tolerates
  it. Fix: rusqlite `Transaction` (rollback on drop); one poison policy. Test:
  panic inside a read, then write succeeds.
- [x] A3. `synchronous = NORMAL` can lose the last commits on power loss; a
  standby that already applied them halts (`ahead_of_primary`). Fix:
  `synchronous = FULL` (writes are rare); document.

## Phase B: read-only connection (structure + isolation)

- [x] B1. Second SQLite connection opened read-only (`query_only`) for all
  reads: `with_conn`, `read_tx`, catalog inputs, API reads. The write
  connection is reachable only through `Storage::write` (token) and the
  listed bookkeeping methods. `read_tx` can no longer write. Test: a write
  through the read path fails.
- [x] B2. `AuditTx.conn` no longer `pub(super)`: account writes only through
  `acct_sql` functions that return the `Change` they made (`#[must_use]`),
  so the compiler, not the source-scan test, enforces "no write without a
  change". Keep the scan test as a second line.
- [x] B3. API handlers stop blocking runtime threads on the database during
  long writes: reads use the read connection (WAL: readers don't wait for
  the writer). Account writes run in `spawn_blocking`. Test: API read and DNS
  latency while a long write holds the write connection.

## Phase C: bounded work on the DNS path

- [x] C1. UDP: cap in-flight forwarded queries with a semaphore (config
  `[forwarding] max_inflight`, default 1024); over the cap, answer SERVFAIL
  (TCP) / drop (UDP) and count it. Authoritative answers are not queued
  behind forwards. Test with a stalled fake upstream.

- [x] C2. (owner, 2026-10-03) The per-client rate limit runs after the DNS
  request is decoded. Check "may this client do anything at all" first: the
  limiter is consulted on the source address before parsing (UDP: in the
  receive loop, before a task is spawned; TCP: before reading/decoding each
  query), so a flood costs one hash lookup per packet, not a parse and a
  task. Slip replies (TC=1) need only the 12-byte header and question bytes
  echoed, not a full decode. Test: over-limit packets are never parsed
  (counter), malformed floods are limited too.

## Phase D: cost per change

- [x] D1. Signature window independent of `updated_at`: a per-zone signing
  epoch (`zones.signed_at`, set when signing is enabled and by
  `zone_resigned`), replicated. Inception = epoch - 1h. Existing signed zones
  migrate with epoch = current `updated_at` so the live window does not move.
- [x] D2. Per-RRset signature cache keyed by (zone, canonical RRset bytes,
  window): a change re-signs only the changed RRsets and the two neighbouring
  NSECs. Test: one record change in a 5,000-record signed zone signs O(1)
  RRsets; dnssec-verify / delv still pass.
- [x] D3. Catalog rebuild per touched zone: `execute` knows the touched zones;
  only those are re-read and rebuilt, the rest of the catalog is shared
  (`Arc<ZoneData>`). Full rebuild stays for startup, bootstrap and fallback.
  Test: equality between incremental and full rebuild (randomized).
- [x] D4. Pre-parse record data at catalog build (no text parsing per query);
  skip query-event formatting when nobody subscribes and query logging is off.

## Phase E: shape of the code

- [x] E1. Split `mutation/mod.rs` (2,850 lines): `tx.rs` (Tx, Change, finish),
  `gate.rs`, `ops.rs` (zone/record/member operations), `import_export.rs`,
  `expiry.rs`, `dnssec_ops.rs`; tests next to their module.
- [x] E2. `Change` split by class at the type level: `DnsChange` and
  `SecretChange` inside one envelope, so only `DnsChange` can be published on
  the event bus or returned by the changelog API. Wire format unchanged
  (`kind` tags stay), verified against stored changelog rows and a
  mixed-version follow test.

## Also noted during deployment (small)

- [x] F1. `--check` reports a database as "fresh" when its data is still in
  the WAL (seen on baba2). Read through a normal connection.
- [x] F2. Replica tracking flags `conflict` after two quick restarts of one
  standby. Flag only when an earlier session id comes back.

- [x] G1. (found by the gate, 2026-10-03) `cargo audit` reports a second
  notice besides `paste`: `yoke-derive 0.8.3` was yanked. Lockfile bump to
  0.8.4 (`cargo update -p yoke-derive`; build-time derive crate under idna).
- [x] G2. (found by the gate) `tests/follow.rs`
  `primary_standby_failover_and_rejoin` failed once with a transport error
  from the test's HTTP client right after a server restart (`POST /zones:
  ... Error encountered in a header: Invalid argument (os error 22)`), and
  passed when rerun alone. Looks like a test-client race on macOS, not a
  server bug; not investigated further. Make the test helper retry transport
  errors, or find the cause.

- [x] H1. (found in B3) `Mutator::import` is quadratic in the number of
  records of a zone: every record re-reads and re-checks the zone's records
  (`create_record` -> `records()` + `record_conflict`). Debug build: 1,500
  records 2.8 s, 6,000 records 44 s, all inside one write transaction (the
  write connection is held that long; with B1/B3 reads and DNS no longer
  wait, other writes still do). Fix: validate against an in-memory index
  kept for the transaction.

- [x] H2. (found in D3) Deleting a user clears `zones.owner_id` through the
  foreign key (`ON DELETE SET NULL`) with no zone change, on the primary
  and, by the same cascade, on a standby replaying `user_deleted`. The
  catalog's copy of the zone row keeps the old `owner_id` until that zone
  changes (already so before D3: account writes never rebuilt the
  catalog). Nothing reads `owner_id` from the catalog (permissions read
  storage), so no behaviour depends on it; make it a typed zone change or
  drop the field from the catalog's zone row.
- [x] H3. (found in D3) A record whose expiry time has passed stays in the
  catalog until the expiry sweeper processes it (primary) or the
  `record_expired` change arrives (standby). Before D3 any commit in any
  zone also dropped it as a side effect of the full rebuild. The sweeper
  wakes at the next expiry, so the window is milliseconds on a primary; a
  standby cut off from its primary keeps serving such records (it already
  did while no change arrived). Decide whether a standby should drop them
  by its own clock in memory.
- [ ] H5. (found in H2) `cargo fmt --all` formats every target in
  Cargo.toml, so with the other session's uncommitted `[[test]]` entry it
  also ran over `compat/dnssec/wushilin_net.rs` once (2026-10-03 13:22,
  this session; mtime changed, rustfmt only rewrites whitespace, the file
  is rustfmt-clean now). From then on this session formats its own files
  by name. Owner: check that file is as intended.
- [ ] H4. Another session edited `tests/dnssec.rs` and added
  `tests/dnssec/wushilin_net.rs` (a live `delv wushilin.net DNSKEY` check)
  in the working tree while this plan ran. Left untouched and NOT in these
  commits; the D2/D3 BIND cases went to a new file,
  `tests/dnssec_changes.rs`, to stay out of its way. Status 2026-10-03
  (second session): `tests/dnssec.rs` is clean again; the working tree
  instead has an uncommitted `Cargo.toml` `[[test]] compat_dnssec_
  wushilin_net` pointing at the untracked `compat/dnssec/wushilin_net.rs`
  (queries the live zone through Google's DNS-over-HTTPS). Not staged,
  committed or deleted by this plan (see H5 for the one rustfmt pass over
  it); the gate runs on a clean worktree of each commit, so it neither
  builds nor runs that test. For the owner to decide: commit it (it needs
  the network, so a plain `cargo test` then depends on dns.google), make
  it `#[ignore]`d / opt-in, or drop it.

## Phase P: query pipeline (owner, 2026-10-03; do before phase I)

The owner wants a servlet-filter-style serving layer: handlers chain, and each
can answer, abort (drop/refuse, with logging) or pass to the next one, and can
inspect or rewrite the response on the way back. Phase I features become
filters instead of branches in `dns/handler.rs`.

- [x] P1. Design and build the pipeline; move today's behaviour into filters
  with NO change in answers.
  - Two stages, because admission must stay before decoding (C2):
    - Raw stage (bytes only, synchronous, no allocation on the reject path):
      admission/rate limit (C2), then TSIG verification (needs raw bytes).
      Outcome: continue, or reply/drop immediately.
    - Query stage (decoded request in a `QueryCtx`: client, proto, EDNS,
      cookies, TSIG identity, runtime snapshot, stats, a per-query log/trace
      record): an ordered chain of `Filter`s. A filter gets `ctx` and `next`;
      it may return its own response (answer / NXDOMAIN / REFUSED /
      SERVFAIL), drop the query (UDP: no reply), or call `next` and then
      inspect or replace the response (post-processing: truncation, DO/RRSIG
      handling, rebinding checks, serve-stale on upstream failure).
  - Initial chain, reproducing today: cookies/ACL checks → special queries
    (version.bind/NSID/minimal ANY) → authoritative zones (incl. DNSSEC,
    auto-PTR, AXFR/IXFR routing) → forwarding (cache, open-resolver
    safeguards, in-flight cap C1, upstream) with response finishing
    (EDNS/DO echo, truncation) as an outer filter. The exact order is
    decided from the current code and documented in one place.
  - The chain is built from config at startup and rebuilt atomically on
    reload/settings changes (ArcSwap), so filters can be switched on/off from
    the console without a restart.
  - Every filter has a name; per-filter counters (handled / answered /
    dropped / passed) in `/metrics`; the live query event records which
    filter produced the answer ("source"), which the console shows.
  - Performance: no per-filter heap allocation on the hot path (static
    dispatch or a pre-boxed chain; measure). Authoritative answers must not
    get slower: benchmark before/after (TCP queries/s locally, release build,
    plus a criterion-style micro bench of handle() if cheap) and record the
    numbers here.
  - Tests: the whole existing suite unchanged (answers byte-identical; reuse
    the D-phase approach: compare a large query matrix between the previous
    binary and the new one, UDP and TCP, with and without EDNS/DO, signed
    and unsigned zones, forwarding via a fake upstream); unit tests for chain
    semantics (answer / drop / pass / post-process, ordering, a filter that
    panics does not take down the server — the query gets SERVFAIL and the
    panic is logged).
- [x] P2. Write the Phase I items as filters on this pipeline (each I item's
  text below stays the spec; "filter" is the implementation shape).

## Phase I: dnsmasq-style resolver features (owner, 2026-10-03)

Goal: close the useful gaps to dnsmasq (DHCP excluded), configured from the
web console wherever possible. Every setting follows the forwarding-settings
model: console page + API (`#[utoipa::path]`, strict contract tests), stored
as an audited typed change (`setting_set` / new kinds via `SecretChange` or
`DnsChange` as appropriate), replicated to standbys, applied without a
restart, shown in `/api/status` and `/metrics`. Per-server facts (listener
interfaces) do not replicate. No native alert/confirm/prompt in the UI.
Defaults must not change answers for existing deployments except where noted.

Order: I1-I4 first (core, ~2 days), then I5-I6, then I7, then the rest.

- [x] I1. Override zones (covers conditional forwarding). A zone of type
  `override` (default type stays `authoritative`) with its own upstream list
  and a mode: `transparent` (default: a name+type defined locally is
  answered from the local records, anything else under the zone is forwarded
  to the zone's upstreams) or `static` (missing names answer NXDOMAIN
  locally, for blocking). An override zone with no records = conditional
  forwarding (`server=/abc.com/10.8.0.1`). Rules: never authoritative (no AA),
  never in AXFR/NOTIFY, never DNSSEC-signed, answers never carry AD; served
  only to clients allowed to forward (others REFUSED, like forwarding today);
  longest match wins between own zones and override zones (an override
  `vpn.wushilin.net` under the signed `wushilin.net` must not break the
  parent's NSEC chain: exclude it from signing and document how that looks to
  validators). Wildcards and CNAMEs work; a local CNAME to a forwarded name is
  chased through the zone's upstreams. Per-zone forward cache keys include the
  upstream set. Console: zone type chosen at creation, upstream editor and
  mode on the zone page, a clear "not authoritative" badge. Replicates (zone
  row fields; check mixed-version compatibility with the 3884ba8 binary and
  the current one; bump nothing unless unavoidable). Tests: local answer,
  per-type fallback, static NXDOMAIN, CNAME local→forwarded, per-zone
  upstreams with a fake resolver, REFUSED for disallowed clients, no AA, not
  in AXFR, no AD, longest-match vs a signed parent (delv still validates the
  parent), replication to a standby.
- [x] I2. `domain-needed`: never forward single-label names (no dot except the
  root). Answer NXDOMAIN locally unless an own/override zone has the name.
  Default ON. Console: toggle in Server settings → Forwarding with a short
  explanation (privacy, `wpad` risk). Counter for refused-locally queries.
- [x] I3. `bogus-priv`: never forward reverse lookups for private/special
  ranges (RFC 6303 zones: 10/8, 172.16/12, 192.168/16, 100.64/10 CGNAT,
  127/8, 169.254/16, 0/8, fc00::/7, fe80::/10, ::1, unspecified). Answer
  NXDOMAIN locally unless an own zone or auto-PTR covers the address (own
  reverse zones always win). Default ON. Console toggle + counter.
- [x] I4. Rebinding protection (`stop-dns-rebind`). Default OFF. When on:
  forwarded answers containing private, loopback, link-local, CGNAT, ULA,
  `0.0.0.0` or `::` addresses are refused (REFUSED), counted and logged with
  the name. Never applied to own or override zones. Allowlist of domain
  suffixes (`rebind-domain-ok`, e.g. `amazonaws.com`, `internal`). Console:
  toggle, allowlist editor, "recently blocked" list with counts. Tests:
  blocked answer, allowlisted answer, own zone with a private address
  unaffected, override zone unaffected, CNAME chain ending in a private
  address blocked.
- [x] I5. Serve stale (RFC 8767). Default OFF. When on and every upstream fails
  or times out, answer from an expired cache entry (TTL 30 s, per RFC 8767)
  up to `max_stale_age` (default 1 day). Console toggle + max age + counter
  of stale answers. Tests with a fake upstream that goes away.
- [x] I6. Upstream strategy and health. Strategies: `in_order` (current),
  `fastest` (track latency, prefer the fastest healthy one), `parallel`
  (send to all, first valid answer wins; respect the in-flight cap from C1).
  Health: per upstream latency (EWMA), success/failure counts, last error,
  marked down after N consecutive failures and probed back. Console:
  dropdown + live health table on Server settings. Applies per override zone
  too. Tests with fake upstreams of different speeds and one dead.
- [x] I7. Blocklists. Console page "Blocklists": list URLs (formats: hosts
  file, plain domains, Adblock `||domain^`), refresh interval, on/off per
  list, allowlist, block action (NXDOMAIN or 0.0.0.0/::), per-list counts and
  last refresh status, "test a name" box. Only the list configuration
  replicates; each server downloads and parses the lists itself (outbound
  HTTPS via the existing reqwest/rustls client) and keeps them in memory in
  a compact structure (suffix set), separate from the zone catalog, swapped
  atomically on refresh. Applies to forwarded queries only (own/override
  zones win). Size limits and failure handling (keep the last good copy).
  Tests: each format, allowlist, action, refresh with a local HTTP server,
  memory for 1M entries measured.
- [x] I8. Hosts-file import. "Import hosts file" in the Import/Export dialog:
  paste or upload `/etc/hosts`-format text, choose the target zone (names
  outside it are listed and skipped), preview, import in one transaction
  (same merge/replace modes as JSON import). Tests: parsing (comments,
  multiple names per line, IPv6), preview, transaction rollback on error.
- [x] I9. Filter record types from forwarded answers (`filter-AAAA`,
  `filter-rr`). Console multi-select of types; answer NODATA for a filtered
  type. Default empty. Tests.
- [x] I10. EDNS Client Subnet on forwarded queries (`add-subnet`). Default OFF;
  console toggle + prefix lengths (IPv4 /24, IPv6 /56 defaults); never for
  clients in private ranges unless chosen; cache key includes the subnet
  scope returned. `add-mac` is out of scope (MACs are only known on the same
  LAN segment). Tests with a fake upstream that echoes the option.
- [x] I11. Follow interfaces (`bind-dynamic` / `interface=`). Listener choice
  by interface name (per server; does not replicate), console shows current
  addresses per interface; sockets re-bound when addresses appear/disappear
  (poll or netlink on Linux; poll elsewhere). Replaces the `run.sh` ens5/eth0
  rewrite. Tests: unit for the address diffing; integration where possible.

- [x] J2 (done as L1). (found in I11) Interfaces are polled (`interface_poll_secs`,
  default 5 s), not followed through netlink: a new address is served
  within one interval. Netlink (Linux) would make it immediate.
- [x] J3. (found by the P1 gate) The unit test `api::proxy::tests::
  v1_split_across_segments` hung for 17 minutes once in the gate while
  other local load (dnsperf, the equivalence script) ran: its spawned
  client's `connect` evidently failed (only the test's LISTEN socket
  remained) and the test waited on `accept` without a timeout. Passed on
  rerun and 5/5 alone. Fixed: the three proxy tests' `accept` is bounded
  (10 s), so such a failure fails instead of hanging. Same gate run:
  `tests/forwarding.rs` `tcp_fallback_answers_are_truncated_for_udp_
  clients` failed once with AddrInUse: its fake upstream binds a free UDP
  port and then TCP on the same number, which another process had; the
  helper now retries with another port.

## Phase K: console editability (owner, 2026-10-03)

- [x] K1. (found on baba2) The standby's Blocklists "Save and apply" looked
  savable: write controls were disabled by a hand-kept selector list
  (`WRITE_SEL`) that phase I buttons never joined (the server refused, no
  data risk). Now structural: default-deny for every button / submit /
  `[data-action]` / `[data-perm]` in the page, dialogs and slide-over; a
  control works on a standby only when marked `data-ro-ok` (or is a close /
  copy control). `api()` refuses on a standby any non-GET request not in the
  server's allowlist, published as `GET /status`
  `replication.standby_writable` (from `STANDBY_WRITABLE`). Allowlist +
  `POST /blocklists/refresh` and `POST /blocklists/test` (in-memory, this
  server only). Tests: `api::ui_tests::*`, `api::tests::
  status_publishes_the_standby_allowlist`, `tests/ui/access.test.js`.
- [x] K2. Editability follows every reason the server refuses: each write
  control declares its permission (`data-perm` + `data-zone`), decided from
  the caller's `GET /users/{me}/rights` (the server's permission table);
  object state via `data-block` (own account delete, root account edit by a
  non-root admin, DNSSEC off while a DS is published or cannot be ruled
  out). Test-enforced: every button declares its access, every non-GET call
  site is a real route behind a declared control whose standby flag matches
  `STANDBY_WRITABLE`.

Considered and NOT planned (owner may revisit): validating DNSSEC on
forwarded answers ourselves (several days, subtle; upstreams already
validate), `ipset`/`nftset` (Linux-only, needs CAP_NET_ADMIN, conflicts with
the unprivileged hardening; only for domain-based routing on VPN gateways),
a router-sized footprint (a design property, not a feature).

## Phase L: queued follow-ups (owner, 2026-10-03)

- [x] K3. (found in K1's walk-through) The changelog page on a standby is
  empty: `GET /api/changelog` returns 0 entries there although the standby
  holds the replicated DNS changelog rows. Find out why (row class, the
  visible-zones filter, offsets copied with the primary's ids, or the
  query), fix, test on a local pair (the standby must show the same DNS
  history as the primary; account rows still never shown), browser check.
  Root cause: none of the four. A standby starts from a snapshot, and
  loading it empties `changelog` and continues at the snapshot offset; only
  changes made after that arrive as rows. Class, filter and query were
  right: a standby showed exactly the rows committed after its snapshot
  (baba2: none since its last `--prepare-standby`). Fix: new local table
  `changelog_history` (DNS rows only, display only); at every follow
  session start the standby copies the primary's DNS rows below its first
  own row through the primary's `GET /api/changelog` (paged, idempotent,
  failure only logged); the changelog API, websocket catch-up and status
  bounds read both (history only below the first `changelog` row).
  Replication never reads it (its offsets have holes where account rows
  were, so a promoted standby still sends a snapshot to a standby behind
  its own first row). Cleared by a snapshot load and `--prepare-standby`;
  pruned with the changelog retention.
- [x] L1 (= J2). Watch interface address changes through netlink on Linux
  instead of polling every `interface_poll_secs`; keep polling as the
  fallback elsewhere. Tests: address diffing unit tests; Linux integration
  where possible (CI runs on Linux).
  Done with `libc` only (no new crate): a `NETLINK_ROUTE` socket bound to
  `RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR` under tokio's `AsyncFd`; any
  `RTM_NEWADDR` / `RTM_DELADDR` (or an error, overrun, `ENOBUFS`, malformed
  buffer) wakes the follower, which re-reads with `getifaddrs` and diffs as
  before (one code path for the truth); a full re-read every 300 s anyway.
  Socket open failure -> polling (logged); a later socket error -> polling
  from then on. Non-Linux: polling as before. Found on the way: the shipped
  systemd units (`deploy/rust-dns.service`, `deploy/install.sh`) had
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`; glibc/musl
  `getifaddrs` itself uses netlink, so `[server] interfaces` could not have
  read any address under those units. `AF_NETLINK` added (gate and baba2
  run under processmaster, not these units: not affected).
  Tests: unit `dns::ifaces::tests::netlink_address_messages_wake_the_
  follower` (message parsing incl. padding, errors, truncation), Linux-only
  `the_netlink_socket_opens`, integration `tests/netlink.rs`
  `interface_addresses_are_followed_through_netlink` (server in a private
  network namespace via `unshare -rn` / `unshare -n` as root / `sudo -n
  unshare -n`; `interface_poll_secs = 3600`; an address added to and
  removed from `lo` must be bound and released within 3 s). CI sets
  `REQUIRE_NETLINK_TEST=1` so a skip fails there.
- [x] L2. Test debt from pending.md, made repeatable where possible:
  recovery-code dialog after MFA enrollment, "New recovery codes", users ->
  "Sign this user out everywhere", the MFA enable/disable/regenerate dialogs
  and the "Promoted" result dialog (not covered in K2), live updates through
  a reverse proxy (local nginx in front of the websocket, if nginx is
  available; otherwise document how to check it).
  Repeatable: `e2e::account_dialog_flows` (the calls each dialog makes:
  enable = start + confirm -> 8 distinct codes; "New recovery codes" needs
  a current code, returns 8 new ones, the replaced ones are refused at
  sign-in and a new one works; disable needs a code, sign-in is one step
  afterwards; "Sign this user out everywhere" revokes exactly that user's
  3 sessions, root's stays, the user can sign in again);
  `follow::primary_standby_failover_and_rejoin` now also checks the
  promote result's `notes` (the "Promoted" dialog's list); the contract
  test already validates every response shape strictly.
  Found in the browser walk-through and fixed: the account page said
  "undefined recovery codes left" (it read `recovery_codes_left` from
  `GET /me`, which never had it). `GET /me` now returns
  `recovery_codes_left` (0 when not enrolled); additive OpenAPI change,
  snapshot regenerated.
  Browser (Chrome, local pair, throwaway configs): Enable MFA dialog (QR,
  manual entry, code) -> recovery codes dialog -> account page "8 recovery
  codes left"; "New recovery codes" -> new codes dialog; Disable MFA:
  wrong code shows "invalid code", a valid one disables; Users -> Edit ->
  "Sign this user out everywhere" -> "Revoked 3 session(s)"; standby ->
  Promote (two-click, force while the cached status said reachable) ->
  "Promoted" dialog with 4 notes; the promoted node's changelog still
  shows the copied history (K3). No console errors.
  Reverse proxy: nginx is not installed here (no Homebrew nginx), so not
  exercised; the manual check (console through the proxy, a change in a
  second tab appears at once, or a `curl` upgrade request answering 101)
  is in the README next to the proxy examples.
- [x] L3. pending.md cleanup: tick entries that are done (TSIG for
  AXFR/NOTIFY, git repository, static musl build in the release workflow,
  deployment notes, per-zone forwarding via override zones) with a pointer
  to where; keep the rest accurate.
  Done: those five ticked with pointers (the per-zone entry split: forwarding
  done via override zones, auto-PTR toggle / transfer ACL / NOTIFY targets
  still open; the musl entry split: Docker image publishing still open);
  the browser debt ticked (L2) and the proxy entry pointed at the README
  check; K3/L1 recorded; stale "not committed" / "in flight" headings and
  the status line brought up to date.

## Rollout (after everything above passes)

- Build on GitHub; upgrade baba2 first, then gate (new change kinds / columns).
- After phase D (see the Log): replication protocol stays 2, no new change
  kind. New: nullable column `zones.signed_at` (added empty by the
  migration; no data is rewritten) and an optional `signed_at` field in
  `serial_bumped` and in zone rows. Either upgrade order works and was
  tested against the 3884ba8 binary (`a_signed_zone_survives_a_mixed_
  version_pair_and_the_upgrade`); standby first is still preferred: with
  the primary first, the old standby signs by the old rule (its window
  moves with each change, signatures valid) until it is upgraded and the
  zone changes once more. Do NOT downgrade a server after it ran this
  version against a peer that did not: the old binary would include the
  unknown `signed_at` column in its `zones` table checksum, the reconcile
  would differ and the standby would halt.
- After each host: config check must pass (script aborts otherwise), DNSSEC
  delv validation of all records against that host, replica `up_to_date`.

- After E1-E2, G2, H1-H3 (this session; not deployed): still protocol
  2, no new change kind, no new column, no data rewritten. New: index
  `records_zone_name` (created at startup, `IF NOT EXISTS`, local schema:
  an older binary ignores it, so a downgrade stays possible as far as
  this is concerned); the expiry watch on every node (a cut-off standby
  stops serving an expired record by its own clock, in memory); the API
  reads request bodies before answering; deleting a user writes
  `zone_updated` (owner cleared, no serial bump) and `member_removed`
  before `user_deleted`. An old (3884ba8) standby replays those as
  before. Upgrade order: either; standby (baba2) first still preferred.

- After phase P and I (this session; not deployed): replication protocol
  stays 2, no new change kind. Everything new is either a console setting
  (`setting_set` / `setting_cleared` with the new keys `resolver` and
  `blocklists`, values are JSON with serde defaults, unknown fields
  ignored) or a zone row field (`override`, present only for override
  zones, in `zone_created` / `zone_updated` and snapshots). New nullable
  column `zones.override_spec` (added NULL by the migration, nothing
  rewritten), in `compat_columns` (left out of the table checksum, covered
  by the per-zone checksum). Without that classification the 3884ba8
  standby halted at its first reconcile ("table zones: differs"): found by
  the new mixed-version test and fixed before any commit.
  What a 3884ba8 standby does with each (tests `phase_i_settings_keep_an_
  old_standby_following`, `an_old_standby_cannot_represent_an_override_
  zone`, real 3884ba8 binary):
  - resolver settings, blocklists, forwarding override: stored as rows,
    never applied (it has no such features); follows, reconcile ok. Once
    upgraded in place it applies them at startup.
  - override zones: it CANNOT represent them. It applies the zone as an
    ordinary authoritative zone (serving it with AA), the per-zone
    checksum differs and the standby HALTS (diverged), as for any
    divergence. So: upgrade the standby (baba2) first, then the primary
    (gate), and create override zones only after both run this version.
    A standby that halted this way must be rebuilt (`--prepare-standby`)
    after its upgrade: its database has the zone without the type.
  - Do NOT downgrade a server once an override zone exists (the old binary
    would include the unknown column in its table checksum, and serve the
    zone as authoritative).
  Default changes (owner's choice): domain-needed and bogus-priv are ON
  for clients allowed to forward: single-label names and reverse names of
  private ranges (RFC 6303) not covered by own zones / automatic PTR are
  answered NXDOMAIN here instead of being forwarded. Equivalence against
  7f7e547 with the defaults: 141 of 20,743 cases differ, all for
  `7.1.1.10.in-addr.arpa.` (private reverse name, previously forwarded);
  with both switched off: 0 differences. Everything else is off by
  default and changes no answer. Blocklists, once configured, make every
  server download the lists itself (outbound HTTP(S) from gate and baba2).
  `[server] interfaces` (I11) could replace run.sh's ens5/eth0 rewrite of
  `bind` on gate/baba2; not required, owner's decision.

## Log

- 2026-10-03: plan written.
- 2026-10-03: A1 done: build tickets in `Cache` (`ticket()` before the read,
  `store_built` refuses an older build); all rebuild paths share
  `rebuild_catalog`. Test `an_older_build_never_replaces_a_newer_one`.
- 2026-10-03: A2 done: `read_tx` uses a `Transaction` (rolls back on drop and
  on panic); one poison policy. Test
  `a_panic_in_a_read_leaves_the_connection_usable`. Side effect: a test that
  wrote through `read_tx` broke (the hole B1 closes); tests now use
  `Storage::exec_raw` (cfg(test)).
- 2026-10-03: A3 done: `synchronous = FULL`.
- 2026-10-03: C2 done. Finding: the limiter already ran before decoding, but
  after the packet was copied and a task spawned. `DnsServer::admit` is now
  the first step (UDP: in the receive loop; TCP: before decode), then
  `handle_admitted`. Test
  `over_limit_packets_are_refused_at_admission_without_decoding`.
  Gate after phase A + C2: clippy clean, 215 tests pass.
- 2026-10-03: F1 done. Cause: `--check` opened the database with
  `SQLITE_OPEN_READ_ONLY` and turned every read error into "no data"
  (`unwrap_or_default`), so a database whose content it could not read was
  called fresh. Now a normal connection with `query_only = ON` and a busy
  timeout (never creates the file), and an error is reported as an error.
  Tests `check_sees_data_that_is_still_in_the_wal`,
  `check_does_not_call_an_unreadable_database_fresh` (main.rs). Not
  reproduced with baba2's exact conditions (file ownership there is
  unknown to me); the test covers WAL-only data with the writer still open.
- 2026-10-03: F2 done. The tracker counted "source switched twice within
  the window" (two restarts = two switches). Now it keeps the sources seen
  recently (session id; the address for a standby that sends none) and
  flags a conflict only when one of them comes back (A, B, A). The stored
  entry gained `earlier` and lost `switches` (old rows load; unknown fields
  are ignored). Tests `two_quick_restarts_are_not_a_conflict`,
  `two_processes_with_one_id_conflict_but_a_restart_does_not`.
- 2026-10-03: gate after F1/F2: fmt, clippy, 171 unit tests, UI, OpenAPI,
  validator, conformance 123, smoke pass. `tests/follow.rs` failed once
  (G2) and passed on rerun. cargo-audit: `paste` plus a new `yoke-derive`
  yanked notice, fixed (G1).
- 2026-10-03: wire-format fixture written BEFORE any refactor (HEAD d8cbf1c
  code): `tests/fixtures/changelog_payloads.jsonl`, 72 real changelog
  payloads (up to 3 of each of the 27 kinds) taken from the randomized
  replay test's database (`UPDATE_FIXTURES=1`; never regenerate it: it
  stands for rows stored by old versions). Test
  `stored_changelog_payloads_round_trip_byte_for_byte` (deserialize,
  serialize as `append_changelog` does, compare bytes; every kind covered).
- 2026-10-03: B1 done. `Storage` has the write connection and 4 read
  connections (`PRAGMA query_only = ON`; not `SQLITE_OPEN_READ_ONLY`, see
  F1). All reads (`with_read`, `read_tx`, catalog inputs, API) take a free
  read connection and run in their own read transaction; a read started
  after a commit sees it. Bookkeeping stays on the write connection:
  `save_replica`, `prune_*`, `scrub_account_changes`, `backup_to` wait for
  it; `touch_session` and the token `last_used_*` update are skipped while
  a write transaction runs (best effort, so a request never waits).
  `authenticate_token` reads on a read connection and writes separately.
  4 readers rather than 1: not measured; chosen because a snapshot, the
  catalog inputs and `quick_check` hold a connection for their whole
  duration and API requests should not queue behind them. Test databases
  (`open_memory`) are now files in a temp directory (WAL, removed on drop)
  so both kinds of connection see the same data as in production.
  Tests: `a_write_through_the_read_path_fails`,
  `reads_see_committed_writes_and_keep_their_snapshot`,
  `reads_and_request_bookkeeping_do_not_wait_for_a_long_write`.
- 2026-10-03: B2 done. `acct_sql`'s SQL functions are private; the one
  entry is `acct_sql::write(conn, ctx, &Change) -> Written`, and `Written`
  is `#[must_use]` with exactly two exits: `log_into` (primary: queued for
  the changelog) and `replayed` (standby / snapshot). `AuditTx.conn` is
  private to accounts.rs; settings.rs and tsig.rs read through
  `AuditTx::tsig_key` / `has_setting` and write only with `record`.
  `Tx::set_dnssec_key` / `delete_dnssec_key` and `replay::apply` use the
  same entry. replica.rs (the replication writer) gets the connection as
  an explicit closure argument. Limit, stated plainly: SQL is text, so
  accounts.rs (sessions, replica list: local tables) and replica.rs could
  still contain a raw statement against an account table; the source-scan
  test stays as the second line for that. Tests:
  `account_tables_are_written_only_through_write`,
  `only_acct_sql_writes_account_tables`.
- 2026-10-03: B3 done, differently from the plan: instead of wrapping ~30
  call sites in `spawn_blocking` (their closures borrow request state),
  `Storage::write` and the waiting bookkeeping methods run inside
  `storage::blocking` (`tokio::task::block_in_place` on a multi-thread
  runtime worker; a plain call elsewhere). Every write path is covered at
  one point, including ones added later. Test
  `api_reads_and_dns_stay_fast_during_a_long_write` (2 workers, a
  1,500-record import holding the write connection 2.8 s, 6 queued account
  writes): 396 probes, max API read 0.41 ms, max DNS answer 0.11 ms. With
  `blocking` disabled the same test gets 2 probes in 2.8 s (the runtime is
  stalled for the whole import) and fails.
- 2026-10-03: gate after phase B (commit 3365eb2, run on a scratch worktree
  of the commit): all steps pass; 177 unit tests, integration suites
  5/3/4/3/7/10/8/7, conformance 123, cargo-audit only `paste`.
- 2026-10-03: C1 done. `[forwarding] max_inflight` (default 1024, >= 1,
  config file only; shown by `GET /settings/forwarding`). Finding: UDP
  queries already run as one task each, so authoritative answers never
  queued behind forwards; what was missing is the bound. A forwarded
  query takes a slot only after the authoritative lookup and the cache
  missed; over the cap it is not queued but turned away at once (UDP
  dropped, TCP SERVFAIL), counted in `dns.forward_overflow` /
  `rustdns_forward_overflow_total` (gauge `rustdns_forward_inflight`), one
  warning a minute. A counter with an RAII guard rather than a semaphore,
  so a reload can change the cap. Test
  `forwarding_is_capped_and_authoritative_answers_do_not_wait`
  (tests/forwarding.rs: stalled upstream, cap 4, 12 queries: 4 in flight,
  8 dropped, TCP SERVFAIL at once, 20 authoritative answers each under
  500 ms, slots freed after the timeout). OpenAPI snapshot refreshed.
- 2026-10-03: gate after phase C (commit af48568): all steps pass; 177 unit
  tests, forwarding suite 8, conformance 123, cargo-audit only `paste`.
- 2026-10-03: D1 done. `zones.signed_at` (nullable, last column) is the
  signing epoch; `Zone::signing_epoch()` = `signed_at` or, when empty,
  `updated_at` (the old rule). The migration only adds the column: an
  already signed zone keeps exactly the window it was served with (not
  "epoch = updated_at written at migration" as planned: writing it would
  change the per-zone JSON and a standby must not write replicated data by
  itself; leaving it empty gives the same window with no write). The
  primary pins it at the zone's next serial bump (to the old change time),
  sets it to the commit time on a re-sign and when signing is turned on,
  clears it when signing is turned off. It replicates in zone rows and in
  `serial_bumped.signed_at` (the whole new value, present in every bump of
  a signed zone, so a standby that missed it converges at the next
  change); `zone_resigned` is unchanged. No protocol bump. `signed_at` is
  in NO checksum (table: `compat_columns`; zone: stripped): a mismatch
  halts a standby, and in a mixed pair the values legitimately differ.
  Consequence, stated plainly: a wrong `signed_at` on a standby is not
  detected by reconcile; it would only give that standby another (valid)
  signature window, and the hour-based fallback still protects against
  expiry. Tests: `the_signature_window_survives_the_upgrade_and_ordinary_
  changes` (frozen copy of the old formula vs the new one on the same
  row; pin; re-sign; off/on; replay), `migrate_adds_the_signing_epoch_
  empty`, `checksums_do_not_cover_the_signing_epoch`, and with the real
  previous binary (3884ba8, `RUST_DNS_PREV_BIN`; skipped without it unless
  `REQUIRE_PREV_BIN`): `a_signed_zone_survives_a_mixed_version_pair_and_
  the_upgrade` (both upgrade orders, in place on the old databases,
  changes while mixed, reconcile ok at every step, never halted,
  `dnssec-verify` on both servers, window unchanged at each upgrade).
- 2026-10-03: D2 done. Signatures are kept per RRset under SHA-256(public
  key, exact signed octets: RRSIG fields with key tag, signer, inception,
  expiration; owner, type, TTL and canonical RDATA of the RRset); a build
  takes them from the zone's previous signed view and signs only what is
  missing. Counter `rustdns_dnssec_signatures_total`. Tests:
  `signatures_are_reused_only_for_identical_signed_octets` (TTL, window,
  key, default TTL all miss), `one_change_in_a_large_signed_zone_signs_a_
  few_rrsets`, `tests/dnssec_changes.rs` (BIND: dnssec-verify of the AXFR
  and delv for a changed record, an unchanged one, a wildcard, NXDOMAIN
  and NODATA after each change; exact signature counts). All signature
  checks validate with ring / BIND, none compares bytes.
- 2026-10-03: D3 done. The zones to rebuild derive from the committed
  changes (`Change::catalog_zone`, exhaustive); `Catalog::with_zones`
  replaces those zones in the current catalog and shares the rest; the
  reverse index is shared when the touched zones contribute the same
  entries, else derived again from all zones by the same function a full
  build uses. Incremental builds run only under the mutator lock
  (`execute` and the standby's `replica_write`); full builds keep using
  tickets; `Cache::apply` documents why no delta can be lost. Snapshot
  loads, promotion, the re-sign timer, startup and any failed incremental
  build do a full build. Behaviour changes: automatic PTR answers list
  owners in zone/record-id order; a transaction without DNS changes
  (members) no longer rebuilds anything; see H2, H3. Tests:
  `incremental_catalog_builds_equal_full_builds` (3 seeds x 260 random
  operations: zones incl. parent/child and a reverse zone, delegations,
  DS, wildcards, DNAME, shared addresses, import, expiry, DNSSEC
  on/off/new key/re-sign; compared with a full build after every step,
  every signature verified; then real expiry, reaping, delete+recreate,
  empty zone delete), `a_standby_keeps_its_catalog_current_per_zone`
  (same on the apply path, also equal to the primary's catalog),
  `incremental_builds_apply_to_the_current_catalog`. Sensitivity checked
  by hand: dropping the deltas of `serial_bumped` and `record_updated`
  makes the equality test fail at step 22.
- 2026-10-03: D4 done. Records are converted to wire form once at catalog
  build (`cache::Rec`, also the SOA and the apex NS set); a query clones
  the prepared record and sets the owner name. Query events (answer
  summary and strings) are not built when nobody subscribes to the query
  feed (`Bus::has_query_subscribers`; the query log is a subscriber).
  Tests: `records_are_converted_once_at_build`,
  `query_subscribers_are_counted`.
- 2026-10-03: measured (debug build, this Mac, 2 signed zones x 5,000
  records, test `one_change_in_a_large_signed_zone_signs_a_few_rrsets`):
  before, every change did a full build: 10,000 record rows read, 20,008
  signatures, 1.17 s. After: a change reads the 5,000 rows of its own
  zone (not O(1): the touched zone is still read and converted whole) and
  signs 4 (new name), 2 (changed record) or 2 (removed name) RRsets;
  whole operation 0.27-0.30 s; the other zone is not read or rebuilt.
  Not measured in a release build.
- 2026-10-03: STOPPED HERE at the owner's request, after phase D. Done and
  committed: F1, F2, G1, B1-B3, C1, D1-D4 (A1-A3, C2 earlier). Next
  unchecked item: E1 (split `mutation/mod.rs`), then E2; also open: G2,
  H1-H4. Context for whoever continues: (1) E1/E2 must keep
  `tests/fixtures/changelog_payloads.jsonl` passing unchanged (never run
  `UPDATE_FIXTURES`); payloads written since D1 may also carry
  `signed_at` in `serial_bumped` and zone rows (optional, skipped when
  empty). (2) After B2 the natural E2 split is: `acct_sql::write` takes
  the secret half. (3) The gate was run on a scratch `git worktree` of
  each commit; the mixed-version test needs the 3884ba8 binary in
  `RUST_DNS_PREV_BIN`. (4) See H4: another session has uncommitted edits
  in tests/dnssec.rs; stage files by name, not `git add -A`.
- 2026-10-03: gate after phase D. First run (commit 3ca6060) failed one
  existing test, `resign_bumps_the_serial_and_keeps_validating`
  (tests/dnssec.rs): it made a re-sign due by backdating `updated_at`
  only, and since D1 the window comes from `signed_at`. Test fixed to
  backdate the epoch (commit 4501db8); no server code changed. Second run
  on 4501db8: all steps pass; 187 unit tests, integration suites
  5/3/1/4/4/8/10/8/7 (follow includes the mixed-version test with
  `REQUIRE_PREV_BIN=1`), conformance 123, cargo-audit only `paste`.
  An operator note follows from the same fact: backdating or editing
  `updated_at` by hand no longer triggers a re-sign.
- 2026-10-03 (second session): H2 done, as typed changes. Findings: (1)
  the zones checksum covers `owner_id`, and primary and standby normally
  agree (same cascade on `user_deleted`); (2) but a standby whose config
  root has the name of an ordinary primary user keeps that account on
  `user_deleted` (local root) and so kept its tokens, memberships and
  owned zones: tables `api_tokens`, `zone_members`, `zones` differed and
  reconcile would halt (reproduced in a test). Fix: `DELETE /users/{id}`
  first runs `Mutator::release_user` (one DNS transaction: per owned zone
  a `zone_updated` that only clears `owner_id`, no serial bump,
  `updated_at` and signing window kept; per membership a
  `member_removed`), then the account transaction. The catalog follows
  (the changes name the zone), the changelog API shows them. Two
  transactions: if the second fails the user stays without zones. And
  `acct_sql` `user_deleted` on a standby that keeps the account as its
  root now removes what the primary's foreign keys removed (its tokens,
  memberships, ownership), so a delete written by an older primary (no
  release) does not halt it either. No new change kind, no wire change.
  Tests `deleting_a_user_releases_its_zones_as_changes`,
  `a_namesake_root_follows_a_delete_without_release` (both fail without
  the fix: checksum view differs). Also seen once: `tests/e2e.rs`
  `json_import_and_record_paging` panicked in ureq (response.rs:389)
  while run with default test threads; passed alone. Probably G2's class.
- 2026-10-03: H3 done: every node (a standby too) stops serving a record
  at its expiry time by its own clock, in memory, never writing.
  `ZoneData::next_expiry` (earliest `expires_at` served); the task
  `Mutator::spawn_expiry_watch` sleeps until the catalog's earliest
  expiry (+1 ms; woken by every stored catalog, at least every minute)
  and `drop_expired_in_memory` rebuilds just the zones that serve a due
  record, incrementally under the mutator lock (the D3 rule). A signed
  zone's NSEC chain and signatures follow the served data (signed by the
  node, D2 reuse for the rest); the serial does not change until the
  primary's `record_expired` + bump arrive (on a cut-off standby: never,
  so its zone transfers carry the old serial with the record gone; that
  is the served truth). The primary still records the expiry through its
  sweeper as before. No storage, wire or protocol change. Tests:
  `expired_records_leave_the_catalog_at_their_expiry_without_a_commit`
  (gate closed, signed zone, equals a full build, other zones shared,
  nothing written) and tests/follow.rs
  `an_expired_record_stops_being_served_on_a_cut_off_standby` (real
  primary + standby, signed zone, primary stopped before expiry: NXDOMAIN
  / NODATA by its own clock, head and serial unchanged, `dnssec-verify`
  of the AXFR and `delv` negative answers fully validated; fails without
  the watch). follow/dnssec/dnssec_changes/e2e suites pass with BIND
  tools and the 3884ba8 binary.
- 2026-10-03: H1 done. Cause: every imported record read the zone's
  whole record list (`records()`) twice (import's pre-check and
  `create_record`) and cloned it in `record_conflict`. The record rules
  and the duplicate check only look at the same name, so checks now read
  `records_named(zone, name)` through a new index `records_zone_name ON
  records(zone_id, name)` (created by the migration, `IF NOT EXISTS`;
  local schema, not data: nothing replicated or checksummed changes; an
  older binary ignores it). Still one transaction. Debug build: 6,000
  records 44 s -> 0.63 s (again, all skipped: 0.08 s; replace: 0.87 s).
  Test `a_large_import_is_linear` (bound 5 s each, CNAME rule still
  applied inside an import). The B3 latency test now imports 15,000
  records (1,500 took only 0.16 s, under its 400 ms floor) and its writer
  check is relative (`>= half the import`), since post-commit work grows
  with the import.
- 2026-10-03: G2 done; cause found and fixed in the server. Reproduced
  (about 7 in 400 POSTs, connection per request): when the API answers
  before reading the request body (401 from auth, 403, the standby's /
  fenced server's 409 `read_only_standby`, axum's 405), hyper closes the
  connection with body bytes still arriving; the kernel answers those
  with a TCP reset and the client can lose the response it was reading
  (macOS: `EINVAL` "Error encountered in a header", or a ureq panic
  "returning stream to pool" / "failed to read exact buffer"). That is
  the failover test's case: POST /zones to a freshly restarted fenced or
  standby server, asserting 409. Also explains the one-off
  `json_import_and_record_paging` panic (its import-bind 404/405 check).
  Fix: middleware `read_body_first` on /api (outermost) reads the whole
  body (same 16 MiB limit as before, JSON 413 above it) before anything
  answers; handlers buffered every body anyway and login is
  unauthenticated already, so pre-auth buffering adds no exposure. Test
  tests/e2e.rs `early_answers_reach_the_client_and_large_bodies_are_
  refused` (400 pooled + 1,200 single-connection POSTs answered 401: none
  lost; fails in about half the runs without the middleware, 8/8 passes
  with it; 413 is JSON).
- 2026-10-03: E1 done (pure move, no behaviour change). `mutation/mod.rs`
  (3,866 lines) is now: `mod.rs` (WriteToken, Rebuild, MutationError,
  Mutator with `execute` / `refresh_catalog` / catalog builds, 420
  lines), `tx.rs` (Change, Tx, `finish`, catalog_zones), `gate.rs`
  (WriteGate), `ops.rs` (zone/record/member operations and their
  validation helpers), `dnssec_ops.rs`, `expiry.rs`, `import_export.rs`
  (export types, import, export), each with its tests, and
  `test_support.rs` (cfg(test): helpers shared with `replica`'s tests).
  Public paths unchanged (`pub use` in mod.rs). Checked mechanically: the
  multiset of non-blank lines of the old file equals that of the new
  files except for module/`use` lines, `impl Mutator {` openers, three
  `pub(super)`s on Tx (conn, new, finish), helper visibility and one
  `ops::` path; same 191 unit tests.
- 2026-10-03: gate on abe2a71 (H2, H3, H1, G2; worktree of the commit,
  `REQUIRE_BIND_TOOLS=1 REQUIRE_PREV_BIN=1`, 3884ba8 binary): all steps
  pass; 191 unit tests, integration suites 5/3/1/5/5/8/10/8/7 (e2e and
  follow one test more each), conformance 123, cargo-audit only `paste`.
- 2026-10-03: E2 done. `Change` is an envelope `Change::Dns(DnsChange)` /
  `Change::Secret(SecretChange)`, both inner enums keep `#[serde(tag =
  "kind")]` and every variant as it was. Serialization is `untagged`
  (the envelope adds nothing: byte-identical, fixture test unchanged and
  passing; fixture file untouched); deserialization is by hand: try the
  DNS family, then the secret one, and report the error of the family
  the kind belongs to. What the types now enforce: `acct_sql::write` and
  `AuditTx::record` take a `SecretChange` (the runtime "not an account
  change" error is gone: a DNS change cannot be passed); the event bus
  takes only a `DnsEvent`, constructible only in `mutation` and only
  with a `&DnsChange` (`Tx::finish` and the standby's apply make them
  with `if let Change::Dns(d)`); the changelog row's class column is the
  envelope variant. Not type-level, stated plainly: the changelog API and
  websocket history read stored rows filtered by that class column (the
  rows are JSON; old rows may predate structured changes), as before.
  Tests: `stored_changelog_payloads_round_trip_byte_for_byte` (unchanged),
  new `stored_kinds_read_into_their_family` (every fixture kind lands in
  the family whose class its stored rows carry; error messages for an
  unknown kind and missing fields). No wire, storage or protocol change
  (replication protocol stays 2).
- 2026-10-03: final gate on c9b252b (E2 HEAD; clean worktree of the
  commit, `REQUIRE_BIND_TOOLS=1 REQUIRE_PREV_BIN=1`, 3884ba8 binary): all
  steps pass; 192 unit tests, integration suites 5/3/1/5/5/8/10/8/7
  (mixed-version follow test, cut-off standby expiry test and the G2
  early-answer test included), UI, OpenAPI snapshot fresh, validator,
  conformance 123, smoke, cargo-audit only `paste`. Open: H4 (owner's
  decision), H5 (owner to look at compat/ after one rustfmt pass).
  Nothing pushed, tagged or deployed.
- 2026-10-03: Phases E, G2, H1-H3 verified by the coordinating session: full
  gate on 6d7e5a2 in the clean worktree passes (192 unit + all integration
  suites incl. mixed-version vs 3884ba8 with REQUIRE_BIND_TOOLS/REQUIRE_PREV_BIN,
  conformance 123, smoke, audit only `paste`). Not deployed.
- 2026-10-03: Phase I added at the owner's request: dnsmasq-style resolver
  features (DHCP excluded), configured from the web console where possible.
  Order: I1-I4, I5-I6, I7, then I8-I11. Not started. H4/H5 still await the
  owner; deployment of the finished work is a separate decision.
- 2026-10-03: Owner's order of work: finish the work (phase P, then all of
  phase I), add unit tests and make sure everything works as intended, and
  only then deploy (expects compatibility; still verify mixed-version with the
  3884ba8 and 6d7e5a2 binaries before deploying). Phase P (query pipeline,
  servlet-filter style) added before phase I.
- 2026-10-03 (phase P session): P1 done (commit 93ddd9d). `src/dns/
  pipeline.rs` (stages, `QueryCtx`, `Filter` enum, runner, finish stage,
  the chain order table in the module docs) and `src/dns/filters.rs` (one
  method per filter, code moved verbatim from `handler::answer`). Raw
  stage unchanged in `handler.rs`: `admit` (C2) then TSIG verify/strip,
  query stage, TSIG signing of the reply. Chain: edns, request, special,
  transfer, authoritative, recursion, [open_resolver], forward. Static
  dispatch (enum + `Vec<Filter>` in `Runtime`, so it is rebuilt and
  swapped with the runtime on reload / console changes; a switched-off
  filter is absent); post-processing is a second pass over the filters
  that passed, innermost first (no recursion, no boxed futures);
  `catch_unwind` around the chain: a panicking filter answers SERVFAIL
  (id + question echoed), is logged with the filter name and counted.
  Per-filter counters `rustdns_filter_queries_total{filter,outcome}`,
  `/api/status` `pipeline` (chain in effect with counters), query events
  carry `filter` (console shows it under Source). Tests:
  `filters_answer_pass_and_post_process_in_order`,
  `a_dropping_filter_sends_nothing`, `a_panicking_filter_answers_
  servfail_and_the_server_goes_on`, `the_default_chain_and_its_counters`;
  C2 test unchanged and passing; all suites pass.
  Equivalence: new `scripts/equivalence.py` / `equivalence-local.sh`
  (BASE NEW): one seeded database copied for both servers, deterministic
  fake upstream per server, 20,743 query pairs (110 names x 19 types x
  EDNS/DO x UDP/TCP, EDNS/cookie/NSID shapes, flags, classes, opcodes,
  malformed and garbage packets, forwarding incl. TC/fail/timeout,
  AXFR/IXFR of 7 zones, TSIG good/bad/badtime/truncated, a rate-limit
  burst sequence, cookies_required). Normalised only: RRSIG signature
  bytes, server cookie bytes, TSIG time/MAC (248 MACs verified). Result
  7f7e547 vs 93ddd9d (release): 0 differences, 16,633 byte-identical.
  Self-test (`--self-test`) proves it reports perturbed cases. Seen by the
  script: 3884ba8's rate-limit replied/dropped sequence varies run to run
  (C2 made it deterministic); the forward cache keeps the letter case of
  the query that filled it (unchanged behaviour, noted).
  Throughput (release, `scripts/bench-tcp-local.sh`, dnsperf -m tcp, 16
  clients, 8 s, alternating runs): 7f7e547 334.5k/341.8k/335.6k/326.4k
  q/s (mean 334.6k), 93ddd9d 338.1k/342.5k/326.3k/324.0k (mean 332.7k):
  no measurable difference (-0.6%, within run-to-run noise of +-2%).
- 2026-10-03 (phase P session): P1 gate on 104b216 (clean worktree,
  `REQUIRE_BIND_TOOLS=1 REQUIRE_PREV_BIN=1`, 3884ba8 binary): fmt, clippy,
  196 unit tests, suites api_contract 5, dnssec 3, dnssec_changes 1, e2e
  5, follow 5 (mixed-version included), forwarding 8, hardening 10,
  openapi_spec 8, tsig 7, UI, OpenAPI, validator, conformance 123, smoke,
  cargo-audit only `paste`. Two environmental flakes on the way, see J3
  (a hung proxy unit test, an AddrInUse in a forwarding test helper; both
  passed on rerun; both made robust).
- 2026-10-03 (phase P session): P2 / I1-I11 done as filters (one commit:
  the items share `src/dns/filters.rs`, `pipeline.rs`, `mod.rs` and the
  settings plumbing, so per-item commits would not each build; recorded
  here instead). Design:
  - Chain (`pipeline.rs` table): edns, request, special, transfer,
    authoritative, override, recursion, [domain_needed], [bogus_priv],
    [filter_types], [blocklist], [open_resolver], [rebind (post)],
    [serve_stale (post)], forward. Bracketed = only in the chain when on.
  - Settings: one console setting `resolver` (`ResolverSettings`: I2-I6,
    I9, I10; absent = defaults) and one `blocklists` (I7), both through
    `AuditTx::set_setting` / `clear_setting` (typed `setting_set` /
    `setting_cleared`, audited `settings.<key>.update/reset`), applied by
    `DnsServer::set_resolver` / `set_blocklists`, on a standby by
    `load_console_settings` after replicated account changes. API
    `GET/PUT/DELETE /settings/resolver`, `GET/PUT /blocklists`, `POST
    /blocklists/refresh`, `POST /blocklists/test`, `POST
    /zones/{zone}/import/hosts`; zone create/update take `override`.
  - I1: `zones.override_spec` (JSON of `ZoneOverride {mode, upstreams}`),
    `Zone.overrides` (`override` in JSON). Catalog keeps override zones but
    never signs them, gives them no auto-PTR entries; `Lookup::Override`
    for names whose longest zone is an override zone; CNAME/DNAME chases,
    glue and DS parent lookups use only authoritative zones
    (`find_auth_zone`); AXFR/IXFR and NOTIFY skip them; DNSSEC cannot be
    turned on for them. Filter `override`: ACL (REFUSED), local data via
    `lookup_override` (non-AA, no RRSIG), local CNAME to elsewhere chased
    through the zone's upstreams, transparent -> zone upstreams (cache
    scope = hash of the upstream set, AD cleared), static (or no
    upstreams) -> local NXDOMAIN/NODATA with SOA. Export/import carry the
    `override` object (new zones only).
  - I4 rebind: post filter on `forward` answers (relayed and cache hits),
    REFUSED, per-name log of the last 100 names. I5: the forward cache keeps
    expired entries while serve-stale is on (`Caps.stale_secs`), post
    filter replaces an upstream-failure SERVFAIL with the stale entry, TTL
    30. I6: `forward::Health` (EWMA latency, counts, last error, down after
    3 failures, one probe per 30 s), `forward_via` with in_order (exactly
    the old order; health only recorded), fastest, parallel (`select_ok`,
    one in-flight slot per query). I7: `src/blocklist.rs` (per-line format
    detection, sorted `Vec<u64>` of keyed SipHash per list, suffix match,
    allowlist, download task with size/time limits keeping the last good
    copy, `ArcSwap` of the compiled set). I8: `parse_hosts` + `Mutator::
    import_hosts` (one transaction via the JSON import). I9: pre filter,
    NODATA. I10: ECS option built from the decoded request, reply
    re-encoded for the client (our option removed, the client's own EDNS),
    cache scope per client subnet, scope-0 answers shared. I11:
    `dns/ifaces.rs`, `getifaddrs` polling, per-address listeners aborted
    when the address goes; status in `/api/status` `listeners.interfaces`
    and on the dashboard.
  - Console: Server settings -> Resolver card (toggles, strategy,
    upstream health incl. override zones, rebind allowlist and recent list,
    stale, filtered types, ECS); Blocklists page (lists, status, allowlist,
    action, interval, download now, test a name); new-zone type selector,
    override badge and "Override settings" dialog on the zone page;
    Import/Export -> Hosts file tab (preview, import). Browser-checked in
    Chrome on a throwaway local instance: pages render, saves work, hosts
    preview/import works, no console errors.
  Tests: `tests/resolver.rs` (`domain_needed_bogus_priv_and_filtered_
  types`, `rebinding_protection`, `serve_stale_when_every_upstream_fails`,
  `upstream_strategies_and_health`, `edns_client_subnet`, `override_zones`,
  `an_override_zone_under_a_signed_parent` (dnssec-verify of the parent's
  AXFR, delv on parent names; delv on the override name reports a broken
  trust chain, as documented), `blocklists_block_forwarded_names`); unit
  `private_reverse_names`, `special_addresses`, `dangling_cnames`,
  `expired_entries_are_served_stale_within_the_window`, blocklist
  `every_format_parses`, `suffix_matching_and_the_allowlist`,
  `settings_validate`, `a_million_entries_are_compact`,
  `refresh_keeps_the_last_good_copy`, hosts `hosts_files_parse`,
  `hosts_import_is_one_transaction`, ifaces `address_changes_are_diffed`,
  `wanted_interfaces_without_link_local`, `loopback_is_listed`,
  `following_an_interface_binds_its_addresses`; pipeline default-chain
  test extended; follow `phase_i_settings_keep_an_old_standby_following`
  and `an_old_standby_cannot_represent_an_override_zone` (3884ba8);
  conformance.py: 4 override checks (127 total; the local harness seeds an
  override zone under the signed test zone).
  Memory for 1M blocklist entries: 8,000,000 bytes for the set (test
  `a_million_entries_are_compact`), built in well under a second; the
  download text is dropped after parsing.
  Equivalence vs 7f7e547 (release): with domain_needed/bogus_priv off
  (`--new-resolver`) 0 differences in 20,743 cases; with the defaults 141,
  all `7.1.1.10.in-addr.arpa.` (I3, intended).
  Throughput (release, `scripts/bench-tcp-local.sh`, alternating):
  7f7e547 338.8k/339.4k/340.5k/316.3k q/s (the last one while a cargo
  build ran), phase I tree 341.5k/338.2k/351.2k/345.6k: no regression.
- 2026-10-03 (phase P session): full gate on 715aa33 (P1 + phase I;
  clean worktree, `REQUIRE_BIND_TOOLS=1 REQUIRE_PREV_BIN=1`, 3884ba8
  binary): all steps pass. fmt, clippy, 211 unit tests, suites
  api_contract 5, dnssec 3, dnssec_changes 1, e2e 5, follow 7 (both new
  mixed-version tests), forwarding 8, hardening 10, openapi_spec 8,
  resolver 8, tsig 7; UI, OpenAPI snapshot, validator, conformance
  127/127, smoke, cargo-audit only `paste`. This one gate stands for the
  planned checkpoints after I1-I4 and I5-I7 (the items landed in one
  commit, see above). Nothing pushed, tagged or deployed. Still open: J2
  (netlink), H4/H5 (owner). Next step: the owner reviews and deploys
  (baba2 first, see Rollout; create override zones only after both run
  this version).

- 2026-10-03: DEPLOYED d32d67f (GitHub build 31917b02…, smoke-tested) to
  baba2 (dns2) first, then gate (dns1). Each: config check passed, previous
  binary kept as rust-dns.prev, restarted via processmaster. Verified after
  each: delv fully validated 158/158 (all 74 records + extras, UDP and TCP)
  against that host with the static DNSKEY anchor; baba2 `up_to_date` at
  offset 120, lag 0, not halted, no conflict; both at serial 14; Google,
  Cloudflare and Quad9 return AD; single-label names answered NXDOMAIN
  locally (I2 default on), forwarding works. No override zones created yet
  (safe now that both run this version). Next: watch the first automatic
  re-sign (due ~2026-10-04) on the new code.

- 2026-10-03: K1 + K2 done (console editability). Browser walk-through on a
  local primary + standby pair (localhost, throwaway configs, high ports):
  standby admin sees every write control disabled with "Read-only standby:
  make changes on the primary (http://127.0.0.1:18611)", while filters, tabs,
  copy, export, view details, pause, test upstreams, download now, test a
  name, TSIG reveal, session revoke and promote work; forced clicks on
  disabled buttons and `api('PUT', ...)` / `DEL` / `POST reset-mfa` from the
  page console were refused locally with no request sent (network log shows
  only GETs and the allowlisted POSTs). Primary checked as admin, owner,
  editor, viewer, no-access user and root; each enabled control matched
  what the server accepts (sampled 200/201) and each disabled one what it
  refuses (sampled 403/400/409). One mismatch found and fixed during the
  walk: the SOA "Edit" button's zone was in a quoted string (`'${...}'`),
  so it was denied for owners; a test now rejects `${` in quoted strings.
- 2026-10-03: K1/K2 verified by the coordinating session (gate on 1ba0933:
  279 tests, both UI unit tests, conformance 127, smoke, audit only `paste`).
  Not deployed (console change; needs a deploy to reach dns1/dns2). Phase L
  queued: K3 (standby changelog empty), L1 (= J2 netlink), L2 (test debt),
  L3 (pending.md cleanup).
- 2026-10-03 (phase L): K3 done. Reproduced on a local pair: primary 9
  DNS rows, standby 0; after one more change the standby showed exactly
  the 2 new rows. Fixed (see K3); the pair then showed identical pages for
  root and for a viewer, and the standby's changelog page in Chrome listed
  offsets 7-19 and took live rows 20/21 from the primary. Test
  `follow::a_standby_shows_the_primarys_dns_changelog` (paged rows, recent
  page and bounds identical; only DNS kinds; after a restart; after an
  in-place upgrade simulated by emptying the copy). Compatibility: no
  protocol or wire change; new local table created at startup (an older
  binary ignores it); works against a 3884ba8 primary (its
  `/api/changelog` is the same).
- 2026-10-03 (phase L): L1 done (see L1). macOS cannot run the Linux
  parts; compiled and run in LXD container `home:alma8-rust` (x86_64, cargo
  1.92, sources + `cargo vendor` pushed, offline build; `home:dns-test` had
  no toolchain, so it was started, found without cargo, and stopped
  again): ifaces unit tests 6/6, `tests/netlink.rs` passed 4 of 4 runs
  after one fix (as root, `unshare -n`; the first version waited only 5 s
  for a slow debug-build start in the container, so the address could be
  added before the follower's first read; it now waits for the netlink
  line and the first bind, up to 180 s, before changing anything). Negative control in the container (netlink open forced to
  fail -> polling): the integration test fails as intended (address never
  bound within 3 s). Not run: the `unshare -rn` (unprivileged) and `sudo
  -n` paths, and clippy with the CI toolchain on Linux (the container's
  clippy 1.92 flags 3 pre-existing lints elsewhere; none in the new code).
- 2026-10-03 (phase L): L2 done (see L2): test `e2e::account_dialog_flows`,
  promote notes asserted, `GET /me` `recovery_codes_left` (console bug),
  browser walk-through of the five dialogs, proxy check documented (no
  nginx here).
- 2026-10-03 (phase L): L3 done (pending.md).
- 2026-10-03 (phase L): full gate on d8360ba (clean worktree,
  `REQUIRE_BIND_TOOLS=1 REQUIRE_PREV_BIN=1`, 3884ba8 binary): all steps
  pass. fmt, clippy, 218 unit tests, suites api_contract 5, dnssec 3,
  dnssec_changes 1, e2e 6, follow 8, forwarding 8, hardening 10, netlink 0
  (Linux only; run in a container, see L1), openapi_spec 8, resolver 8,
  tsig 7; UI tests, OpenAPI snapshot, validator, conformance 127/127,
  smoke, cargo-audit only `paste`. The K3 checkpoint gate on 993c104 also
  passed (280 tests). Nothing pushed, tagged or deployed. Rollout: still
  protocol 2, no new change kind, no payload change; new local table
  `changelog_history` (created at startup; an older binary ignores it) and
  an additive `recovery_codes_left` in `GET /me`. Either upgrade order;
  standby (baba2) first as usual. After the upgrade baba2's changelog page
  fills from gate at its next follow session start.
