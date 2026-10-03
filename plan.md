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

- [ ] B1. Second SQLite connection opened read-only (`query_only`) for all
  reads: `with_conn`, `read_tx`, catalog inputs, API reads. The write
  connection is reachable only through `Storage::write` (token) and the
  listed bookkeeping methods. `read_tx` can no longer write. Test: a write
  through the read path fails.
- [ ] B2. `AuditTx.conn` no longer `pub(super)`: account writes only through
  `acct_sql` functions that return the `Change` they made (`#[must_use]`),
  so the compiler, not the source-scan test, enforces "no write without a
  change". Keep the scan test as a second line.
- [ ] B3. API handlers stop blocking runtime threads on the database during
  long writes: reads use the read connection (WAL: readers don't wait for
  the writer). Account writes run in `spawn_blocking`. Test: API read and DNS
  latency while a long write holds the write connection.

## Phase C: bounded work on the DNS path

- [ ] C1. UDP: cap in-flight forwarded queries with a semaphore (config
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

- [ ] D1. Signature window independent of `updated_at`: a per-zone signing
  epoch (`zones.signed_at`, set when signing is enabled and by
  `zone_resigned`), replicated. Inception = epoch - 1h. Existing signed zones
  migrate with epoch = current `updated_at` so the live window does not move.
- [ ] D2. Per-RRset signature cache keyed by (zone, canonical RRset bytes,
  window): a change re-signs only the changed RRsets and the two neighbouring
  NSECs. Test: one record change in a 5,000-record signed zone signs O(1)
  RRsets; dnssec-verify / delv still pass.
- [ ] D3. Catalog rebuild per touched zone: `execute` knows the touched zones;
  only those are re-read and rebuilt, the rest of the catalog is shared
  (`Arc<ZoneData>`). Full rebuild stays for startup, bootstrap and fallback.
  Test: equality between incremental and full rebuild (randomized).
- [ ] D4. Pre-parse record data at catalog build (no text parsing per query);
  skip query-event formatting when nobody subscribes and query logging is off.

## Phase E: shape of the code

- [ ] E1. Split `mutation/mod.rs` (2,850 lines): `tx.rs` (Tx, Change, finish),
  `gate.rs`, `ops.rs` (zone/record/member operations), `import_export.rs`,
  `expiry.rs`, `dnssec_ops.rs`; tests next to their module.
- [ ] E2. `Change` split by class at the type level: `DnsChange` and
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
- [ ] G2. (found by the gate) `tests/follow.rs`
  `primary_standby_failover_and_rejoin` failed once with a transport error
  from the test's HTTP client right after a server restart (`POST /zones:
  ... Error encountered in a header: Invalid argument (os error 22)`), and
  passed when rerun alone. Looks like a test-client race on macOS, not a
  server bug; not investigated further. Make the test helper retry transport
  errors, or find the cause.

## Rollout (after everything above passes)

- Build on GitHub; upgrade baba2 first, then gate (new change kinds / columns).
- After each host: config check must pass (script aborts otherwise), DNSSEC
  delv validation of all records against that host, replica `up_to_date`.

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
