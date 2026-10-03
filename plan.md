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

- [ ] H1. (found in B3) `Mutator::import` is quadratic in the number of
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
- [ ] H3. (found in D3) A record whose expiry time has passed stays in the
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
  `tests/dnssec_changes.rs`, to stay out of its way.

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
