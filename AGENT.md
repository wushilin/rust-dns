# House rules for rust-dns

These rules are for every contributor, human or agent. `CLAUDE.md` is a link
to this file. They exist because the changelog is the replication stream: a
standby (follower) rebuilds its data only from it, so a change that is not
in the changelog, is recorded wrongly, or is lost after a crash, is a
divergence. Divergence halts the standby.

## 1. Every change is changelogged

- Every mutation of replicated state is a typed change, recorded **in the
  same SQLite transaction** as the data it changes. There is no write
  without its changelog row, and no changelog row without its write.
- DNS data (zones, records, members, DNSSEC flags, re-signs, serials) goes
  through `mutation::Tx`; each `Tx` write method records its `DnsChange`.
  Accounts, MFA, tokens, TSIG keys, DNSSEC keys and settings go through
  `AuditTx` / `acct_sql::write`, which take a `SecretChange` and return a
  `#[must_use]` receipt; the audit row commits with them.
- Only the mutation module can open a write transaction (`WriteToken`).
  Never add SQL that writes a replicated table anywhere else. All reads go
  through the read-only connections.
- When in doubt, changelog it. The only writes outside the changelog are
  **local bookkeeping**, each listed and classified `Local` in
  `src/replication/tables.rs`: sessions, `last_seen_at`, token `last_used_*`,
  replication state and the replica list, pruning and retention, schema
  migrations. Adding to that list needs a reason in the code comment and in
  the commit message.
- A new table or column must be classified (replicated or local) in
  `src/replication/tables.rs`; the test `every_table_is_classified` fails
  otherwise.

## 2. The changelog is accurate

- A change is a **fact**, not an intent: it records the resulting state
  (whole rows where a row changed), so replaying it reproduces identical
  rows. Never record "user asked to X"; record what X produced.
- Changes are applied by one exhaustive `replay::apply` on both the primary
  (which applies its own change through the same path) and the standby. A
  new kind does not compile until it is handled.
- Offsets are one ordered sequence for DNS and secret changes, so a change
  never refers to something the follower has not seen yet (a user is
  created before a grant that names it). A transaction is never split
  across replication batches.
- The randomized replay test compares the full contents of every replicated
  table between a database and its replay. Keep it covering every kind.

## 3. The changelog is durable and compatible

- SQLite runs with `journal_mode = WAL` and `synchronous = FULL`. Do not
  lower it: losing the last commits on power loss leaves a standby ahead of
  its primary, and it halts.
- The wire format of a stored change (its `kind` tag and fields) never
  changes in place. `tests/fixtures/changelog_payloads.jsonl` holds real
  payloads of every kind; `stored_changelog_payloads_round_trip_byte_for_byte`
  must pass unchanged. **Never regenerate that fixture.** Add lines only for
  new kinds.
- New fields are optional with a default, so an older peer still reads the
  row. A change an older standby cannot apply needs a replication protocol
  bump and a documented upgrade order (standby first).
- Retention removes old rows only by offset and age. Payloads of secret
  changes are scrubbed after `[changelog].account_retention_days`; a
  follower that needs a pruned or scrubbed row gets `gap` and takes a
  snapshot.
- Secret changes (password hashes, TOTP, TSIG and DNSSEC keys) never leave
  through the user-facing changelog API, the websocket or the event bus, and
  never appear in logs or audit detail. The type split (`DnsChange` /
  `SecretChange`) enforces this; keep it that way.

## 4. Followers replicate as soon as possible, and verify periodically

- A standby follows its primary continuously: after a snapshot it
  long-polls `/rust-dns/api/replication/changes?after=<offset>` and applies each
  batch as soon as it arrives, in one transaction that also stores the
  offset. A restart resumes from the stored offset.
- It reconciles periodically (`[follow] reconcile_interval_secs`, default
  one hour): per-table and per-zone checksums against the primary.
- A standby **never writes replicated data by itself**. Every write path is
  closed on it (`WriteGate`, the API's `STANDBY_WRITABLE` allowlist, and the
  console's default-deny controls). Its only writer is the replication apply
  path.
- Any divergence is a bug, never something to repair silently: a reconcile
  mismatch, a change that does not apply, a transaction-id mismatch or a
  standby ahead of its primary puts it in a persistent `halted` state with a
  report file. It keeps serving its last good data and does not follow until
  an operator rebuilds it with `rust-dns --prepare-standby --yes`. Do not add
  automatic re-bootstrapping or self-healing.
- The only automatic snapshot is a gap in the same history (the rows it
  needs were pruned or scrubbed): nothing deviated, the history is just gone.
- Only a fresh database, or one already in this primary's history, may start
  following. Discarding data is always an explicit operator action.

## 5. Rights are checked in one place

- Every permission comes from the table in `model.rs` (`ZonePerm`,
  `GlobalPerm`), checked through the `Caller`: `require`, `has`,
  `require_zone`, `visible_zones`, `ws::View::build`. These apply the API
  token's scope (M1), which only ever removes rights. Never decide access
  from `caller.user` directly (`is_admin`, `owner_id`, memberships): that
  would ignore the scope.
- A new column that older versions do not have and that changes what a row
  means (a token's scope) goes in `optional_columns` (in the table checksum
  only where set), so an older standby halts rather than serving it wrong.
- A process the standby must represent while it runs (N1: a DNSKEY
  rollover) is refused on the primary while a following standby does not
  advertise it (`replicas::VERSION_WITH_FEATURES`, the `+feature` build
  metadata of its version header): the older standby keeps following
  instead of halting. Add a feature name there for the next such case.

## 6. Before a change is done

- Tests prove the change is logged and replays: a unit test on the change
  kind, the replay equality test, and for anything that crosses servers a
  case in `tests/follow.rs`, including the mixed-version test against the
  previous deployed binary (`RUST_DNS_PREV_BIN`, `REQUIRE_PREV_BIN=1`).
- The full gate in `plan.md` passes (fmt, clippy `-D warnings`, all tests
  with BIND tools required, UI tests, OpenAPI snapshot and validator,
  conformance, smoke test, cargo-audit).
- Deploy standby first, then the primary; verify after each host (config
  check, DNSSEC validation of every record, replica `up_to_date`, not
  halted). See the Rollout section of `plan.md`.
