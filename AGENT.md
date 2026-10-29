# House rules for rust-dns

These rules are for every contributor, human or agent. `CLAUDE.md` is a link to this file.

They exist because of how replication works: a standby rebuilds its data only from the replication stream, changelog v2 (`crates/sqlite-cdc`). If a change escapes the stream, is recorded wrongly, or is lost after a crash, the standby diverges, and divergence halts it.

## 1. Every change is captured

- **What captures a write.** Every write to a replicated table is captured by changelog v2's triggers, in the same SQLite transaction as the data. The capture is the row SQLite actually wrote, before and after. There is no write without its log rows, and no log rows without the write.
- **Only one place may write.** Only the mutation module can open a write transaction (`WriteToken`), and every such transaction goes through `Storage::write`, which opens and closes the capture.
  - DNS data still goes through `mutation::Tx`.
  - Accounts, MFA, tokens, TSIG keys, DNSSEC keys and settings go through `AuditTx` / `acct_sql::write`.
  - Both write the v1 changelog too. That is now only the user-facing history (the changelog page, the websocket, the event bus).
  - Never add SQL that writes a replicated table anywhere else.
- **Lenient shadow capture.** In rust-dns the capture is lenient. A write to a captured table outside `Storage::write` is not refused. It is counted, and the next transaction marks the v2 log `broken`, loudly. A broken log means a bug to fix, never something to live with.
- **What is captured.** The captured set is `replication::tables::cdc_tables()`: every replicated table, plus `audit_log`.
  - Per-server columns are excluded per table (`node_columns`).
  - Everything else is local bookkeeping, each listed and classified `Local` in `src/replication/tables.rs`: sessions, login failures, `audit_local` (a standby's own audit events), the v1 changelog, replication state, v2's own tables (`_cdc*`), pruning and retention, schema migrations.
  - Adding to the local list needs a reason in the code comment and in the commit message.
- **Classify new tables.** A new table or column must be classified (replicated or local) in `src/replication/tables.rs`; the test `every_table_is_classified` fails otherwise. A new replicated table needs a declared primary key, and its key never changes.

## 2. The log is accurate

- **Facts, not intents.** The log records what SQLite wrote (whole rows), so applying it reproduces identical rows. Values are carried exactly: BLOBs as hex, REALs as their shortest exact decimal.
- **The follower checks every row.** A follower applies rows generically, and its own triggers capture the result. That capture must equal the received rows byte for byte, which also checks every `before` image. Any difference is a divergence, with one exception: a delete of a row the follower does not have is skipped with a warning (the row is gone either way, so the result is the primary's).
- **The chain.**
  - Transactions form one ordered sequence and are never split across batches.
  - Each one carries `hash = blake3(previous hash ‖ transaction)`. The chain starts from a random history id, and every promotion starts a new epoch with a random nonce.
  - A follower presents its position (history, transaction, hash) on every request.
- **Tests.** The crate's tests and `mutation::replica::tests::changelog_v2_captures_every_change_exactly` replay the log into an empty database and compare every captured table. Keep them covering every write path.

## 3. The log is durable and compatible

- **Durability.** SQLite runs with `journal_mode = WAL` and `synchronous = FULL`. Do not lower it: losing the last commits on power loss leaves a standby ahead of its primary, and it halts.
- **Schema changes.** A follower presents its schema fingerprint; while it differs from the primary's, it is `blocked` (logged with the column differences) and resumes by itself once both run the same schema. A schema change is a startup migration on every node, never a write inside a replicated transaction (refused).
- **Secrets.** The v2 log and snapshots contain secrets (password hashes, TOTP, TSIG and DNSSEC keys): they are served only behind the `replicate` permission, never through the user-facing changelog API, the websocket or the event bus, and never appear in logs or audit detail. The v1 type split (`DnsChange` / `SecretChange`) still keeps secrets out of the user-facing history.
- **The v1 payload fixture.** The v1 changelog's stored payload format is still frozen for the user-facing history: `stored_changelog_payloads_round_trip_byte_for_byte` must pass unchanged. **Never regenerate that fixture.**

## 4. Followers replicate as soon as possible, and verify

- **Following.** A standby streams its primary's log (`/rust-dns/changelog-api/v2/stream`) and applies each batch as it arrives, in one transaction with its new position. A restart resumes from the stored position. A fresh standby first loads a consistent snapshot, verifies every table against the primary, then streams.
- **Verification.** It verifies periodically (`[follow] reconcile_interval_secs`): bucketed row hashes of every table against the primary, as of the same transaction.
- **No local writes.** A standby **never writes replicated data by itself**. Every write path is closed on it: the `WriteGate`, the API's `STANDBY_WRITABLE` allowlist, the console's default-deny controls, and its config root is not synced. Its only writer is the v2 apply path.
- **Divergence halts.** Any divergence is a bug, never something to repair silently: a row that does not match, a chain mismatch, another history, a standby ahead of its primary. It puts the standby in a persistent `halted` state, and the standby keeps serving its last good data.
  - The operator rebuilds it with **Rebootstrap** (console or `POST /replication/rebootstrap`), which replaces all replicated data with a fresh snapshot in one transaction, or offline with `rust-dns --prepare-standby --yes`.
  - Once the cause is understood and fixed, the operator may instead **Resume** it (console, `POST /replication/resume`, or offline `rust-dns --resume-standby --yes`): the halt is cleared, the data is kept, and it follows again from its stored position with every check as before, so a divergence that is still there halts it again.
  - Do not add automatic re-bootstrapping or self-healing.
- **The only automatic snapshot** is a gap in the same history: the rows it needs were pruned, the position is still on the primary's chain, nothing deviated.
- **Who may start following.** Only a fresh database, or one already in this primary's history, may start following. Discarding data is always an explicit operator action.

## 5. Rights are checked in one place

- **Every permission comes from the table in `model.rs`** (`ZonePerm`, `GlobalPerm`), checked through the `Caller`: `require`, `has`, `require_zone`, `visible_zones`, `ws::View::build`. These apply the API token's scope (M1), which only ever removes rights.
- **Never decide access from `caller.user` directly** (`is_admin`, `owner_id`, memberships): that would ignore the scope.

## 6. Before a change is done

- **Tests.** They prove the change is captured and replays: the v2 replay test and, for anything that crosses servers, a case in `tests/follow.rs`.
- **The gate.** The full gate in `plan.md` passes: fmt, clippy `-D warnings`, all tests with BIND tools required, UI tests, OpenAPI snapshot and validator, conformance, smoke test, cargo-audit.
- **Rollout.** Deploy the standbys first, then the primary. Verify after each host: config check, DNSSEC validation of every record, replica `up_to_date`, not halted. See the Rollout section of `plan.md`.
