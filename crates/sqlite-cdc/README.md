# sqlite-cdc

A change log for SQLite captured by triggers and chained with hashes, replicated from a leader to followers over JSON/HTTP. In rust-dns it is "changelog v2". It currently runs in shadow mode next to the v1 changelog; see `src/storage.rs` (`attach_cdc`) and `src/replication/tables.rs` (`cdc_tables`).

## Using it

- **Turn CDC on per table:**

  ```rust
  Config::new(vec![TableConfig::new("users").exclude(&["last_login"])])
  ```

  Excluded columns stay local to each node. They are not captured, applied or compared, and an update that only touches them is not a change. Every captured table needs a declared primary key, and the key never changes.

- **Pick how the store gets its connection:**
  - `Store::open(path, cfg, migrate)` owns its writer connection.
  - `Store::attach(path, Arc<Mutex<Connection>>, cfg)` shares a host application's writer connection. Wrap each host write transaction in `host_begin()`, then call `host_finish(&scope, &tx, meta)` before the commit and `host_committed(id)` after it.

- **Choose the mode:**
  - `strict`: a write to a captured table outside a capture scope fails.
  - Lenient (shadow): such a write is counted, the next transaction marks the log `broken` and leaves the host's write alone, and `restart_history()` starts a new history.
  - `temp_triggers`: the triggers live only on the writer connection and are never stored in the file, so an older binary can open the file safely.

- **Mount the protocol:** `server::router(node, RouterOptions { auth, admin })` is a prefix-free axum router. Mount it anywhere and plug in an `Authorizer`, or let the host authenticate in front of it.

## How it works

- **Capture:** triggers are generated from `PRAGMA table_info` and write row images into the same transaction as the data. Values are carried exactly:
  - BLOBs as hex;
  - REALs as their shortest exact decimal (`json_object` keeps only 15 digits, and SQLite's own number parsing isn't exact).
- **Chain:** each transaction stores `hash = blake3(prev ‖ txn)`. The chain starts from a random history id, and every promotion adds an epoch entry with a random nonce.
- **Apply:** a follower applies rows generically and its own triggers capture the result. That capture must equal the received rows byte for byte, which also checks every `before` image. Foreign keys are switched off around replays, because the leader's cascades are already in the log.

## Protocol

These paths are relative to the mount point. rust-dns serves them at `/rust-dns/changelog-api/v2`.

| Route | What it does |
|---|---|
| `GET /snapshot` | Consistent NDJSON snapshot: a header (position, schema, row counts for progress), the rows, the chain, a digest |
| `GET /changes?history&after&hash&schema&min_bytes&max_wait_ms&max_bytes` | Long poll |
| `GET /stream?history&after&hash&schema` | NDJSON push, with the server position and heartbeats |
| `POST /progress` | A streaming follower reports its applied position |
| `GET /clients` | Every follower: position, lag, `up_to_date`. A poll response also carries the server's view of the asking follower. |
| `GET /hashes`, `/schema`, `/status`, `/self-check` | `/self-check` compares the newest logged image of every row with the live row |
| `GET /verify/{table}?at&buckets` and `/verify/{table}/rows` | Bucketed row hashes as of a past transaction |
| `POST /admin/{promote,rejoin,rebootstrap,resume,follow,verify,prune,restart-history}` | Only when `admin` is set |

Errors:

| Status | Error | Meaning |
|---|---|---|
| 410 | `gap` | Same history, rows pruned |
| 409 | `diverged` / `ahead` | Not on this chain |
| 412 | `history` | Another history |
| 409 | `schema_mismatch` | The follower waits and resumes on its own |
| 503 | `broken` | The leader's log is incomplete |

Responses are gzip-compressed when the client asks for it. The client decodes gzip itself, so the crate doesn't switch on reqwest's `gzip` feature for the whole host application.

## Failing loudly

| Failure | Result |
|---|---|
| Row images differ, chain mismatch, wrong history, follower ahead, verify finds differing rows | Persistent halt naming the transaction, table and key, with `options: [rebootstrap, resume]` (resume keeps the data and follows on with every check; not for a former leader) |
| A delete of a row the follower does not have | Skipped with a warning (the outcome is the leader's) |
| A capture trigger dropped or changed, or a table altered while running | Writes and applies are refused until the triggers are regenerated. `/status` `health` lists the problems. |

Nothing is repaired in place. A diverged follower is rebuilt from a snapshot, which takes about 1 s per 100k rows.

## Tests and tools

- **Tests:** `cargo test -p sqlite-cdc`. It covers the core, the protocol over HTTP, and kill -9 of real processes.
- **Example node:** `examples/cdcnode.rs`.
- **Benchmark:** `cargo run --release -p sqlite-cdc --example cdcbench` measures write overhead, catch-up, latency, snapshot and verify.
