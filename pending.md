# Pending work

Status as of 2026-09-27. Deployed to dns-test (musl build, /opt/rust-dns) with everything below. Stages 1 to 3 (log rotation, DNS protocol completeness, console fixes) are implemented. The current workspace has additional Stage 4 changes in progress below.

## TSIG for zone transfers and NOTIFY (2026-09-27, verified)

- [x] RFC 8945 hand-implemented in `src/dns/tsig.rs` (pure Rust: `hmac` + `sha1`/`sha2`, no new dependencies): hmac-sha256 (default), -sha384, -sha512, -sha1 (legacy). Constant-time MAC compare; truncated MACs follow §5.2.2.1 (too short/long = FORMERR, valid but shorter than full = signed BADTRUNC); fudge capped at 300 s.
- [x] Keys in the `tsig_keys` table, written only through `AuditTx` (`tsig.create`, `tsig.update`, `tsig.delete`, `tsig.reveal`; no secret in detail or logs). API (admin, `server_admin`): `GET/POST /api/tsig/keys`, `PUT/DELETE /api/tsig/keys/{name}`, `POST /api/tsig/keys/{name}/reveal`, `GET /api/settings/transfer`.
- [x] Policy: `[transfer].allow` AND (when signed or `require_tsig = true`) a valid key covering the zone. BADKEY/BADSIG unsigned, BADTIME signed with server time; never treated as unsigned. Every AXFR message signed with MAC chaining. `notify_key` / per-target `{ address, key }` sign NOTIFY; responses verified.
- [x] Tests: known-answer vectors from dnspython 2.8 (all four algorithms, request + 2-message chained response), unit error cases, `tests/tsig.rs` end to end, 9 new conformance checks (85/85).
- [x] Interop with BIND 9.20 (`named` as secondary, `dig -y`): multi-message signed AXFR, signed NOTIFY triggers refresh and BIND's signed ack verifies, wrong key refused on both sides.
- [x] Console: Admin → TSIG keys (create generate/import, zone scope, secret once with BIND/dig snippets, two-step reveal, two-click delete, transfer policy read-only) checked in Chrome.
- [ ] Not done: replay protection by caching the last Time Signed per key (RFC 8945 §5.2.3 SHOULD); inbound signed NOTIFY/UPDATE (not applicable: primary only).

## Forwarding settings from the console/API (2026-09-27, verified)

- [x] `GET/PUT/DELETE /api/settings/forwarding`, `POST /api/settings/forwarding/test` (admin): upstreams, allowed clients, timeout; stored in the `settings` table as an override of `[forwarding]`, written with its audit entry in one transaction, applied immediately, kept across restarts and config reloads; reset returns to the config file.
- [x] Validation lists every problem (host names, duplicates, `/0` open-resolver networks, timeout range); tests: `tests/forwarding.rs` (fake upstream, restart persistence), `mutation::settings` unit tests, contract tests cover the new operations.
- [x] Console "Server settings" page: load, test upstreams and save checked in the browser against a live instance.

## API token tags and last use (2026-09-27, verified)

- [x] Tags on tokens (`[a-z0-9._-]`, 1-32 chars, up to 16, normalized and sorted): set on create, replaced with `PUT /api/tokens/{id}` (audited `token.update` with before/after), filtered with `GET /api/tokens?tag=`.
- [x] `last_used_at` and `last_used_ip` recorded on bearer use; written at most once a minute, immediately when the address changes.
- [x] Console: tag chips (click to filter), tag filter, chip editor in the create and edit dialogs, last used time and address.

## Console layout rework (2026-09-27, verified)

- [x] Records toolbar on one row; SOA / Delegation / Test with dig / Access as chips opening a side panel; record add/edit in a dialog.
- [x] Audit and changelog entries open a readable detail view; dialogs fit the viewport and scroll; compact effective-rights layout.
- [x] Collapsible sidebar with sections and icons; drawer on phones.
- [x] SOA fields explained; Delegation tab with nameservers, glue and registrar steps (reverse zones explained separately).
- [x] Dashboard "DNS listeners" card and per-zone dig commands (UDP/TCP, port, AXFR when allowed).
- [ ] Live updates through a reverse proxy not exercised in the browser this round (websocket path unchanged).

## In flight right now (uncommitted edits on disk)

- [x] `src/ui/index.html`: zone page paging fix is built; the end-to-end `bind_import_and_record_paging` test covers the server-side paging API.
- [x] Zone page and record filter verified in the browser (2026-09-27).
- [ ] Browser check still owed for: BIND import modal, recovery-code modal after MFA enrollment, "New recovery codes" flow, users → "Sign this user out everywhere". In-app Browser is unavailable in this session.
- [x] `scripts/conformance-local.sh` passes 85/85 (76 before TSIG); `RUN_COMPLIANCE=1 scripts/conformance-local.sh` builds and runs ISC genreport with every probe `ok`.
- [x] `cargo fmt --all` and `cargo clippy --all-targets -- -D warnings` pass.
- [x] `cargo test -- --test-threads=1` passes (34 unit + 3 end-to-end); serial run avoids an occasional collision in the tests' free-port helper.

## Review fixes (2026-09-27, all verified)

- [x] Tests no longer write backups into the repo root; `/backups/` is gitignored.
- [x] First backup runs one interval after startup; backups go to a temp file, pass an integrity check, then are renamed, so partial or corrupt copies never evict good ones. Backup logic lives in `src/backup.rs`.
- [x] `[backup]` changes are reported as restart-required on reload.
- [x] `/api/health` is a cheap `SELECT 1` with a generic error body; the full integrity scan is admin-only at `GET /api/admin/integrity`.
- [x] `scripts/load-test.py` expires lost queries, so sending continues under packet loss and loss is reported correctly.
- [x] `config::validate` checks CIDRs, proxy versions, log level/format, ports, collisions, SOA defaults and more; `--check`, startup and reload share it.

## Structural changelog (2026-09-27, verified)

- [x] Only the mutation module can open a write transaction (`WriteToken`); data and account write SQL is private to it.
- [x] DNS operations get a `Tx`; every write records a typed `Change`; commit writes changelog rows and serial bumps in the same transaction.
- [x] Validation runs inside the transaction; any failure rolls back everything and is logged as a warning, with no changelog row.
- [x] Zone delete logs every record and member removed; imports log every record; payloads are exact facts.
- [x] `replay` rebuilds identical data from the changelog (randomized test: 645 rows, 81 rollbacks, all change kinds).
- [x] Account and security writes go through `AuditTx` into `audit_log`, same guarantee; `GET /api/audit` and an admin Audit page.
- [x] Existing databases are migrated in place; old changelog rows are kept as schema 1 and are not replayable.
- [ ] Follower mode: a second server that tails `/api/changelog` or the websocket and calls `replay`.

## Effective rights (2026-09-27, verified)

- [x] Single permission table (`ZonePerm`, `GlobalPerm` in `model.rs`) used by every API check and by `GET /api/users/{id}/rights`.
- [x] Console: Owner column on API tokens (click for effective rights), Rights button on Users, link on Account.
- [x] Live query feed limited to zones the user owns, attributed to the most specific zone.
- [x] Fixed: websocket `?token=` authentication never worked (nested-router path).
- [ ] Per-token scopes (zones, max role, expiry); token creation only from a browser session; revoke tokens on password change.

## API explorer (2026-09-27, verified)

- [x] Swagger UI 5.33.0 vendored (integrity-checked, Apache-2.0) and served at /docs, gzip + ETag; console "API explorer" section embeds it.
- [x] Requests use the signed-in session (CSRF header added automatically) or a token via Authorize.
- [x] OpenAPI spec complete (49 operations, tags, schemas, examples), validated; now generated from the code (see below), so routes and spec cannot drift.
- [x] Fixed: updating a record without `ttl` no longer resets its TTL (`null` resets explicitly).

## Record expiry (2026-09-27, verified)

- [x] `expires_at` / `expires_in` on records; expired records leave the catalog at once (answers, AXFR, BIND export, auto-PTR).
- [x] Sweeper wakes at the next expiry: commits `record_expired` + serial bump; reaps after `[expiry].retention_days` (default 30) as `record_reaped`.
- [x] Identical record with an expiry renews (200); expired records don't block new ones; console Expires column and editor.
- [ ] Zone-level default and maximum expiry for self-registration zones.

## Spec/API consistency and console polish (2026-09-27, verified)

- [x] Contract tests (`tests/api_contract.rs`): all 49 operations and 22 request examples run against a live server; responses validated strictly (undocumented fields, missing required fields, undocumented statuses fail).
- [x] Framework rejections (bad JSON, wrong types, bad path/query values, missing content type) now return the JSON `Error` with `code: invalid_request` (was plain text, 415/422).
- [x] Console: "TTL (seconds)" labels; expiry durations `1m`, `1h`, `1d`, `6d12h14s` (units d/h/m/s, largest first, each once) with live preview; parser tested in CI.
- [x] OpenAPI generated from the code (utoipa 5 + utoipa-axum `OpenApiRouter`): each route is declared once with `routes!`, bodies are `ToSchema` types, ad-hoc `json!` responses replaced by typed structs; the hand-written `src/api/openapi.json` is gone. Snapshot at `docs/openapi.json` with a staleness test (`UPDATE_OPENAPI=1 cargo test --bin rust-dns openapi` refreshes it). Document is OpenAPI 3.1.
- [ ] Consider utoipa 6 / utoipa-axum 0.3 (released 2026-09-23) once it has settled.

## Stage 4: operations and testing

- [x] Scheduled SQLite backups (`[backup] dir, interval_hours, keep`) using the online backup API.
- [x] `/api/health` checks the database and returns 503 on failure.
- [x] `rust-dns --check` validates a config file and exits non-zero on problems.
- [x] GitHub Actions workflow runs fmt, clippy, cargo test, conformance against a spawned and seeded instance, and a short load probe.
- [x] README: document stages 1 to 3 and refresh the testing section.
- [ ] Record Linux load-test results. `scripts/load-test-local.sh` now runs in CI; local macOS smoke run returned valid replies but is not a performance measurement.
- [x] Prometheus alert examples for `rate_limited`, `refused`, `errors`, `bad_cookie`.

## DNS features not started

- [ ] DNSSEC signing (NSEC/NSEC3, key management, DS publication). Largest remaining item.
- [ ] TSIG for AXFR and NOTIFY. Transfers are currently restricted by client network only.
- [ ] Changelog-based follower mode (a second rust-dns replaying `/api/ws?after=` events) as an alternative to AXFR secondaries.
- [ ] Inbound NOTIFY / acting as a secondary for zones hosted elsewhere.
- [ ] DNS over TLS / HTTPS (inbound and upstream). Deliberately deferred.
- [ ] Response Rate Limiting per response tuple in addition to per-client limiting.
- [ ] Per-zone settings: forwarding overrides, auto-PTR toggle, transfer ACL and NOTIFY targets.
- [ ] Record types hickory-proto's text parser does not cover (LOC and others).

## Console and API

- [ ] Explicit CSRF token instead of the `X-Requested-With` header check (header check is enforced today).
- [ ] Bulk record editing (multi-select delete, paste-many).
- [ ] Zone cloning and rename; search across all zones.
- [ ] Login audit view (currently only in logs).
- [ ] Password policy options and lockout beyond per-address login rate limiting.
- [ ] WebAuthn / passkeys as an alternative second factor.
- [ ] Column sorting and keyboard shortcuts in the records table.
- [ ] Console TLS is intentionally out of scope (reverse proxy).

## Packaging

- [ ] Static musl build and multi-arch Docker image publish.
- [ ] Debian package and Homebrew formula.
- [ ] Windows service wrapper (untested platform).
- [ ] Initialise the git repository and make the first commit (remote to be decided by the user).

## Known limitations to document

- Forwarded answers are cached but not prefetched; SERVFAIL is not cached.
- Cookie secret rotates on every restart (clients re-learn transparently).
- `[server]`, `[web_console].bind`, `[database]`, logging file targets, and PROXY settings require a restart; everything else reloads on SIGHUP or `POST /api/admin/reload`.
- hickory's zone parser inherits TTLs from the previous record; `src/zonefile.rs` pre-pass works around it for BIND import.
