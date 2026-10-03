# Pending work

Status as of 2026-09-27. Deployed to dns-test (musl build, /opt/rust-dns) with everything below. Stages 1 to 3 (log rotation, DNS protocol completeness, console fixes) are implemented. The current workspace has additional Stage 4 changes in progress below.

## Console editability (2026-10-03, K1/K2 in plan.md)

- [x] K1. Standby: default-deny of console write controls (`data-ro-ok` opt-in), client guard in `api()` from `GET /status` `replication.standby_writable`; blocklist download/test allowed on a standby.
- [x] K2. Every write control declares its permission (`data-perm`/`data-zone`), decided from the caller's effective rights; state blocks (`data-block`) for own-account delete, root edit by non-root, DNSSEC off while a DS may be published. Test-enforced in `api::ui_tests` and `tests/ui/access.test.js`.

## DNSSEC online signing (2026-09-27, implemented, not committed)

- [x] RFC 3225 fix (ships with signing off): the query's DO bit is copied into the response OPT (was always clear). Unit/e2e/conformance checks.
- [x] Per-zone signing, off by default: `zones.dnssec` (Zone JSON field only when on; changed through `update_zone` -> `zone_updated` + serial bump), one CSK per zone (257, alg 13 ECDSA P-256, ring), NSEC. Key in `dnssec_keys` (registry: replicated), written only through `DnssecKeySet` / `DnssecKeyDeleted` account-class changes (acct_sql; source-scan test covers the table); never in the changelog API, websocket (Tx::finish now publishes only dns-class events), audit, logs; scrubbed after `account_retention_days`; in snapshots.
- [x] Signing in memory at catalog build (`dnssec::signed`), cached by a fingerprint of zone row + served records + key + window; queries (DO) and AXFR share it. Inception = `updated_at` - 1 h, validity `[dnssec].signature_validity_days` (14); primary re-signs (`zone_resigned` + serial bump) `resign_before_days` (7) before expiry via `Mutator::spawn_resigner`; any node re-signs in memory from the current hour if a window gets within half of that of expiry without a bump (standby cut off). Standby never writes.
- [x] Responses: RRSIGs, NXDOMAIN/NODATA/ENT/wildcard/wildcard-NODATA proofs, referrals with DS or no-DS NSEC, DS at a cut answered by the parent side (only when signed or DS records exist: unsigned zones unchanged), DNAME signed / synthesized CNAME unsigned, signed minimal ANY = one RRset + RRSIG, DNSKEY/NSEC/RRSIG qtypes, DO answers drop the additional section before truncating. Auto-PTR disabled inside signed zones.
- [x] DS record type in the editor (`<tag> <alg> <digest type> <hex>`, types 1/2/4 with exact lengths).
- [x] API: `GET/PUT /zones/{zone}/dnssec`, `GET .../dnssec/ds`, `GET .../dnssec/check` (self-validation of this server's answers), `GET .../dnssec/parent` (DS via the first forwarding upstream: present/absent/mismatch/unknown). Disabling refused with 409 `ds_published` unless the parent check says absent; `force` in the API only. Contract tests cover all (74/74 operations).
- [x] Console: DNSSEC chip + tab (status, key, DNSKEY, DS with copy buttons and registrar fields, window and next re-sign, check, parent lookup, two-step enable dialog with optional new key, disable dialog showing the refusal). Delegation tab no longer says DNSSEC is unsupported. Checked in Chrome.
- [x] Mixed-version safety while signing is off: `zones.dnssec` is left out of the table checksum (covered by the per-zone checksum, where it appears only when on); an empty table unknown to an older primary is not a reconcile difference. Upgrade standbys before turning signing on.
- [x] Tests: dnspython known-answer vectors + BIND DS (`src/dnssec/vectors.rs`, `scripts/dnssec-vectors.py`), unit tests (canonical order, bitmaps, key tag/DS RFC 4034 examples, chain/positions, window), mutation tests (enable/disable/key lifecycle, secrecy, re-sign, cache), randomized replay covers the new change kinds, replica snapshot/secrets tests, `tests/dnssec.rs` (dnssec-verify, dnssec-dsfromkey, delv x40 + negative control, validating named with AD, no-DO answers unchanged, truncation, re-sign, parent DS refusal with a second rust-dns as parent), `tests/follow.rs` (standby signs with the replicated key, delv + dnssec-verify against it, reconcile ok, no halt), conformance 86 -> 123.
- [ ] Not done: automated key rollover (double-signature or CDS/CDNSKEY, RFC 7344/8078), NSEC3, other algorithms, signing auto-PTR answers, DS query at an apex whose parent zone is here but unsigned and has no DS keeps the child NODATA (pre-existing behaviour), wildcards whose `*` label is itself an empty non-terminal (records under `*.x`) are answered NXDOMAIN as before and their NSEC proof would not validate (unusual; not blocked in the editor).
- [ ] Owner notes for deployment: build, deploy with signing off (no answer changes except the DO echo), upgrade baba2 before gate if possible (either order is safe while signing is off), then enable on wushilin.net, run the check, confirm baba2's DNSSEC tab shows the same key, publish the DS at the registrar, confirm with the parent lookup (needs a forwarding upstream on gate, else `dig +short DS wushilin.net`).

## Open resolver mode (2026-09-27, implemented, not committed)

- [x] `[forwarding] open_resolver = false` (default), `open_resolver_max_udp_payload = 512` (512..4096), `open_resolver_rate_per_second = 20` (0 = no extra limit). The L10 guard stays the default; the flag skips it in `config::validate` and `mutation::settings::validate`. Empty `allowed_clients` still means nobody (the /0 entries must be listed). `--check` prints `WARNING:` lines; WARN at startup, on reload (notes too) and on every off->on transition. Reloadable.
- [x] Console/API override: `ForwardingSettings.open_resolver: Option<bool>` (absent in old overrides = the file's value; new saves always store it explicitly). `ForwardingInput.open_resolver` (omitted = file value), `ForwardingView.open_resolver/_max_udp_payload/_rate_per_second`, `config.open_resolver`. Audited in `settings.forwarding.update` before/after; replicated as part of the `setting_set` JSON (replay test data, snapshot test, `tests/follow.rs`).
- [x] Runtime: effective mode = override ?? file; an ACL the guard would refuse always gets the safeguards (defence in depth). Safeguards only while on and upstreams exist: UDP cap on forwarded answers (upstream and cache; TC=1), ANY for foreign names -> RFC 8482 HINFO (not forwarded), per-client forwarding limiter (`DnsServer::fwd_limiter`, same count-min + slip; UDP drop/slip, TCP REFUSED).
- [x] Visibility: gauge `rustdns_open_resolver`, counters `rustdns_open_resolver_{truncated,any,rate_limited}_total`, `/api/status` `forwarding.open_resolver` + `dns.open_resolver_*`; console badge on dashboard and Server settings, two-step in-dialog enable, turn-off dialog with a narrowed ACL.
- [ ] Not done: exempting clients with a valid server cookie from the UDP cap (cookie proves the source address); per-mode limits configurable from the console (file only).

## Replica tracking and halting (2026-09-27, implemented, not committed)

- [x] `[follow].instance_id` required (host label); standby sends `X-Rust-DNS-Instance/Version/Session` on every replication request; data endpoints 400 without it.
- [x] Primary tracks replicas (`replication::replicas`): applied offset (= `after`), lag changes/seconds, last seen, address, version, user; states up_to_date/catching_up/falling_behind/offline/bootstrapping/halted; conflict flag; `[replication]` thresholds (reloadable); local `replicas` table (registry: Local), pruned after `forget_after_days`; `GET /api/replication/replicas`, audited `DELETE .../{id}`; metrics per instance; console table.
- [x] Halt (terminal until `--prepare-standby`): reconcile mismatch, apply failure, txn mismatch at head, ahead of primary. Report file `diverged-*.json`, state in `replication_state`, audit row `replication.halt`, log, metric `rustdns_replication_halted`, banner, status, `--check`; reported to the primary (`POST /api/replication/replicas/{id}/report`) at the halt and at each start.
- [x] Root rename on a standby refused (would change a replicated row).

## Account changes in the changelog (2026-09-27, implemented, not committed)

- [x] `Change` gained the account family (user_created/updated/deleted, totp_step_accepted, recovery_codes_replaced, recovery_code_used, token_created/tags_set/revoked, tsig_key_set/deleted, setting_set/cleared): facts, applied by `mutation::acct_sql` (the only writer of those tables; source-scan test) on the primary through `AuditTx::record` and on a standby through the same `replay::apply` (local-root merge inside it).
- [x] One changelog sequence; column `class` ('dns'|'account'); changelog API/websocket show `dns` only; account payloads scrubbed after `[changelog].account_retention_days` (default 3) -> gap -> snapshot.
- [x] Snapshot = logical entities (the same facts) loaded through replay; accounts endpoint, generation counter and account checksum removed; reconcile = per-table checksums from the table registry (`replication::tables`) + per-zone.
- [x] Replication protocol 2 (status/identity/changes/snapshot); a standby refuses a protocol-1 primary. Existing databases migrate in place (class column, old rows 'dns').
- [x] Standby-local account writes (its root, TOTP steps / recovery codes used there) are applied but not changelogged (gate closed before the root sync at startup).
- [x] Snapshot only when connecting (fresh database, or same-lineage gap); afterwards changelog only. Replay is idempotent (upserts, `INSERT OR REPLACE` of changelog rows), overlapping batches are accepted. Reconcile mismatch is reported (log, status, metric), no automatic reload.

## Standby: follow only a fresh database (2026-09-27, implemented, not committed)

- [x] `[follow]` follows only when the database is in the primary's lineage (restart/reconnect; gap or reconcile re-bootstrap stays automatic) or fresh (`replication::data::fresh_problems`: no zones, records, members, TSIG keys, settings, tokens, users besides the config root). Otherwise state `refused`, read-only, error names the data and `--prepare-standby`; shown in status (`replication.problem` in `/api/status`), banner, Replication page, `--check`, log.
- [x] `rust-dns --prepare-standby [--yes]` (server stopped; web port in use or DB locked = refused): dry run lists and exits 2; `--yes` writes `<db>.pre-standby-<time>` (online backup, integrity-checked), `divergent-<time>.json` when there are local changes the primary lacks, empties replicated tables and lineage, audit row `replication.prepare_standby`.
- [x] The automatic divergence save on follow was removed; tests updated (`tests/follow.rs` rejoin via --prepare-standby, standby restart resumes without a snapshot).

## Standby / follow mode (2026-09-27, committed b17f229)

- [x] `[follow] primary/token/reconcile_interval_secs/allow_insecure_http/timeout_secs` (https required, loopback exempt; validated by `--check`); `[peer] url/check_interval_secs` on the primary fences a returning old primary (read-only).
- [x] Primary API (`GlobalPerm::Replicate`, admin): `GET /api/replication/{status,snapshot,accounts,changes,checksum}`, public `identity`, `POST promote`. Snapshot = one read transaction; changes = long-poll, whole transactions; account-data generation bumped by the `Accounts` commit hook.
- [x] Standby: snapshot bootstrap, tail with the primary's offsets (`mutation::replica`, changelog rows copied), accounts/settings/TSIG sync with an audit row `replication.accounts_sync`, periodic checksum reconcile, gap / history / divergence handling (`replication::lineage`), divergent tail saved to `divergent-*.json`.
- [x] Local root merged with the primary's namesake (local credentials) or kept local (negative id on collision); TOTP last step and used recovery codes merged (max / keep used).
- [x] Read-only: `WriteGate` in `Mutator::execute` + API middleware with an explicit allowlist (`STANDBY_WRITABLE`); 409 `read_only_standby` added to the OpenAPI document for every other mutating operation; expiry sweeper paused.
- [x] Promotion: console (Admin -> Replication, two-click), API, `--promote` (stopped server), or removing `[follow]` by hand (recorded at next start). New history id with parent + fork offset; `[follow]` removed from the config file.
- [x] Console: banner on every page, write controls disabled, Replication page; checked in Chrome (banner in sync / unreachable, disabled edits, promote flow, no console errors).
- [x] Tests: `tests/follow.rs` (two binaries, full failover and rejoin), unit tests in `mutation::replica`, `replication::lineage`, `api::tests` (every mutating route refused), contract test promotes a real standby.
- [ ] Not done: cascading standbys (a standby refuses to serve replication), gzip of snapshots, custom CA file for the primary's certificate (OS trust store only), websocket signal for account changes (long-poll used instead).

## Security review fixes (2026-09-27)

- [x] H3 TCP pinning: per-write timeout (`tcp_write_timeout_secs`), connection age and query caps, per-client (IPv4 / IPv6 /64) connection cap; regression `tests/hardening.rs`.
- [x] H2/A2 no default password: `--init-config` (0600, random hashed password printed once), placeholder `change-me*` and empty passwords refused by `--check` and startup, installer uses it; L6 generated password never logged; L7 umask 0077, 0600 rewrites, hardened systemd units (`systemd-analyze verify` not run: no systemd on the dev machine; verify on the Linux host).
- [x] BIND zone-file import and export removed (was H1 via `$INCLUDE`); JSON import/export stays.
- [x] M1 Argon2 on a bounded blocking pool (503 + Retry-After when saturated). M2 rate limits keyed by IPv6 /64, count-min table (no eviction resets), slip; per-account/network back-off; 5 codes per session. M3 per-column account writes. M4 websocket re-validation + L4 Origin + L5 subprotocol token. M5 forwarder ID/0x20/question checks and UDP truncation. M6 re-enrollment needs the current factor, TOTP replay protection (`users.totp_last_step`). M7 password change signs out other sessions. M8 explicit proxy trust. M9 hickory-proto 0.26.1, lru 0.18.
- [x] L1 web header timeout / connection cap, L11 PROXY header timeout and split v1 headers, L2 `__Host-` Secure cookies over HTTPS, L3 CSP with script hashes, L8 member events / actor IPs redacted below owner, L9 renamed root disables the previous root, L10 open-resolver coverage check in config and API.
- [x] Conformance: 86/86 (new check: rate-limit slip replies). cargo-audit: no vulnerabilities (only the informational `paste` notice).
- [x] Forward cache TTL caps (`cache_max_ttl`, `cache_negative_max_ttl`, console-overridable), cache stats and `POST /api/settings/forwarding/cache/flush`.
- [ ] L13 admin-initiated MFA enrollment (forced enrollment still trusts the first sign-in after `mfa_required` is set). Not implemented: needs an out-of-band delivery of the secret (QR to the admin, handed over), a new state and UI.
- [ ] Per-account back-off and code-attempt counters are in memory (reset on restart; the per-network request limit still applies). Persisting them would need an audited table.
- [ ] Websocket rights are re-checked every 10 s and on zone/member changes, not instantly on session/token revocation (no revocation event on the bus yet).

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

- [x] `src/ui/index.html`: zone page paging fix is built; the end-to-end `json_import_and_record_paging` test covers the server-side paging API.
- [x] Zone page and record filter verified in the browser (2026-09-27).
- [ ] Browser check still owed for: recovery-code modal after MFA enrollment, "New recovery codes" flow, users → "Sign this user out everywhere". In-app Browser is unavailable in this session.
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
- [x] Follower mode: see "Standby / follow mode" above.

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

- [x] DNSSEC signing (NSEC, CSK, DS publication): see above. NSEC3 and automated rollover remain.
- [ ] TSIG for AXFR and NOTIFY. Transfers are currently restricted by client network only.
- [x] Changelog-based follower mode (standby mode, 2026-09-27).
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
- BIND zone-file import/export was removed in the security review (no zone-file parser is exposed any more).
