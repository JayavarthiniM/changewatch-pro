# ChangeWatch Pro — implementation audit (2026-10-16)

This is an honest implementation/verification ledger, not a claim that every item in the competition brief is complete. “Implemented” means a code path exists; it does not imply production acceptance testing.

## Implemented in the current single-process prototype

- Public HTTP(S) website monitoring with Playwright Chromium, bounded retries/timeouts, per-domain spacing, same-site in-flight coalescing, and a scheduler.
- Text extraction/normalization, hashes, text diffs, heuristic significance/explanations, numeric extraction, and change events.
- Snapshot history and best-effort screenshots; side-by-side screenshot comparison and a capped client-side pixel-difference preview.
- CSS watch/ignore selectors and a companion Chrome selector-picker extension.
- Per-site keyword/severity/score alert rules, duplicate suppression, quiet hours, retryable pending notifications, and configurable email/Discord/Telegram channels.
- Global/per-site RSS, JSON/CSV exports, configuration import/export, numeric history endpoint, diagnostics, synthetic Reliability Lab scenarios, and local synthetic benchmark.
- URL/network checks intended to reduce SSRF exposure, input validation for settings/site patches, API rate limiting, optional Basic Auth, atomic JSON writes and backup recovery.
- Unit tests for core helper modules and policy behavior.
- Startup store normalization for missing/malformed collections and settings, with warnings and automatic rewrite of normalized/recovered data.

## Partial / heuristic / requires acceptance testing

- CAPTCHA/outage classification is heuristic and can misclassify pages.
- Significance, summaries, and numeric extraction are deterministic heuristics, not semantic AI; accuracy varies by site/content.
- Screenshot diff is a visual preview and can report noise from fonts, animations, dynamic content, and browser rendering.
- Adaptive monitoring exists as a policy field/behavior but needs controlled real-site validation.
- Email requires working SMTP configuration; Telegram/Discord require valid credentials and a real delivery test.
- CSS selector extension workflow requires a manual Chrome test against representative pages.
- Rate limiter is in-process and per-instance; it is not a shared distributed limiter.
- Scheduler/queue records can be recovered from JSON, but the runtime queue is not transactional or safe for multiple server processes sharing a data directory.
- SSRF checks reduce risk but do not eliminate DNS-rebinding/time-of-check/time-of-use risks; production needs outbound egress controls and a live security review.
- Reliability Lab results are synthetic and must not be presented as live throughput or real-site accuracy measurements.

## Not yet complete for a production-grade submission

- SQLite schema, migrations, and tested import of existing JSON data.
- Transactional durable queue and multi-process coordination.
- React + TypeScript + Vite + Tailwind frontend migration (current dashboard is vanilla HTML/CSS/JS).
- Live Express API integration tests and full Playwright end-to-end tests.
- End-to-end tests for real notification delivery, retries, restart recovery, selector picking, visual comparison, and real controlled page changes.
- Shared rate-limit storage for multi-instance hosting, production-grade secret management, and outbound-network enforcement.
- Full keyboard/screen-reader/mobile accessibility pass, production deployment smoke test, and final requirement-by-requirement acceptance evidence.

## Release gate

Do not label this project production-ready until the outstanding items above are either implemented and tested or explicitly accepted as scope limitations. Run `npm.cmd test`, install Playwright Chromium, run live API/browser acceptance tests, and test deployment with persistent storage and authentication enabled. Current helper suite: 61 tests passing on 2026-10-16; this is not a substitute for live API/browser acceptance tests.

### New live-API verification harness

Added `scripts/live-smoke.js` and `npm run smoke` to check key read-only endpoints against an already-running server: health, diagnostics, dashboard data, configuration export, synthetic Reliability Lab benchmark, RSS, and CSV export. The harness uses Node's built-in `fetch` and does not add a dependency or mutate monitored sites. It has not been executed against a live server in this build environment because application dependencies are not installed here; run it locally after `npm install` and `npm start`.

## New migration preparation (not a runtime storage switch)
- Added `scripts/migrate-json-to-sqlite.js`, a non-destructive first-stage copier that validates the source JSON shape, writes the full state into a transactional SQLite envelope, stores a SHA-256 source fingerprint, runs SQLite `integrity_check`, and verifies the stored payload.
- The original JSON file is not modified. Existing target files are refused by default; `--force` is required to replace an existing migration payload.
- Added `better-sqlite3` and `npm run migrate:sqlite` for this migration utility.
- **Still incomplete:** `server.js` continues to read/write JSON. This is a migration tool, not a claim that the running application has switched to SQLite or that normalized relational tables/durable queue are finished. Run and verify the migration on a copy of real data before any runtime cutover.


## Runtime storage observability correction

- `/api/health` and `/api/diagnostics` now report the configured backend (`local-json-with-backup` or `sqlite-app-state`) rather than always claiming JSON storage.
- Queue durability labels distinguish recoverable job records stored in JSON from job records included in the SQLite application-state document. This does not make the queue a separate relational or multi-process transactional queue.
- This is a metadata/diagnostics correction; it does not claim the SQLite adapter has been verified against the native dependency in this environment.


## SQLite empty-database guard

- SQLite startup now refuses to initialize an empty database when the legacy JSON store contains application records, avoiding a silent apparent data-loss event after an incorrect storage-path configuration.
- Malformed legacy JSON also blocks empty SQLite startup unless the operator explicitly opts into a new empty database with `CW_SQLITE_ALLOW_EMPTY=true`.
- This guard is unit-tested; real native SQLite migration and restart acceptance tests are still required.

## SQLite bootstrap guard refinement

- Empty-database startup protection now treats customized settings as existing user data even when there are no sites or snapshots. This avoids silently losing theme, alert destinations, quiet hours, digest preferences, and sensitivity settings during a misconfigured storage switch.
- Added a regression test for a settings-only legacy store. The helper suite now has 51 passing tests; native SQLite migration/runtime acceptance is still pending.


## SQLite path safety refinement
- `sqlite-storage.js` now creates missing parent directories before opening a configured SQLite database, preventing startup failures when `CW_SQLITE_PATH` points into a new directory.
- New database directories request restrictive POSIX permissions, and the database file is chmod'ed to owner-only where the platform supports it. Windows ACLs should still be configured separately for production.
- Added a regression test for nested storage paths. The suite passes 52/52 tests. These tests use a fake database adapter for storage behavior; native `better-sqlite3` migration, permissions, and restart behavior still require Windows acceptance testing.


## Backup failure cleanup hardening (2026-10-16)
- SQLite backup verification now removes an incomplete destination on any verification failure, including a missing `app_state` table or malformed application-state JSON, not only a failed integrity check.
- Added a regression test confirming a partially created backup is deleted when verification fails.
- Still required: run backup/migration with the native `better-sqlite3` dependency against a real database on Windows.

- SQLite backup verification now checks that a present `app_state.payload_json` is a JSON object and that known core collections (`sites`, `snapshots`, `events`) are arrays when present; malformed backup artifacts are deleted. Regression test added. Native SQLite backup remains to be exercised with the installed dependency.

## SQLite bootstrap recovery-backup guard (2026-10-16)
- Empty SQLite startup now checks `store.json.bak` when the primary `store.json` is missing, matching the JSON backend's last-known-good recovery behavior.
- Prevents a missing primary file from masking recoverable user data in the backup and accidentally bootstrapping an empty SQLite store.
- Added a regression test for a populated backup with no primary file. Current unit suite: 55/55 passing.
- Still outstanding: native SQLite dependency installation and full migration/runtime/restart acceptance testing.

## SSRF reserved-address hardening (2026-10-16)
- Extended the IP guard to reject additional special-purpose/documentation IPv4 ranges (including 192.0.2/24, 198.51.100/24, and 203.0.113/24) and IPv6 documentation/transition ranges.
- Added regression coverage for these ranges while confirming a public IPv4 address remains allowed.
- This reduces accidental access to reserved targets but does not eliminate DNS rebinding or TOCTOU risks; production still requires outbound egress controls and a security review.
- Current unit suite: 56 tests passing. Native SQLite and live API/browser acceptance tests remain outstanding.


## API error response hardening (2026-10-16)
- Added `api-error-handler.js` and mounted it after API routes so malformed JSON and oversized request bodies receive consistent JSON errors (`400 INVALID_JSON`, `413 PAYLOAD_TOO_LARGE`).
- Unexpected API errors return a generic `500 INTERNAL_ERROR` without exposing stack traces or dependency details; non-API errors continue through Express error handling.
- Added three unit tests for malformed JSON, oversized payloads, and internal-error redaction/non-API forwarding.
- Unit suite passes 59/59; server/frontend/helper syntax checks and archive integrity verified. Full live Express integration still needs running-server acceptance testing.


### Live API smoke coverage update
- Extended `scripts/live-smoke.js` to POST malformed JSON to an API endpoint and require the safe `400 INVALID_JSON` response.
- This verifies the parser/error-handler integration when run against a live server; the check is not counted as passed until `npm run smoke` is executed against that server.


### Live API smoke coverage update
- Extended `scripts/live-smoke.js` to POST malformed JSON to an API endpoint and require the safe `400 INVALID_JSON` response.
- This verifies parser/error-handler integration when run against a live server; the check is not counted as passed until `npm run smoke` is executed against that server.

### Authenticated smoke-test alignment
- `scripts/live-smoke.js` now supports optional `CW_AUTH_USER` and `CW_AUTH_PASSWORD` credentials when testing a server protected by the application's HTTP Basic Authentication middleware.
- This prevents the acceptance script from incorrectly failing every protected endpoint with `401` when production-style auth is enabled.
- Validation performed here: script syntax and the unit suite. A live server run remains required to verify real HTTP behavior.

### Smoke-test authentication configuration hardening
- Extracted Basic Authorization header construction into `basic-auth-header.js` so it can be tested without a live server.
- The smoke runner now fails fast if only one credential is configured and rejects usernames containing `:`, avoiding silently unauthenticated test runs or invalid Basic credentials.
- Supports UTF-8 credentials and colons in passwords. Live server authentication remains a separate acceptance check.


## Repeatable local preflight command (2026-10-16)
- Added `npm run check`, which syntax-checks every project JavaScript file outside ignored dependency/build folders and then runs the built-in Node test suite.
- This is a repeatable local code preflight, not a substitute for live API, browser, SQLite-native, notification, or deployment acceptance tests.

## Dashboard trust and status polish (2026-10-16)
- Replaced the hard-coded “worker ready” label with a live `/api/health` connection indicator. It shows API connectivity and exposes site/queue/storage details on hover; failures visibly switch the indicator to offline.
- Manual refresh now reports success only when the workspace data request succeeds, rather than showing a success toast after a failed refresh.
- This is a focused UX/trust improvement, not a new monitoring capability. Verified with JavaScript syntax checks and the 61-test helper suite; browser-level visual verification still needs the local app running.
