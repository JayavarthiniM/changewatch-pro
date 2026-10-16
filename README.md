# ChangeWatch Pro

ChangeWatch Pro monitors public web pages using Playwright Chromium, stores evidence only for distinct content versions, and creates explainable alerts for meaningful changes. It is designed as a VinnovateIT Website Change Detector submission.

## VinnovateIT requirement checklist

| Requirement | Implementation status | Notes |
|---|---|---|
| Add URL, name, interval 15 min–24 h | Implemented | Interval is clamped to the required range. |
| Headless browser rendering | Implemented | Playwright Chromium. |
| Scheduler, queue, timeouts, retries | Implemented | In-process queue with configurable concurrency, same-site coalescing, per-domain spacing, 20 s navigation timeout and bounded retries. Queued and interrupted jobs are re-queued from persisted job records on restart; this is single-process recovery, not a transactional or distributed queue. |
| Public pages only / no stored page credentials | Implemented with caveats | HTTP(S), URL/DNS checks and resource/redirect checks. Continue hardening SSRF protection before production. |
| Save text and screenshot only when content hash changes | Implemented | First successful snapshot is stored; identical content reuses the prior snapshot. Screenshot capture is best-effort. |
| Noise filtering | Partial | Timestamps, counters, UUID-like IDs and long random tokens normalized; common page chrome removed; user-configurable ignored selectors. Site-specific rotating banners still require a selector. |
| Sensitivity setting | Implemented | Per-monitor threshold, 0–100. Scores are heuristic. |
| Visual region picker | Implemented as companion Chrome extension | `browser-extension/`; select an element on the target page and paste its generated CSS selector into the monitor form. |
| Text diff | Implemented | LCS for normal-sized content, bounded token-set fallback for large pages. |
| Highlighted screenshot diff | Implemented in comparison UI | Side-by-side screenshots plus client-side pixel-difference preview; pixel differences can be noisy and are not semantic. |
| Side-by-side comparison of any two versions | Implemented | Snapshot comparison dialog. |
| Before-and-after screenshot slider | Implemented | Interactive overlay slider added to the comparison dialog; depends on both screenshots being available. |
| Email and Telegram/Discord webhook alerts | Implemented/configuration-dependent | Telegram and Discord configured in Settings. Email requires SMTP environment variables. |
| Summary and diff link; duplicate alert suppression | Implemented | Change summary, comparison IDs and per-hash duplicate suppression. |
| Optional daily digest | Implemented/configuration-dependent | Daily 09:00 server timezone (default Asia/Kolkata); digest must be enabled and a notification channel configured. |
| Version timeline | Implemented | Per-site history dialog. |
| Dashboard: last checked, last changed, status | Partial | Last checked and status are exposed; last-changed is represented by change events/history rather than a dedicated field in every card. |
| CAPTCHA vs outage | Implemented heuristic | 403/429 and CAPTCHA/access-denied text are classified as blocked; 5xx/navigation failures as errors. False positives are possible. |
| Same URL watched by 200 users | Locally deduplicated | Exact duplicate URLs are rejected in this single-workspace app, so the same page isn't separately scheduled 200 times. This is not a multi-user service or distributed shared cache. |
| Avoid endless alerts on volatile pages | Implemented with caveats | Hash dedupe, noise normalization, keyword filtering, significance threshold and ignored selectors. Highly volatile pages may need per-site tuning. |
| Avoid hammering a site | Implemented with caveats | Per-domain spacing, concurrency limit, bounded retries and 15-minute minimum interval. Respect target website terms and rate limits. |
| Bonus number tracking and charts | Partial | Numeric extraction, comparison and CSV export; extraction is heuristic and not all numeric series are automatically charted. |
| Bonus AI one-line summaries | Partial | Deterministic local summaries, not an AI API. |
| Bonus browser extension | Implemented | Chrome Manifest V3 selector picker under `browser-extension/`. |
| Bonus per-page RSS feed | Implemented | `GET /api/sites/:id/rss.xml` provides events for one monitored site; `GET /api/rss.xml` remains the global feed. |

### Quiet-hour notification queue

Change events created during configured quiet hours are retained in the JSON store and queued for delivery after quiet hours end. Failed queued deliveries are retried with bounded exponential delays (up to five attempts) and exposed through the diagnostics queue count. The JSON store is atomically written with restrictive file permissions and a last-known-good `.bak` copy; if the primary JSON file is malformed on startup, the app attempts recovery from that backup and preserves the corrupt primary for inspection. Monitoring jobs are recorded in the JSON store with queued/running/completed/failed/cancelled states. Queued and interrupted-running jobs are re-queued on startup. This is restart-recoverable JSON persistence, not a transactional multi-process queue; run one server process per data directory.

## Windows PowerShell setup

Use Node.js 20 or newer. In the project folder:

```powershell
npm.cmd install
npm.cmd exec playwright install chromium
npm.cmd test
npm.cmd start
```

Open `http://localhost:3000`. Keep the terminal open while using the dashboard. `npm.cmd` avoids the common PowerShell `npm.ps1` execution-policy issue.

## Browser region picker

1. Open Chrome and navigate to `chrome://extensions`.
2. Enable **Developer mode** and choose **Load unpacked**.
3. Select this project's `browser-extension` folder.
4. Open the public page you want to monitor and click the ChangeWatch Region Picker extension.
5. Choose **Pick region**, click the element, reopen the extension and copy the selector.
6. Paste it into **CSS selector to watch** in ChangeWatch Pro. Use **CSS selector to ignore** for ads, rotating banners or volatile regions.

## Configuration

Copy `.env.example` to `.env` for reference, then configure environment variables in your terminal/hosting provider (the app does not automatically load `.env`).

- `PORT` — default 3000.
- `MAX_CONCURRENT_JOBS` — global in-process browser job concurrency, default 2.
- `CW_AUTH_USER` / `CW_AUTH_PASSWORD` — Basic Auth for the dashboard and API. Both are mandatory when `NODE_ENV=production`.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` — optional email transport; set recipient email in Settings.
- `TZ` — scheduler timezone; default `Asia/Kolkata` in the deployment config.

Discord webhook and Telegram bot/chat settings can be entered in Settings. Never commit credentials or `data/store.json`.

## Deployment

A Dockerfile and `render.yaml` are provided as a starting point. Configure `CW_AUTH_USER` and a strong `CW_AUTH_PASSWORD` in the host before deploying. Persist the `data/` and `snapshots/` directories on a persistent disk/volume; otherwise data may disappear when the host restarts or redeploys. Check the hosting platform's browser support, persistent storage, resource limits and outbound networking before relying on it.

## Project layout

- `server.js` — API, scheduler, bounded queue, browser capture, storage, notifications, exports and RSS.
- `json-storage.js` — atomic JSON writes, last-known-good backup and corrupt-store recovery.
- `intelligence.js` — text normalization, diffs, number extraction, summaries, keyword matching and significance heuristics.
- `public/` — dashboard and comparison UI.
- `browser-extension/` — Chrome region picker.
- `data/store.json` — generated workspace data and notification settings.
- `snapshots/` — captured screenshots for distinct content versions.
- `test.js` — automated unit tests.

## Known limitations / honest caveats

- This is a single-process, single-workspace student prototype. The in-process job queue can recover persisted queued/interrupted job records after restart, but it is not a transactional or distributed queue. Run one server process per data directory.
- Basic Auth is a minimum deployment guard, not a full user/account system. Use HTTPS at the hosting edge and set a strong password. Add proper rate limiting, CSRF strategy and multi-user authorization before a larger public deployment.
- SSRF defenses reduce risk but do not constitute a formal security audit; DNS rebinding and unusual network configurations need further testing.
- Pixel-level screenshot diff is sensitive to layout, fonts, animations and dynamic assets; it is a visual aid, not semantic change detection.
- CAPTCHA/outage classification and number extraction are heuristic and require review on real target pages.
- Analytics can contain synthetic demo records; clearly distinguish demo data from real monitoring in a submission demo.

## Tests

Run `npm.cmd test` for unit tests. Before submission, also run the app locally, test real authorized public pages, verify screenshot/diff behavior, exercise notification channels with test credentials, restart the server to verify persistence, and check the deployed instance after configuring persistent storage and authentication.

## Reliability Lab and numeric history API (integration increment)

The Analytics view includes a **Reliability Lab** with synthetic scenarios for a price change, rotating-ad text, a simulated outage, and repeated/burst version changes. These scenarios are explicitly marked as demo data and do not fetch or modify third-party websites. Run them from Analytics or call `POST /api/lab/run` with `{ "scenario": "price-change" }`, `rotating-ad`, `outage`, or `burst`. List scenarios with `GET /api/lab/scenarios`.

`GET /api/analytics/numbers` returns a bounded JSON history of extracted numeric values; optionally pass `?siteId=<id>&limit=100`. Numeric parsing is heuristic, so values with different units or page-number noise must not be treated as comparable prices without additional rules.

These are controlled synthetic scenarios, not proof of real-world outage/CAPTCHA classification accuracy. Full API/browser acceptance tests still need to be run in an environment with dependencies and Playwright Chromium installed.

## Reliability and diagnostics increment

- Failed checks now use bounded exponential backoff based on the configured interval, capped at 24 hours, and reset the failure counter after a successful page check.
- Adaptive monitoring now adjusts a separate `adaptiveMultiplier` rather than overwriting the user's configured interval. Repeated unchanged checks back off gradually; detected changes bring the multiplier back toward the configured interval.
- `GET /api/diagnostics` provides a non-secret operational view of scheduler queue depth, active jobs, per-site status, failure counters, adaptive multipliers, and recent failures.
- `GET /api/health` reports queue pressure and identifies storage as `local-json-with-backup`; job records are recoverable from JSON, but this is not a transactional multi-process queue. `GET /api/diagnostics` reports job record counts and failed jobs. Jobs are persisted to the JSON store and pending/interrupted jobs are recovered on startup; use a transactional database-backed queue before running multiple application processes against shared storage.

## Security hardening update

- Added a dedicated IP-address guard that blocks private IPv4, loopback, link-local, multicast, IPv6 unique-local, and IPv4-mapped IPv6 destinations.
- Browser requests validate every HTTP(S) destination, including redirect targets, and the final page URL is validated after navigation.
- Redirect chains are bounded to 10 hops.
- Unit tests cover representative private/public IPv4 and IPv6 addresses.

This reduces SSRF risk but is not a substitute for production network egress controls. DNS rebinding and browser/network-layer behavior still require deployment-level testing and ideally an outbound proxy/firewall that blocks private ranges.


### Per-site alert rules

Each monitor can now store an `alertRules` object through `POST /api/sites` or `PATCH /api/sites/:id`. Supported fields are `enabled` (boolean), `minimumScore` (0–100), `minimumSeverity` (`low`, `medium`, `high`, `critical`), `includeKeywords` (comma-separated string), `excludeKeywords` (comma-separated string), and `keywordMode` (`any` or `all`). Existing `keywords` and `sensitivity` settings remain supported for compatibility. Example JSON:

```json
{
  "alertRules": {
    "enabled": true,
    "minimumScore": 35,
    "minimumSeverity": "medium",
    "includeKeywords": "price,availability,deadline",
    "excludeKeywords": "advertisement,related articles",
    "keywordMode": "any"
  }
}
```

Rule decisions are recorded as `lastRuleEvaluation` on the monitor and included in generated events when an alert is allowed. These are deterministic text rules, not semantic AI classification. The dashboard does not yet expose every rule field in a dedicated editor; use the API until that UI is added.

### Reliability Lab benchmark report

`GET /api/lab/benchmark` returns deterministic, local-only fixture checks for price changes, timestamp normalization, duplicate hashes, outage classification, and the same-site burst-coalescing contract. The response is explicitly labelled synthetic. It is **not** a live-browser benchmark, a throughput measurement, or proof that real concurrent requests have been load-tested; those require the full integration test phase.

### Visual comparison memory safeguards

The screenshot pixel-difference preview caps the working canvas to a maximum side length of 1,400 pixels and approximately 1.2 million pixels. Oversized screenshots are downscaled before reading pixel buffers, and the UI reports that downscaling occurred. This reduces browser memory pressure but means the heatmap is a preview, not a pixel-perfect forensic comparison at original resolution. Browser rendering changes, animation, fonts, anti-aliasing, and dynamic page content can still produce false visual differences.

## Configuration backup and restore

- `GET /api/export/config.json` downloads a versioned configuration file containing non-demo monitor definitions and safe settings. It intentionally excludes notification credentials, snapshots, screenshots, and event history.
- `POST /api/import/config.json` accepts that JSON format, validates entries, re-validates each URL against the server's network safety rules, skips already-monitored URLs, and merges valid monitors/settings without deleting current data.
- Import requests use the same authentication as the rest of the API when Basic Auth is enabled. Treat exported configuration as operational metadata, not as a full data backup.

## Website update validation increment

`PATCH /api/sites/:id` now passes through `site-validation.js` before changing a monitor. It rejects unknown fields, incorrect boolean types, invalid monitoring intervals, out-of-range sensitivity values, oversized selectors/keywords, and non-official Discord webhook hosts. This prevents malformed browser/API payloads from silently mutating persisted monitor state. Automated tests cover the validation rules; a live API/browser acceptance pass is still required before deployment.

### Live API smoke tests

Start the application in one terminal (`npm start`), then in a second terminal run `npm run smoke`. The smoke test checks the health, diagnostics, dashboard data, configuration export, Reliability Lab benchmark, RSS, CSV export, and malformed-JSON error handling endpoints against the running server. To test a non-default local URL, set `CW_BASE_URL` (for example, `$env:CW_BASE_URL='http://127.0.0.1:3001'` in PowerShell). These checks are separate from the offline unit-test suite and do not create or modify monitored websites.

### Preparing a JSON-to-SQLite migration (non-destructive)

The migration utility copies the current JSON state into a SQLite database for inspection; it does **not** switch the running server away from JSON yet. Install dependencies first, then run:

```powershell
npm install
npm run migrate:sqlite
```

By default it reads `data/store.json` and creates `data/changewatch.sqlite`. The JSON source is left untouched, and an existing target is not overwritten unless you explicitly pass `--force`:

```powershell
node scripts/migrate-json-to-sqlite.js .\data\store.json .\data\changewatch.sqlite --force
```

Back up your data before migration. Test this on a copy first; the application continues using JSON until a separate, tested runtime cutover is completed.


### Opt-in SQLite runtime storage (experimental)

The default remains JSON storage. After creating and verifying a SQLite copy with `npm run migrate:sqlite`, you can opt into the SQLite state adapter by setting `CW_STORAGE=sqlite` and optionally `CW_SQLITE_PATH=./data/changewatch.sqlite`. If the target SQLite database is empty while the legacy JSON store contains sites, snapshots, events, jobs, pending notifications, or reports, startup now refuses to continue rather than silently showing an empty dashboard. Run the migration first. For a genuinely new installation only, `CW_SQLITE_ALLOW_EMPTY=true` explicitly permits an empty initial database. The adapter persists the complete application state document in one SQLite transaction; this is a compatibility bridge, not yet a normalized relational schema or multi-process job queue. Keep a backup of `data/store.json` and test on a copy before switching. To return to JSON, stop the server and unset `CW_STORAGE` (or set it to `json`). Do not run multiple server processes against the same state file.

### Creating a verified SQLite backup

When using the experimental SQLite adapter, create a consistent online backup (rather than copying a live database file, especially when WAL mode is enabled):

```powershell
npm.cmd run backup:sqlite
# Optional explicit source and destination:
node scripts/backup-sqlite.js .\data\changewatch.sqlite .\data\changewatch-backup.sqlite
```

The command refuses to overwrite an existing destination, checks source integrity, uses SQLite's online backup API, then verifies the backup integrity and application-state payload. Store backups outside the deployed instance as well; a local backup alone does not protect against disk or host loss. This utility requires installed dependencies and has not been validated against a real database in this development environment.
