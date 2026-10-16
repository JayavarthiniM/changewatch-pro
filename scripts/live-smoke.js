#!/usr/bin/env node
'use strict';

// Lightweight live-server acceptance checks. Start the app first, then run `npm run smoke`.
// This deliberately uses Node's built-in fetch so the smoke test adds no dependencies.
const base = (process.env.CW_BASE_URL || 'http://127.0.0.1:3000').replace(/\/$/, '');
const { buildBasicAuthHeader } = require('../basic-auth-header');
let authHeader;
try {
  authHeader = buildBasicAuthHeader(process.env.CW_AUTH_USER, process.env.CW_AUTH_PASSWORD);
} catch (error) {
  console.error(`Invalid smoke-test authentication configuration: ${error.message}`);
  process.exit(2);
}
const checks = [
  { name: 'health endpoint', path: '/api/health', type: 'json', validate: x => x && x.ok === true && typeof x.storage === 'string' },
  { name: 'diagnostics endpoint', path: '/api/diagnostics', type: 'json', validate: x => x && x.storage && x.scheduler && Array.isArray(x.sites) },
  { name: 'dashboard data endpoint', path: '/api/data', type: 'json', validate: x => x && Array.isArray(x.sites) && Array.isArray(x.snapshots) && Array.isArray(x.events) && x.settings },
  { name: 'configuration export', path: '/api/export/config.json', type: 'json', validate: x => x && x.format === 'changewatch-config' && Array.isArray(x.sites) },
  { name: 'reliability lab benchmark', path: '/api/lab/benchmark', type: 'json', validate: x => x && typeof x === 'object' },
  { name: 'RSS feed', path: '/api/rss.xml', type: 'text', validate: x => x.includes('<rss') && x.includes('<channel>') },
  { name: 'CSV export', path: '/api/export/csv', type: 'text', validate: x => x.startsWith('"time","site","url","severity","score","summary"') },
  { name: 'malformed JSON returns safe API error', path: '/api/sites', method: 'POST', headers: { 'content-type': 'application/json' }, body: '{not-json', expectedStatus: 400, type: 'json', validate: x => x && x.code === 'INVALID_JSON' && x.error === 'Request body must contain valid JSON' },
];

(async () => {
  let failed = 0;
  for (const check of checks) {
    try {
      const response = await fetch(`${base}${check.path}`, {
        method: check.method || 'GET',
        headers: { ...authHeader, ...(check.headers || {}) },
        body: check.body,
        signal: AbortSignal.timeout(5000)
      });
      const expectedStatus = check.expectedStatus || 200;
      if (response.status !== expectedStatus) throw new Error(`HTTP ${response.status} (expected ${expectedStatus})`);
      const body = check.type === 'json' ? await response.json() : await response.text();
      if (!check.validate(body)) throw new Error('response shape/content did not match expectations');
      process.stdout.write(`PASS ${check.name}\n`);
    } catch (error) {
      failed++;
      process.stderr.write(`FAIL ${check.name}: ${error.message}\n`);
    }
  }
  process.stdout.write(`\n${checks.length - failed}/${checks.length} live API smoke checks passed (${base})\n`);
  if (failed) process.exitCode = 1;
})().catch(error => { console.error(error); process.exitCode = 1; });
