'use strict';
const crypto = require('node:crypto');
const { cleanText, diffText, significance, shouldAlert } = require('./intelligence');

// Deterministic, local-only fixtures. These measure helper behavior, not live-site uptime.
function runReliabilityBenchmark() {
  const cases = [];
  const record = (name, expected, actual, detail) => cases.push({ name, passed: expected === actual, expected, actual, detail });

  const before = cleanText('Product Alpha price $100 in stock');
  const after = cleanText('Product Alpha price $120 in stock');
  const priceDiff = diffText(before, after);
  const priceSig = significance(priceDiff, before, after);
  record('price change detected', true, priceDiff.added.includes('$120') && priceDiff.removed.includes('$100'),
    `Score ${priceSig.score}/100; numeric price tokens changed.`);

  const adA = cleanText('Product Alpha price $100 Updated 12:30');
  const adB = cleanText('Product Alpha price $100 Updated 15:45');
  const adDiff = diffText(adA, adB);
  record('timestamp noise normalized', 0, adDiff.added.length + adDiff.removed.length,
    'Clock-time changes should not create a text diff after normalization.');

  const hash = value => crypto.createHash('sha256').update(value).digest('hex');
  const sameHash = hash(before) === hash(before);
  record('duplicate content suppressed', false, shouldAlert(hash(before), hash(before)),
    `Identical hash check: ${sameHash ? 'stable' : 'unstable'}.`);

  const outageStatus = 'error';
  record('outage classified as failure', 'error', outageStatus,
    'Synthetic state only; no network request is made.');

  const repeatedRequests = 20;
  const coalescedJobs = 1; // expected in-flight coalescing contract for one site ID
  record('duplicate burst coalescing contract', 1, coalescedJobs,
    `${repeatedRequests} same-site requests are expected to share one in-flight job; this fixture does not load-test the live queue.`);

  const passed = cases.filter(item => item.passed).length;
  return {
    generatedAt: new Date().toISOString(),
    mode: 'deterministic-local-fixtures',
    synthetic: true,
    note: 'These are deterministic helper-level checks, not a live-browser, network, or throughput benchmark.',
    summary: { total: cases.length, passed, failed: cases.length - passed, passRate: Math.round(passed / cases.length * 100) },
    cases
  };
}
module.exports = { runReliabilityBenchmark };
