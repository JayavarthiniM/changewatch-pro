'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  cleanText,
  extractNumbers,
  diffText,
  summarizeChange,
  matchesKeywords,
  shouldAlert,
  significance
} = require('./intelligence');

test('noise cleaner normalizes whitespace and timestamps', () => {
  assert.equal(cleanText('Hello   world 12:30'), 'Hello world TIME');
});

test('text diff identifies additions and removals', () => {
  const d = diffText('price is ten', 'price is twelve');
  assert.deepEqual(d.removed, ['ten']);
  assert.deepEqual(d.added, ['twelve']);
});

test('identical text has empty diff', () => {
  const d = diffText('same page text', 'same page text');
  assert.equal(d.added.length, 0);
  assert.equal(d.removed.length, 0);
});

test('hash is deterministic', () => {
  const h = s => crypto.createHash('sha256').update(s).digest('hex');
  assert.equal(h('abc'), h('abc'));
  assert.notEqual(h('abc'), h('abd'));
});

test('extracts prices, percentages, and plain numeric values', () => {
  const values = extractNumbers('Price $1,299.50, discount 10%, stock 25');
  assert.deepEqual(values.map(x => x.value), ['$1,299.50', '10%', '25']);
});

test('summarizes additions and removals', () => {
  assert.equal(
    summarizeChange(['Price', 'increased'], ['Price', 'decreased']),
    'Added: Price increased. Removed: Price decreased.'
  );
});

test('keyword matching is case-insensitive and empty keywords match all', () => {
  assert.equal(matchesKeywords(['Price', 'increased'], [], 'price'), true);
  assert.equal(matchesKeywords(['New', 'colour'], [], 'price'), false);
  assert.equal(matchesKeywords(['New'], [], ''), true);
});

test('duplicate alert logic ignores unchanged hashes', () => {
  assert.equal(shouldAlert('abc', 'abc'), false);
  assert.equal(shouldAlert('abc', 'def'), true);
  assert.equal(shouldAlert('', 'def'), true);
  assert.equal(shouldAlert('abc', ''), false);
});

test('significance returns bounded score and explanation', () => {
  const d = diffText('price is ten', 'price is twelve');
  const s = significance(d, 'price is ten', 'price is twelve');

  assert.ok(s.score >= 0 && s.score <= 100);
  assert.equal(s.changedTokens, 2);
  assert.match(s.explanation, /2 token changes/);
});

test('noise cleaner normalizes UUID-like IDs and long random tokens', () => {
  const text = cleanText(
    'Release 550e8400-e29b-41d4-a716-446655440000 token AbCdEfGhIjKlMnOpQrStUvWxYz123456'
  );

  assert.match(text, /RANDOM_ID/);
  assert.match(text, /RANDOM_TOKEN/);
});

const {
  isPrivateAddress,
  normalizeHostname,
  MAX_REDIRECT_HOPS
} = require('./security');

test('SSRF guard blocks private, loopback, link-local and mapped IPv4 addresses', () => {
  for (const ip of [
    '127.0.0.1',
    '10.0.0.5',
    '192.168.1.1',
    '169.254.169.254',
    '::1',
    'fc00::1',
    'fe80::1',
    '::ffff:127.0.0.1',
    '::ffff:7f00:1'
  ]) {
    assert.equal(isPrivateAddress(ip), true, ip);
  }
});

test('SSRF guard allows public IP addresses', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) {
    assert.equal(isPrivateAddress(ip), false, ip);
  }
});

test('SSRF guard blocks reserved and documentation-only address ranges', () => {
  for (const ip of [
    '192.0.2.10',
    '198.51.100.20',
    '203.0.113.9',
    '192.88.99.1',
    '2001:db8::1',
    '2001:0::1',
    '2002:0808:0808::1'
  ]) {
    assert.equal(isPrivateAddress(ip), true, ip);
  }

  assert.equal(isPrivateAddress('9.9.9.9'), false);
});

test('redirect hop guard is bounded and hostname normalization is consistent', () => {
  assert.equal(MAX_REDIRECT_HOPS, 10);
  assert.equal(normalizeHostname('EXAMPLE.COM.'), 'example.com');
});

const { isQuietHours } = require('./notification-policy');

test('quiet hours handles windows crossing midnight', () => {
  assert.equal(
    isQuietHours(
      { quietStart: '22:00', quietEnd: '08:00' },
      new Date(2026, 0, 1, 23, 0)
    ),
    true
  );

  assert.equal(
    isQuietHours(
      { quietStart: '22:00', quietEnd: '08:00' },
      new Date(2026, 0, 1, 7, 59)
    ),
    true
  );

  assert.equal(
    isQuietHours(
      { quietStart: '22:00', quietEnd: '08:00' },
      new Date(2026, 0, 1, 12, 0)
    ),
    false
  );
});

test('quiet hours supports same-day windows and rejects invalid times safely', () => {
  assert.equal(
    isQuietHours(
      { quietStart: '13:00', quietEnd: '14:00' },
      new Date(2026, 0, 1, 13, 30)
    ),
    true
  );

  assert.equal(
    isQuietHours(
      { quietStart: '99:00', quietEnd: '08:00' },
      new Date(2026, 0, 1, 7, 0)
    ),
    false
  );
});

const {
  normalizeAlertRules,
  evaluateAlertRules
} = require('./alert-rules');

test('per-site alert rules enforce score and severity thresholds', () => {
  assert.equal(
    evaluateAlertRules({
      score: 20,
      severity: 'low',
      added: ['price'],
      rules: { minimumScore: 30 }
    }).allowed,
    false
  );

  assert.equal(
    evaluateAlertRules({
      score: 90,
      severity: 'high',
      added: ['price'],
      rules: { minimumSeverity: 'critical' }
    }).allowed,
    false
  );

  assert.equal(
    evaluateAlertRules({
      score: 90,
      severity: 'critical',
      added: ['price'],
      rules: { minimumSeverity: 'critical' }
    }).allowed,
    true
  );
});

test('per-site alert rules support include any/all and excluded keywords', () => {
  assert.equal(
    evaluateAlertRules({
      score: 90,
      severity: 'high',
      added: ['price', 'changed'],
      rules: { includeKeywords: 'price,launch', keywordMode: 'any' }
    }).allowed,
    true
  );

  assert.equal(
    evaluateAlertRules({
      score: 90,
      severity: 'high',
      added: ['price'],
      rules: { includeKeywords: 'price,launch', keywordMode: 'all' }
    }).allowed,
    false
  );

  assert.equal(
    evaluateAlertRules({
      score: 90,
      severity: 'high',
      added: ['price', 'advertisement'],
      rules: { excludeKeywords: 'advertisement' }
    }).allowed,
    false
  );
});

test('per-site alert rules can disable notifications and normalize unsafe values', () => {
  assert.equal(
    evaluateAlertRules({
      score: 100,
      severity: 'critical',
      added: ['price'],
      rules: { enabled: false }
    }).allowed,
    false
  );

  const r = normalizeAlertRules({
    minimumScore: 999,
    minimumSeverity: 'nonsense',
    keywordMode: 'anything'
  });

  assert.equal(r.minimumScore, 100);
  assert.equal(r.minimumSeverity, 'low');
  assert.equal(r.keywordMode, 'any');
});

const { runReliabilityBenchmark } = require('./reliability-benchmark');

test('Reliability Lab benchmark passes deterministic local scenarios', () => {
  const report = runReliabilityBenchmark();

  assert.equal(report.synthetic, true);
  assert.equal(report.summary.failed, 0);
  assert.equal(report.summary.passed, report.summary.total);
  assert.ok(report.cases.some(c => c.name === 'price change detected'));
  assert.ok(report.cases.some(c => c.name === 'timestamp noise normalized'));
});

test('Reliability Lab benchmark clearly disclaims live load testing', () => {
  const report = runReliabilityBenchmark();
  assert.match(report.note, /not a live-browser, network, or throughput benchmark/i);
});

const { explainChange } = require('./intelligence');

test('explainable change reports rule-based categories and counts', () => {
  const result = explainChange(
    {
      added: ['Price', 'increased', '10%'],
      removed: ['available']
    },
    'Price 9 USD available',
    'Price 10 USD'
  );

  assert.ok(result.categories.includes('price'));
  assert.ok(result.categories.includes('availability'));
  assert.equal(result.numericCounts.old, 1);
  assert.match(result.note, /Rule-based/);
});

test('explainable change labels ordinary text without claiming semantic certainty', () => {
  const result = explainChange(
    { added: ['Welcome'], removed: [] },
    '',
    'Welcome'
  );

  assert.deepEqual(result.categories, ['content']);
  assert.match(result.note, /not verified semantic intent/);
});

const {
  buildConfigExport,
  validateConfigImport
} = require('./config-transfer');

test('configuration export excludes credentials, history, and demo sites', () => {
  const exported = buildConfigExport({
    sites: [
      {
        url: 'https://example.com/',
        name: 'Example',
        interval: 30,
        discordWebhook: 'secret',
        demo: false
      },
      {
        url: 'https://demo.invalid/',
        demo: true
      }
    ],
    settings: {
      theme: 'dark',
      telegramToken: 'secret',
      email: 'private@example.com',
      sensitivity: 25
    },
    snapshots: [{ text: 'private page' }]
  });

  assert.equal(exported.sites.length, 1);
  assert.equal(exported.sites[0].discordWebhook, undefined);
  assert.equal(exported.settings.telegramToken, undefined);
  assert.equal(exported.settings.email, undefined);
  assert.equal(JSON.stringify(exported).includes('private page'), false);
});

test('configuration import validates format, bounds fields, and rejects duplicate or unsafe URLs', () => {
  assert.throws(
    () => validateConfigImport({ format: 'wrong', version: 1, sites: [] }),
    /Unsupported/
  );

  assert.throws(
    () => validateConfigImport({
      format: 'changewatch-config',
      version: 1,
      sites: [{ url: 'file:///etc/passwd' }]
    }),
    /HTTP\(S\)/
  );

  assert.throws(
    () => validateConfigImport({
      format: 'changewatch-config',
      version: 1,
      sites: [
        { url: 'https://example.com' },
        { url: 'https://example.com/' }
      ]
    }),
    /Duplicate URL/
  );

  const valid = validateConfigImport({
    format: 'changewatch-config',
    version: 1,
    sites: [{
      url: 'https://example.com',
      interval: 99999,
      name: 'x'.repeat(200),
      sensitivity: 200
    }]
  });

  assert.equal(valid.sites[0].interval, 1440);
  assert.equal(valid.sites[0].name.length, 100);
  assert.equal(valid.sites[0].sensitivity, 100);
});

const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');

const {
  readJsonWithBackup,
  writeJsonAtomic
} = require('./json-storage');

test('JSON storage writes complete data and keeps a last-known-good backup', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-store-'));

  try {
    const file = path.join(dir, 'store.json');

    writeJsonAtomic(file, { revision: 1, sites: [] });
    writeJsonAtomic(file, { revision: 2, sites: [{ id: 'a' }] });

    assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).revision, 2);
    assert.equal(JSON.parse(fs.readFileSync(`${file}.bak`, 'utf8')).revision, 1);

    // POSIX permission bits are not portable to Windows.
    // Keep the strict check on POSIX platforms.
    if (process.platform !== 'win32') {
      assert.equal((fs.statSync(file).mode & 0o777), 0o600);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('JSON storage recovers from a corrupt primary using the valid backup', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-recover-'));

  try {
    const file = path.join(dir, 'store.json');

    fs.writeFileSync(file, '{broken');
    fs.writeFileSync(`${file}.bak`, JSON.stringify({ revision: 7, sites: [] }));

    const result = readJsonWithBackup(file, { revision: 0 });

    assert.equal(result.recoveredFromBackup, true);
    assert.equal(result.value.revision, 7);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('JSON storage uses fallback when both primary and backup are invalid', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-fallback-'));

  try {
    const file = path.join(dir, 'store.json');

    fs.writeFileSync(file, '{broken');
    fs.writeFileSync(`${file}.bak`, '[]');

    assert.deepEqual(
      readJsonWithBackup(file, { safe: true }).value,
      { safe: true }
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

const { validateSettingsPatch } = require('./settings-validation');

test('settings validation accepts a safe partial update and normalizes strings', () => {
  assert.deepEqual(
    validateSettingsPatch({
      email: '  test@example.com ',
      digest: true,
      sensitivity: 45
    }),
    {
      email: 'test@example.com',
      digest: true,
      sensitivity: 45
    }
  );
});

test('settings validation rejects malformed email, invalid quiet hours, and out-of-range sensitivity', () => {
  assert.throws(
    () => validateSettingsPatch({ email: 'not-an-email' }),
    /valid email/
  );

  assert.throws(
    () => validateSettingsPatch({ quietStart: '25:70' }),
    /HH:MM/
  );

  assert.throws(
    () => validateSettingsPatch({ sensitivity: 101 }),
    /between 0 and 100/
  );
});

test('settings validation blocks unsafe Discord webhook destinations and unknown keys', () => {
  assert.throws(
    () => validateSettingsPatch({
      discordWebhook: 'http://discord.com/api/webhooks/x/y'
    }),
    /official HTTPS/
  );

  assert.throws(
    () => validateSettingsPatch({
      discordWebhook: 'https://evil.example/webhook'
    }),
    /official HTTPS/
  );

  assert.throws(
    () => validateSettingsPatch({ admin: true }),
    /Unsupported setting/
  );
});

const { validateSitePatch } = require('./site-validation');

test('website patch validation accepts a valid typed partial update', () => {
  assert.deepEqual(
    validateSitePatch({
      name: '  Product Watch ',
      paused: true,
      interval: 60,
      sensitivity: 35
    }),
    {
      name: 'Product Watch',
      paused: true,
      interval: 60,
      sensitivity: 35
    }
  );
});

test('website patch validation rejects wrong types, unknown fields, and unsafe webhook URLs', () => {
  assert.throws(
    () => validateSitePatch({ paused: 'false' }),
    /true or false/
  );

  assert.throws(
    () => validateSitePatch({ interval: 2 }),
    /between 15 and 1440/
  );

  assert.throws(
    () => validateSitePatch({ isAdmin: true }),
    /Unsupported website field/
  );

  assert.throws(
    () => validateSitePatch({ discordWebhook: 'https://evil.example/hook' }),
    /official HTTPS/
  );
});

test('website patch validation bounds selector and keyword input sizes', () => {
  assert.throws(
    () => validateSitePatch({ watchSelector: 'x'.repeat(301) }),
    /at most 300/
  );

  assert.throws(
    () => validateSitePatch({ keywords: 'x'.repeat(1001) }),
    /at most 1000/
  );

  assert.throws(
    () => validateSitePatch({}),
    /No website fields/
  );
});

const { retainRecentJobs } = require('./job-retention');

test('job retention preserves queued and running work even when active jobs exceed history limit', () => {
  const jobs = [
    { id: 'q1', status: 'queued', createdAt: 1 },
    { id: 'r1', status: 'running', createdAt: 2 },
    { id: 'q2', status: 'queued', createdAt: 3 },
    { id: 'done', status: 'completed', createdAt: 4, finishedAt: 5 }
  ];

  const kept = retainRecentJobs(jobs, 2);

  assert.deepEqual(kept.map(j => j.id), ['q1', 'r1', 'q2']);
});

test('job retention keeps newest terminal records and all active jobs', () => {
  const jobs = [
    { id: 'old', status: 'completed', finishedAt: 1 },
    { id: 'queued', status: 'queued', createdAt: 2 },
    { id: 'new', status: 'failed', finishedAt: 9 },
    { id: 'mid', status: 'cancelled', finishedAt: 5 }
  ];

  assert.deepEqual(
    retainRecentJobs(jobs, 3).map(j => j.id),
    ['queued', 'new', 'mid']
  );
});

test('job retention rejects invalid inputs and does not mutate input', () => {
  const jobs = [{ id: 'a', status: 'completed', finishedAt: 1 }];

  assert.throws(() => retainRecentJobs(null, 2), /array/);
  assert.throws(() => retainRecentJobs(jobs, -1), /non-negative/);
  assert.equal(retainRecentJobs(jobs, 5).length, 1);
  assert.equal(jobs.length, 1);
});

const { createRateLimiter } = require('./api-rate-limit');

test('API rate limiter allows requests up to the configured limit and resets by window', () => {
  let time = 1_000;

  const limiter = createRateLimiter({
    windowMs: 10_000,
    max: 2,
    now: () => time
  });

  assert.equal(limiter.consume('client-a', time).allowed, true);
  assert.equal(limiter.consume('client-a', time).remaining, 0);
  assert.equal(limiter.consume('client-a', time).allowed, false);

  time += 10_000;

  assert.equal(limiter.consume('client-a', time).allowed, true);
});

test('API rate limiter isolates clients and validates configuration', () => {
  const limiter = createRateLimiter({
    windowMs: 1000,
    max: 1,
    now: () => 100
  });

  assert.equal(limiter.consume('a', 100).allowed, true);
  assert.equal(limiter.consume('b', 100).allowed, true);
  assert.equal(limiter.consume('a', 100).allowed, false);
  assert.throws(() => createRateLimiter({ max: 0 }), /positive integer/);
});

test('API limiter middleware emits headers and returns HTTP 429 after limit', () => {
  let time = 10_000;

  const limiter = createRateLimiter({
    windowMs: 60_000,
    max: 1,
    now: () => time,
    keyFor: req => req.client
  });

  const invoke = client => {
    const headers = {};
    let statusCode = 200;
    let payload;
    let nextCalled = false;

    const res = {
      setHeader: (k, v) => {
        headers[k] = v;
      },
      status: code => {
        statusCode = code;
        return res;
      },
      json: body => {
        payload = body;
        return body;
      }
    };

    limiter({ client }, res, () => {
      nextCalled = true;
    });

    return { headers, statusCode, payload, nextCalled };
  };

  const first = invoke('a');

  assert.equal(first.nextCalled, true);
  assert.equal(first.headers['RateLimit-Remaining'], '0');

  const second = invoke('a');

  assert.equal(second.statusCode, 429);
  assert.equal(second.nextCalled, false);
  assert.equal(second.headers['Retry-After'], '60');
  assert.match(second.payload.error, /rate limit exceeded/i);

  time += 60_000;

  assert.equal(invoke('a').nextCalled, true);
});

test('API limiter bounds memory used by distinct client keys', () => {
  const limiter = createRateLimiter({
    max: 2,
    maxBuckets: 2,
    now: () => 100
  });

  limiter.consume('a');
  limiter.consume('b');
  limiter.consume('c');

  assert.equal(limiter.size(), 2);
});

const { normalizeStore } = require('./store-normalization');

test('store normalization preserves valid data and fills missing collections/settings', () => {
  const defaults = {
    sites: [],
    snapshots: [],
    events: [],
    pendingNotifications: [],
    jobs: [],
    reports: [],
    settings: { theme: 'dark', sensitivity: 20 },
    schemaVersion: 2
  };

  const site = { id: 'site-1', url: 'https://example.com/' };

  const result = normalizeStore({
    sites: [site],
    settings: { theme: 'light' },
    schemaVersion: 2
  }, defaults);

  assert.deepEqual(result.value.sites, [site]);
  assert.deepEqual(result.value.settings, { theme: 'light', sensitivity: 20 });
  assert.deepEqual(result.value.snapshots, []);
  assert.equal(result.value.schemaVersion, 2);
});

test('store normalization safely resets malformed collection and settings shapes', () => {
  const defaults = {
    sites: [],
    snapshots: [],
    events: [],
    pendingNotifications: [],
    jobs: [],
    reports: [],
    settings: { theme: 'dark' },
    schemaVersion: 2
  };

  const result = normalizeStore({
    sites: { bad: true },
    settings: ['bad'],
    schemaVersion: 'broken'
  }, defaults);

  assert.deepEqual(result.value.sites, []);
  assert.deepEqual(result.value.settings, { theme: 'dark' });
  assert.equal(result.value.schemaVersion, 2);
  assert.equal(result.warnings.length, 3);
});

test('store normalization does not mutate caller defaults', () => {
  const defaults = {
    sites: [],
    snapshots: [],
    events: [],
    pendingNotifications: [],
    jobs: [],
    reports: [],
    settings: { theme: 'dark' },
    schemaVersion: 2
  };

  normalizeStore({ sites: ['x'] }, defaults).value.sites.push('y');

  assert.deepEqual(defaults.sites, []);
});

const { parseStore } = require('./scripts/migrate-json-to-sqlite');

test('SQLite migration parser accepts a valid JSON store and fingerprints the exact source', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-migration-'));

  try {
    const file = path.join(dir, 'store.json');
    const raw = JSON.stringify({
      schemaVersion: 2,
      sites: [{ id: 's1' }],
      snapshots: [],
      events: [],
      jobs: []
    });

    fs.writeFileSync(file, raw);

    const result = parseStore(file);

    assert.deepEqual(result.value.sites, [{ id: 's1' }]);
    assert.equal(
      result.sha256,
      require('node:crypto').createHash('sha256').update(raw).digest('hex')
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('SQLite migration parser rejects non-object stores and malformed core collections', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-migration-'));

  try {
    const file = path.join(dir, 'store.json');

    fs.writeFileSync(file, '[]');
    assert.throws(() => parseStore(file), /JSON object/);

    fs.writeFileSync(file, JSON.stringify({ sites: { broken: true } }));
    assert.throws(() => parseStore(file), /sites.*array/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

const { createSqliteStorage } = require('./sqlite-storage');

test('SQLite runtime adapter saves and reloads state through a transaction boundary', () => {
  class FakeDatabase {
    constructor() {
      this.row = null;
      this.closed = false;
    }

    pragma(name) {
      return name === 'integrity_check' ? 'ok' : undefined;
    }

    exec() {}

    prepare(sql) {
      if (sql.includes('SELECT payload_json')) {
        return {
          get: () => this.row && {
            payload_json: this.row.payload_json
          }
        };
      }

      if (sql.includes('INSERT INTO app_state')) {
        return {
          run: row => {
            this.row = { ...row, payload_json: row.payload };
          }
        };
      }

      throw new Error(`Unexpected SQL: ${sql}`);
    }

    transaction(fn) {
      return (...args) => fn(...args);
    }

    close() {
      this.closed = true;
    }
  }

  let instance;

  class Database extends FakeDatabase {
    constructor(filename) {
      super();
      instance = this;
      this.filename = filename;
    }
  }

  const storage = createSqliteStorage({
    filename: './test-state.sqlite',
    Database
  });

  const fallback = { sites: [], schemaVersion: 2 };

  assert.deepEqual(storage.load(fallback), {
    value: fallback,
    recovered: false,
    empty: true
  });

  const state = {
    sites: [{ id: 's1' }],
    schemaVersion: 2
  };

  storage.save(state);

  assert.deepEqual(storage.load(fallback), {
    value: state,
    recovered: false,
    empty: false
  });

  assert.equal(storage.integrityCheck(), 'ok');

  storage.close();

  assert.equal(instance.closed, true);
});

test('SQLite runtime adapter refuses malformed saved state rather than overwriting it', () => {
  class Database {
    pragma(name) {
      return name === 'integrity_check' ? 'ok' : undefined;
    }

    exec() {}

    prepare(sql) {
      if (sql.includes('SELECT payload_json')) {
        return {
          get: () => ({ payload_json: 'not-json' })
        };
      }

      return { run() {} };
    }

    transaction(fn) {
      return fn;
    }

    close() {}
  }

  const storage = createSqliteStorage({
    filename: './invalid-state.sqlite',
    Database
  });

  assert.throws(
    () => storage.load({ sites: [] }),
    /refusing to overwrite/
  );

  storage.close();
});

const { validatePaths } = require('./scripts/backup-sqlite');

test('SQLite backup path validation requires distinct existing source and new target', () => {
  const exists = p => p.endsWith('source.sqlite');

  assert.throws(() => validatePaths('', 'target.sqlite', { exists }), /required/);
  assert.throws(() => validatePaths('source.sqlite', 'source.sqlite', { exists }), /different/);
  assert.throws(() => validatePaths('missing.sqlite', 'target.sqlite', { exists }), /does not exist/);

  assert.deepEqual(
    validatePaths('source.sqlite', 'target.sqlite', { exists }),
    {
      source: path.resolve('source.sqlite'),
      target: path.resolve('target.sqlite')
    }
  );
});

const { assertSafeSqliteBootstrap } = require('./sqlite-storage');

test('SQLite startup refuses to silently ignore an existing populated JSON store', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-sqlite-bootstrap-'));

  try {
    const legacy = path.join(dir, 'store.json');

    fs.writeFileSync(legacy, JSON.stringify({
      sites: [{ id: 'existing-site' }],
      snapshots: [],
      events: []
    }));

    assert.throws(
      () => assertSafeSqliteBootstrap({
        sqliteEmpty: true,
        legacyJsonPath: legacy
      }),
      /contains existing application data/
    );

    assert.deepEqual(
      assertSafeSqliteBootstrap({
        sqliteEmpty: false,
        legacyJsonPath: legacy
      }),
      { blocked: false }
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('SQLite startup blocks malformed legacy data but supports explicit intentional empty bootstrap', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-sqlite-bootstrap-'));

  try {
    const legacy = path.join(dir, 'store.json');

    fs.writeFileSync(legacy, '{bad json');

    assert.throws(
      () => assertSafeSqliteBootstrap({
        sqliteEmpty: true,
        legacyJsonPath: legacy
      }),
      /could not be parsed/
    );

    assert.deepEqual(
      assertSafeSqliteBootstrap({
        sqliteEmpty: true,
        legacyJsonPath: legacy,
        allowEmpty: true
      }),
      { blocked: false }
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('SQLite startup guard preserves customized settings even when no sites exist', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-sqlite-settings-'));

  try {
    const legacy = path.join(dir, 'store.json');

    fs.writeFileSync(legacy, JSON.stringify({
      sites: [],
      snapshots: [],
      events: [],
      jobs: [],
      pendingNotifications: [],
      reports: [],
      settings: {
        theme: 'light',
        email: '',
        telegramToken: '',
        telegramChatId: '',
        discordWebhook: '',
        quietStart: '22:00',
        quietEnd: '08:00',
        digest: false,
        sensitivity: 20
      }
    }));

    assert.throws(
      () => assertSafeSqliteBootstrap({
        sqliteEmpty: true,
        legacyJsonPath: legacy
      }),
      /customized settings/
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('SQLite runtime adapter creates missing parent directories before opening storage', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-sqlite-path-'));

  class Database {
    constructor(filename) {
      this.filename = filename;
    }

    pragma() {}
    exec() {}

    prepare(sql) {
      if (sql.includes('SELECT payload_json')) {
        return { get: () => null };
      }

      return { run() {} };
    }

    transaction(fn) {
      return fn;
    }

    close() {}
  }

  try {
    const target = path.join(dir, 'nested', 'data', 'app.sqlite');

    const storage = createSqliteStorage({
      filename: target,
      Database
    });

    assert.equal(fs.existsSync(path.dirname(target)), true);
    assert.equal(storage.filename, target);

    storage.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('SQLite backup removes an invalid partial artifact when verification fails', async () => {
  const { backupSqlite } = require('./scripts/backup-sqlite');

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-sqlite-backup-cleanup-'));
  const source = path.join(dir, 'source.sqlite');
  const target = path.join(dir, 'backup.sqlite');

  fs.writeFileSync(source, 'source-placeholder');

  class FakeDatabase {
    constructor(filename, options = {}) {
      this.filename = filename;
      this.options = options;
    }

    pragma() {
      return 'ok';
    }

    async backup(destination) {
      fs.writeFileSync(destination, 'partial-backup');
    }

    prepare(sql) {
      if (sql.includes('sqlite_master')) {
        return { get: () => undefined };
      }

      return { get: () => undefined };
    }

    close() {}
  }

  try {
    await assert.rejects(
      backupSqlite({
        sourcePath: source,
        targetPath: target,
        Database: FakeDatabase
      }),
      /app_state table is missing/
    );

    assert.equal(fs.existsSync(target), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('SQLite backup rejects structurally invalid JSON state and removes the artifact', async () => {
  const { backupSqlite } = require('./scripts/backup-sqlite');

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-sqlite-backup-shape-'));
  const source = path.join(dir, 'source.sqlite');
  const target = path.join(dir, 'backup.sqlite');

  fs.writeFileSync(source, 'source-placeholder');

  class FakeDatabase {
    constructor(filename) {
      this.filename = filename;
    }

    pragma() {
      return 'ok';
    }

    async backup(destination) {
      fs.writeFileSync(destination, 'backup-placeholder');
    }

    prepare(sql) {
      if (sql.includes('sqlite_master')) {
        return { get: () => ({ name: 'app_state' }) };
      }

      return { get: () => ({ payload_json: '[]' }) };
    }

    close() {}
  }

  try {
    await assert.rejects(
      backupSqlite({
        sourcePath: source,
        targetPath: target,
        Database: FakeDatabase
      }),
      /must be a JSON object/
    );

    assert.equal(fs.existsSync(target), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('SQLite bootstrap guard detects populated JSON backup when primary store is missing', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-sqlite-backup-bootstrap-'));

  try {
    const legacy = path.join(dir, 'store.json');

    fs.writeFileSync(`${legacy}.bak`, JSON.stringify({
      sites: [{ id: 'recoverable-site' }],
      snapshots: [],
      events: [],
      settings: { theme: 'dark' }
    }));

    assert.throws(
      () => assertSafeSqliteBootstrap({
        sqliteEmpty: true,
        legacyJsonPath: legacy
      }),
      /store\.json\.bak contains existing application data/
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

const { apiErrorHandler } = require('./api-error-handler');

test('API error handler returns a safe JSON response for malformed JSON', () => {
  let statusCode = 200;
  let body;
  let contentType;

  const req = {
    originalUrl: '/api/sites',
    url: '/api/sites'
  };

  const res = {
    headersSent: false,
    status(code) {
      statusCode = code;
      return this;
    },
    json(value) {
      body = value;
      contentType = 'json';
      return this;
    }
  };

  apiErrorHandler(
    Object.assign(new SyntaxError('sensitive parser detail'), {
      type: 'entity.parse.failed',
      status: 400
    }),
    req,
    res,
    () => assert.fail('unexpected next')
  );

  assert.equal(statusCode, 400);
  assert.deepEqual(body, {
    error: 'Request body must contain valid JSON',
    code: 'INVALID_JSON'
  });
  assert.equal(contentType, 'json');
});

test('API error handler returns 413 for oversized payloads', () => {
  let statusCode = 200;
  let body;

  const req = { originalUrl: '/api/import/config.json' };

  const res = {
    headersSent: false,
    status(code) {
      statusCode = code;
      return this;
    },
    json(value) {
      body = value;
      return this;
    }
  };

  apiErrorHandler(
    Object.assign(new Error('too large'), {
      type: 'entity.too.large',
      status: 413
    }),
    req,
    res,
    () => assert.fail('unexpected next')
  );

  assert.equal(statusCode, 413);
  assert.equal(body.code, 'PAYLOAD_TOO_LARGE');
});

test('API error handler does not expose internal errors and passes non-API errors onward', () => {
  let statusCode = 200;
  let body;
  let forwarded;

  const res = {
    headersSent: false,
    status(code) {
      statusCode = code;
      return this;
    },
    json(value) {
      body = value;
      return this;
    }
  };

  apiErrorHandler(
    new Error('database password leaked'),
    { originalUrl: '/api/data' },
    res,
    () => {}
  );

  assert.equal(statusCode, 500);
  assert.deepEqual(body, {
    error: 'Internal server error',
    code: 'INTERNAL_ERROR'
  });

  apiErrorHandler(
    new Error('page error'),
    { originalUrl: '/' },
    res,
    e => {
      forwarded = e;
    }
  );

  assert.equal(forwarded.message, 'page error');
});

const { buildBasicAuthHeader } = require('./basic-auth-header');

test('smoke-test auth header supports Unicode credentials and colons in passwords', () => {
  const header = buildBasicAuthHeader('monitor-user', 'pāss:word');

  assert.equal(
    Buffer.from(
      header.authorization.slice('Basic '.length),
      'base64'
    ).toString('utf8'),
    'monitor-user:pāss:word'
  );
});

test('smoke-test auth requires a complete credential pair and rejects colon usernames', () => {
  assert.deepEqual(buildBasicAuthHeader('', ''), {});

  assert.throws(
    () => buildBasicAuthHeader('user', ''),
    /Set both CW_AUTH_USER/
  );

  assert.throws(
    () => buildBasicAuthHeader('', 'password'),
    /Set both CW_AUTH_USER/
  );

  assert.throws(
    () => buildBasicAuthHeader('bad:user', 'password'),
    /cannot contain a colon/
  );
});
