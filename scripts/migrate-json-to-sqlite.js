'use strict';

// Safe first-stage migration: preserve the existing JSON store as the source of truth
// and copy its complete document into a transactional SQLite envelope. The server is
// not switched to SQLite by this utility yet.
const fs = require('node:fs');
const path = require('node:path');

function parseStore(sourcePath) {
  const raw = fs.readFileSync(sourcePath, 'utf8');
  const value = JSON.parse(raw);
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Source store must contain a JSON object');
  }
  for (const key of ['sites', 'snapshots', 'events', 'jobs']) {
    if (value[key] !== undefined && !Array.isArray(value[key])) {
      throw new Error(`Source store field "${key}" must be an array`);
    }
  }
  return { value, sha256: require('node:crypto').createHash('sha256').update(raw).digest('hex') };
}

function migrate({ sourcePath, targetPath, force = false, Database } = {}) {
  if (!sourcePath || !targetPath) throw new Error('sourcePath and targetPath are required');
  const source = path.resolve(sourcePath);
  const target = path.resolve(targetPath);
  if (source === target) throw new Error('Source and target paths must be different');
  if (!fs.existsSync(source)) throw new Error(`Source JSON file does not exist: ${source}`);
  if (fs.existsSync(target) && !force) throw new Error(`Target already exists; refusing to overwrite: ${target}`);
  const parsed = parseStore(source);
  const Sqlite = Database || require('better-sqlite3');
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const db = new Sqlite(target);
  try {
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    db.exec(`CREATE TABLE IF NOT EXISTS app_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      schema_version INTEGER NOT NULL,
      payload_json TEXT NOT NULL,
      source_sha256 TEXT NOT NULL,
      migrated_at TEXT NOT NULL
    )`);
    const existing = db.prepare('SELECT id FROM app_state WHERE id = 1').get();
    if (existing && !force) throw new Error('Target database already contains migrated state; use --force to replace it');
    const insert = db.prepare(`INSERT INTO app_state (id, schema_version, payload_json, source_sha256, migrated_at)
      VALUES (1, @schemaVersion, @payload, @hash, @migratedAt)
      ON CONFLICT(id) DO UPDATE SET schema_version=excluded.schema_version, payload_json=excluded.payload_json,
      source_sha256=excluded.source_sha256, migrated_at=excluded.migrated_at`);
    db.transaction(() => insert.run({
      schemaVersion: Number.isInteger(parsed.value.schemaVersion) ? parsed.value.schemaVersion : 1,
      payload: JSON.stringify(parsed.value),
      hash: parsed.sha256,
      migratedAt: new Date().toISOString()
    }))();
    const check = db.pragma('integrity_check', { simple: true });
    if (check !== 'ok') throw new Error(`SQLite integrity check failed: ${check}`);
    const saved = db.prepare('SELECT payload_json, source_sha256 FROM app_state WHERE id=1').get();
    if (!saved || saved.source_sha256 !== parsed.sha256 || JSON.stringify(JSON.parse(saved.payload_json)) !== JSON.stringify(parsed.value)) {
      throw new Error('Post-migration verification failed');
    }
    return { source, target, sha256: parsed.sha256, siteCount: (parsed.value.sites || []).length,
      snapshotCount: (parsed.value.snapshots || []).length, eventCount: (parsed.value.events || []).length,
      jobCount: (parsed.value.jobs || []).length, integrity: check };
  } finally {
    db.close();
  }
}

if (require.main === module) {
  const args = process.argv.slice(2);
  const force = args.includes('--force');
  const positional = args.filter(arg => arg !== '--force');
  const sourcePath = positional[0] || path.join(__dirname, '..', 'data', 'store.json');
  const targetPath = positional[1] || path.join(__dirname, '..', 'data', 'changewatch.sqlite');
  try {
    const result = migrate({ sourcePath, targetPath, force });
    console.log('SQLite migration copy verified. Original JSON source was not modified.');
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(`Migration failed: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = { parseStore, migrate };
