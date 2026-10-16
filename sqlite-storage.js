'use strict';

// Optional runtime storage adapter. JSON remains the default until explicitly enabled.
// It stores the application state as one transactional payload so the current server
// can migrate without changing every route at once.
const path = require('node:path');
const fs = require('node:fs');

function assertSafeSqliteBootstrap({ sqliteEmpty, legacyJsonPath, allowEmpty = false, exists = fs.existsSync, readFile = fs.readFileSync } = {}) {
  if (!sqliteEmpty || allowEmpty || !legacyJsonPath) return { blocked: false };
  // JSON storage can recover from store.json.bak when the primary file is missing.
  // SQLite bootstrap must recognize that same recoverable data before initializing empty.
  const backupPath = `${legacyJsonPath}.bak`;
  const legacyPathToRead = exists(legacyJsonPath) ? legacyJsonPath : (exists(backupPath) ? backupPath : null);
  if (!legacyPathToRead) return { blocked: false };
  let legacy;
  try {
    legacy = JSON.parse(readFile(legacyPathToRead, 'utf8'));
  } catch (error) {
    throw new Error(`SQLite is empty and the legacy JSON store could not be parsed (${legacyPathToRead}); refusing to start with empty data: ${error.message}`);
  }
  if (!legacy || typeof legacy !== 'object' || Array.isArray(legacy)) {
    throw new Error(`SQLite is empty and the legacy JSON store is invalid (${legacyPathToRead}); refusing to start with empty data`);
  }
  const collectionKeys = ['sites', 'snapshots', 'events', 'jobs', 'pendingNotifications', 'reports'];
  const hasCollectionData = collectionKeys.some(key => Array.isArray(legacy[key]) && legacy[key].length > 0);
  // Settings are user data too: an installation with no monitored sites may still
  // have SMTP/Telegram/Discord configuration, quiet hours, sensitivity, or theme.
  const settings = legacy.settings;
  const hasCustomSettings = settings && typeof settings === 'object' && !Array.isArray(settings) &&
    Object.entries(settings).some(([key, value]) => {
      if (key === 'theme') return value !== 'dark';
      if (key === 'sensitivity') return value !== 20;
      if (key === 'quietStart') return value !== '22:00';
      if (key === 'quietEnd') return value !== '08:00';
      if (key === 'digest') return value !== false;
      if (typeof value === 'string') return value.length > 0;
      if (typeof value === 'boolean') return value;
      return value !== null && value !== undefined;
    });
  if (hasCollectionData || hasCustomSettings) {
    throw new Error(`SQLite database is empty but ${legacyPathToRead} contains existing application data or customized settings. Run npm run migrate:sqlite -- ${legacyPathToRead} ${process.env.CW_SQLITE_PATH || './data/changewatch.sqlite'} first, or explicitly set CW_SQLITE_ALLOW_EMPTY=true only if you intend to start a new empty database.`);
  }
  return { blocked: false };
}

function createSqliteStorage({ filename, Database } = {}) {
  if (!filename) throw new Error('SQLite filename is required');
  const resolved = path.resolve(filename);
  const Sqlite = Database || require('better-sqlite3');
  // better-sqlite3 does not create missing parent directories. Create them before
  // opening the database, and restrict new directory permissions on POSIX systems.
  fs.mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
  const handle = new Sqlite(resolved);
  // Database files may contain notification tokens and destination details.
  // chmod is best-effort because Windows applies different ACL semantics.
  try { fs.chmodSync(resolved, 0o600); } catch {}
  handle.pragma('journal_mode = WAL');
  handle.pragma('foreign_keys = ON');
  handle.pragma('busy_timeout = 5000');
  handle.exec(`CREATE TABLE IF NOT EXISTS app_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version INTEGER NOT NULL,
    payload_json TEXT NOT NULL,
    source_sha256 TEXT NOT NULL DEFAULT '',
    migrated_at TEXT NOT NULL
  )`);
  const select = handle.prepare('SELECT payload_json FROM app_state WHERE id = 1');
  const upsert = handle.prepare(`INSERT INTO app_state (id, schema_version, payload_json, source_sha256, migrated_at)
    VALUES (1, @schemaVersion, @payload, '', @savedAt)
    ON CONFLICT(id) DO UPDATE SET schema_version=excluded.schema_version,
      payload_json=excluded.payload_json, migrated_at=excluded.migrated_at`);
  const saveTransaction = handle.transaction(state => {
    upsert.run({ schemaVersion: Number.isInteger(state.schemaVersion) ? state.schemaVersion : 1,
      payload: JSON.stringify(state), savedAt: new Date().toISOString() });
  });
  return {
    filename: resolved,
    load(fallback) {
      const row = select.get();
      if (!row) return { value: structuredClone(fallback), recovered: false, empty: true };
      try {
        const value = JSON.parse(row.payload_json);
        if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('SQLite state payload is not an object');
        return { value, recovered: false, empty: false };
      } catch (error) {
        throw new Error(`SQLite state payload is invalid; refusing to overwrite it: ${error.message}`);
      }
    },
    save(state) { saveTransaction(state); },
    integrityCheck() { return handle.pragma('integrity_check', { simple: true }); },
    close() { handle.close(); }
  };
}

module.exports = { createSqliteStorage, assertSafeSqliteBootstrap };
