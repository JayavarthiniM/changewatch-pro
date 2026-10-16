'use strict';

// Creates a consistent SQLite backup using better-sqlite3's online backup API.
// This avoids copying a live database file while WAL changes may still be pending.
const fs = require('node:fs');
const path = require('node:path');

function validatePaths(sourcePath, targetPath, { exists = fs.existsSync } = {}) {
  if (!sourcePath || !targetPath) throw new Error('sourcePath and targetPath are required');
  const source = path.resolve(sourcePath);
  const target = path.resolve(targetPath);
  if (source === target) throw new Error('Source and backup paths must be different');
  if (!exists(source)) throw new Error(`SQLite source database does not exist: ${source}`);
  if (exists(target)) throw new Error(`Backup target already exists; refusing to overwrite: ${target}`);
  return { source, target };
}

async function backupSqlite({ sourcePath, targetPath, Database } = {}) {
  const paths = validatePaths(sourcePath, targetPath);
  const Sqlite = Database || require('better-sqlite3');
  fs.mkdirSync(path.dirname(paths.target), { recursive: true });
  const db = new Sqlite(paths.source, { readonly: true, fileMustExist: true });
  try {
    const before = db.pragma('integrity_check', { simple: true });
    if (before !== 'ok') throw new Error(`Source SQLite integrity check failed: ${before}`);
    await db.backup(paths.target);
  } finally {
    db.close();
  }
  let verified = false;
  let verify;
  try {
    verify = new Sqlite(paths.target, { readonly: true, fileMustExist: true });
    const integrity = verify.pragma('integrity_check', { simple: true });
    if (integrity !== 'ok') throw new Error(`Backup integrity check failed: ${integrity}`);
    const tables = verify.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='app_state'").get();
    if (!tables) throw new Error('Backup verification failed: app_state table is missing');
    const row = verify.prepare('SELECT payload_json FROM app_state WHERE id=1').get();
    if (row) {
      let payload;
      try { payload = JSON.parse(row.payload_json); }
      catch { throw new Error('Backup verification failed: application-state payload is invalid JSON'); }
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        throw new Error('Backup verification failed: application-state payload must be a JSON object');
      }
      for (const key of ['sites', 'snapshots', 'events']) {
        if (payload[key] !== undefined && !Array.isArray(payload[key])) {
          throw new Error(`Backup verification failed: application-state ${key} must be an array`);
        }
      }
    }
    verified = true;
    return { ...paths, integrity, hasApplicationState: Boolean(row) };
  } finally {
    if (verify) verify.close();
    // Never leave a corrupt/incomplete artifact at the requested backup path.
    if (!verified) { try { fs.unlinkSync(paths.target); } catch {} }
  }
}

if (require.main === module) {
  const [sourcePath, targetPath] = process.argv.slice(2);
  backupSqlite({ sourcePath: sourcePath || path.join(__dirname, '..', 'data', 'changewatch.sqlite'),
    targetPath: targetPath || path.join(__dirname, '..', 'data', `changewatch-backup-${new Date().toISOString().replace(/[:.]/g, '-')}.sqlite`) })
    .then(result => console.log(`SQLite backup verified.\n${JSON.stringify(result, null, 2)}`))
    .catch(error => { console.error(`SQLite backup failed: ${error.message}`); process.exitCode = 1; });
}

module.exports = { validatePaths, backupSqlite };
