'use strict';
const fs = require('node:fs');
const path = require('node:path');

/** Read a JSON document, falling back to its last known-good backup if needed. */
function readJsonWithBackup(file, fallback) {
  for (const candidate of [file, `${file}.bak`]) {
    try {
      if (!fs.existsSync(candidate)) continue;
      const parsed = JSON.parse(fs.readFileSync(candidate, 'utf8'));
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) continue;
      return { value: parsed, recoveredFromBackup: candidate !== file, source: candidate };
    } catch { /* Try the backup or caller's fallback. */ }
  }
  return { value: structuredClone(fallback), recoveredFromBackup: false, source: null };
}

/** Atomic JSON persistence with a last-known-good backup and restrictive file mode. */
function writeJsonAtomic(file, value) {
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  const backup = `${file}.bak`;
  let fd;
  try {
    const payload = `${JSON.stringify(value, null, 2)}\n`;
    fd = fs.openSync(tmp, 'w', 0o600);
    fs.writeFileSync(fd, payload, 'utf8');
    fs.fsyncSync(fd);
    fs.closeSync(fd); fd = undefined;
    if (fs.existsSync(file)) {
      // Preserve the current complete file before replacing it. A corrupt current file
      // can still be recovered from this backup if a later write is interrupted.
      const current = fs.readFileSync(file, 'utf8');
      JSON.parse(current); // Never overwrite a known-good backup from a corrupt source.
      const backupTmp = `${backup}.${process.pid}.tmp`;
      fs.writeFileSync(backupTmp, current, { mode: 0o600 });
      fs.renameSync(backupTmp, backup);
    }
    fs.renameSync(tmp, file);
    try { fs.chmodSync(file, 0o600); } catch { /* Some filesystems do not support chmod. */ }
  } catch (error) {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
    try { if (fs.existsSync(tmp)) fs.unlinkSync(tmp); } catch {}
    throw error;
  }
}
module.exports = { readJsonWithBackup, writeJsonAtomic };
