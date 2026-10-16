'use strict';

const ARRAY_FIELDS = ['sites', 'snapshots', 'events', 'pendingNotifications', 'jobs', 'reports'];

/** Normalize older or partially malformed stores without discarding valid records. */
function normalizeStore(loaded, defaults) {
  const source = loaded && typeof loaded === 'object' && !Array.isArray(loaded) ? loaded : {};
  const result = { ...structuredClone(defaults), ...source };
  const warnings = [];

  for (const field of ARRAY_FIELDS) {
    if (!Array.isArray(source[field])) {
      result[field] = structuredClone(defaults[field] || []);
      if (source[field] !== undefined) warnings.push(`Invalid ${field} collection reset to defaults`);
    }
  }

  if (!source.settings || typeof source.settings !== 'object' || Array.isArray(source.settings)) {
    result.settings = structuredClone(defaults.settings || {});
    if (source.settings !== undefined) warnings.push('Invalid settings object reset to defaults');
  } else {
    result.settings = { ...(defaults.settings || {}), ...source.settings };
  }

  const version = Number(source.schemaVersion);
  result.schemaVersion = Number.isInteger(version) && version >= 1 ? version : (defaults.schemaVersion || 1);
  if (source.schemaVersion !== result.schemaVersion) warnings.push('Store schema version normalized');
  return { value: result, warnings };
}

module.exports = { normalizeStore };
