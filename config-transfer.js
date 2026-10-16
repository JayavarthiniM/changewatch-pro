'use strict';

const SITE_FIELDS = ['name','interval','paused','watchSelector','ignoreSelector','sensitivity','keywords','adaptive','alertRules'];
const SETTING_FIELDS = ['quietStart','quietEnd','digest','theme','sensitivity'];
function buildConfigExport(db) {
  return {
    format: 'changewatch-config',
    version: 1,
    exportedAt: new Date().toISOString(),
    sites: (Array.isArray(db.sites) ? db.sites : []).filter(s => !s.demo).map(s => {
      const out = { url: s.url };
      for (const key of SITE_FIELDS) if (s[key] !== undefined) out[key] = s[key];
      return out;
    }),
    settings: Object.fromEntries(SETTING_FIELDS.filter(k => db.settings && db.settings[k] !== undefined).map(k => [k, db.settings[k]])),
    secretsExcluded: true
  };
}
function validateConfigImport(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Configuration must be a JSON object');
  if (input.format !== 'changewatch-config' || input.version !== 1) throw new Error('Unsupported configuration format or version');
  if (!Array.isArray(input.sites) || input.sites.length > 500) throw new Error('sites must be an array containing at most 500 entries');
  const seen = new Set();
  const sites = input.sites.map((s, i) => {
    if (!s || typeof s !== 'object' || Array.isArray(s) || typeof s.url !== 'string' || s.url.length > 2048) throw new Error(`Invalid site entry at index ${i}`);
    let url;
    try { url = new URL(s.url); } catch { throw new Error(`Invalid URL at site index ${i}`); }
    if (!['http:','https:'].includes(url.protocol) || url.username || url.password) throw new Error(`Only credential-free HTTP(S) URLs are allowed at site index ${i}`);
    const normalized = url.toString();
    if (seen.has(normalized)) throw new Error(`Duplicate URL in configuration: ${normalized}`);
    seen.add(normalized);
    const out = { url: normalized };
    for (const key of SITE_FIELDS) if (s[key] !== undefined) out[key] = s[key];
    out.name = String(out.name || url.hostname).slice(0,100);
    out.interval = Math.max(15, Math.min(1440, Number(out.interval) || 15));
    out.paused = out.paused === true;
    out.watchSelector = String(out.watchSelector || '').slice(0,300);
    out.ignoreSelector = String(out.ignoreSelector || '').slice(0,300);
    out.keywords = String(out.keywords || '').slice(0,1000);
    out.sensitivity = Math.max(0, Math.min(100, Number(out.sensitivity ?? 20) || 0));
    out.adaptive = out.adaptive === true;
    return out;
  });
  const settings = {};
  if (input.settings && typeof input.settings === 'object' && !Array.isArray(input.settings)) {
    for (const key of SETTING_FIELDS) if (input.settings[key] !== undefined) settings[key] = input.settings[key];
  }
  return { sites, settings };
}
module.exports = { buildConfigExport, validateConfigImport };
