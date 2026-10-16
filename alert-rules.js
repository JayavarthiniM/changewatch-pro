'use strict';

const SEVERITY = Object.freeze({ low: 1, medium: 2, high: 3, critical: 4 });

function normalizeAlertRules(input = {}) {
  const rules = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
  const words = value => String(value || '').split(',').map(x => x.trim().toLowerCase()).filter(Boolean).slice(0, 50);
  const severity = String(rules.minimumSeverity || 'low').toLowerCase();
  return {
    enabled: rules.enabled !== false,
    minimumScore: Number.isFinite(Number(rules.minimumScore)) ? Math.max(0, Math.min(100, Number(rules.minimumScore))) : 0,
    minimumSeverity: Object.hasOwn(SEVERITY, severity) ? severity : 'low',
    includeKeywords: words(rules.includeKeywords),
    excludeKeywords: words(rules.excludeKeywords),
    keywordMode: rules.keywordMode === 'all' ? 'all' : 'any'
  };
}

function evaluateAlertRules({ score = 0, severity = 'low', added = [], removed = [], rules = {}, legacyKeywords = '' } = {}) {
  const r = normalizeAlertRules(rules);
  if (!r.enabled) return { allowed: false, reason: 'Per-site alerts are disabled', matchedKeywords: [] };
  const numericScore = Math.max(0, Math.min(100, Number(score) || 0));
  if (numericScore < r.minimumScore) return { allowed: false, reason: `Score ${numericScore} is below minimum ${r.minimumScore}`, matchedKeywords: [] };
  const actualSeverity = SEVERITY[String(severity).toLowerCase()] || 1;
  if (actualSeverity < SEVERITY[r.minimumSeverity]) return { allowed: false, reason: `Severity ${severity} is below minimum ${r.minimumSeverity}`, matchedKeywords: [] };
  const text = [...added, ...removed].join(' ').toLowerCase();
  const legacy = String(legacyKeywords || '').split(',').map(x => x.trim().toLowerCase()).filter(Boolean);
  const include = [...new Set([...legacy, ...r.includeKeywords])];
  const matchedKeywords = include.filter(word => text.includes(word));
  if (include.length && (r.keywordMode === 'all' ? matchedKeywords.length !== include.length : matchedKeywords.length === 0)) {
    return { allowed: false, reason: `Required keyword rule (${r.keywordMode}) did not match`, matchedKeywords };
  }
  const excluded = r.excludeKeywords.filter(word => text.includes(word));
  if (excluded.length) return { allowed: false, reason: `Excluded keyword matched: ${excluded.join(', ')}`, matchedKeywords, excludedKeywords: excluded };
  return { allowed: true, reason: 'All per-site alert rules matched', matchedKeywords };
}

module.exports = { normalizeAlertRules, evaluateAlertRules };
