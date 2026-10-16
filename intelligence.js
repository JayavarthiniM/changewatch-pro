'use strict';

function cleanText(s) {
  return String(s ?? '')
    .replace(/\b\d{1,2}:\d{2}(?::\d{2})?\b/g, ' TIME ')
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi, ' RANDOM_ID ')
    .replace(/\b\d{10,13}\b/g, ' COUNTER ')
    .replace(/\b(?=[A-Za-z0-9_-]{24,}\b)(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[a-z])(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]+\b/g, ' RANDOM_TOKEN ')
    .replace(/\s+/g, ' ')
    .trim();
}

function extractNumbers(text) {
  const results = [];
  const regex = /(?:[$€£₹]\s*)?\b\d+(?:,\d{3})*(?:\.\d+)?\s*(?:%|USD|EUR|INR|GBP)?/gi;
  for (const match of String(text || '').matchAll(regex)) {
    const value = match[0].trim();
    if (value) results.push({ value, index: match.index });
  }
  return results;
}

function diffText(a, b) {
  const aa = String(a || '').split(/\s+/).filter(Boolean);
  const bb = String(b || '').split(/\s+/).filter(Boolean);
  if (aa.length * bb.length > 90000) {
    const setA = new Set(aa), setB = new Set(bb);
    return {
      added: bb.filter(x => !setA.has(x)).slice(0, 500),
      removed: aa.filter(x => !setB.has(x)).slice(0, 500),
      method: 'token-set (large page)'
    };
  }
  const dp = Array.from({ length: aa.length + 1 }, () => new Uint32Array(bb.length + 1));
  for (let i = aa.length - 1; i >= 0; i--) {
    for (let j = bb.length - 1; j >= 0; j--) {
      dp[i][j] = aa[i] === bb[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  let i = 0, j = 0;
  const added = [], removed = [];
  while (i < aa.length && j < bb.length) {
    if (aa[i] === bb[j]) { i++; j++; }
    else if (dp[i][j + 1] >= dp[i + 1][j]) added.push(bb[j++]);
    else removed.push(aa[i++]);
  }
  removed.push(...aa.slice(i));
  added.push(...bb.slice(j));
  return { added: added.slice(0, 500), removed: removed.slice(0, 500), method: 'LCS' };
}

function summarizeChange(added = [], removed = []) {
  const additions = added.slice(0, 8).join(' ');
  const removals = removed.slice(0, 8).join(' ');
  if (!added.length && !removed.length) return 'No meaningful text changes detected.';
  if (additions && removals) return `Added: ${additions}. Removed: ${removals}.`;
  if (additions) return `Added: ${additions}.`;
  return `Removed: ${removals}.`;
}

function matchesKeywords(added = [], removed = [], keywords = '') {
  const terms = String(keywords || '').split(',').map(x => x.trim().toLowerCase()).filter(Boolean);
  if (!terms.length) return true;
  const changed = [...added, ...removed].join(' ').toLowerCase();
  return terms.some(term => changed.includes(term));
}

function shouldAlert(previousHash, currentHash) {
  return Boolean(currentHash) && previousHash !== currentHash;
}

function significance(diff, oldText, newText) {
  const total = Math.max(1, String(oldText || '').split(/\s+/).filter(Boolean).length);
  const changed = diff.added.length + diff.removed.length;
  const keywords = ['price', 'sale', 'available', 'unavailable', 'deadline', 'date', 'policy', 'terms', 'security', 'version', 'status', 'launch', 'closed', 'open'];
  const hits = [...diff.added, ...diff.removed].filter(w => keywords.includes(w.toLowerCase().replace(/[^a-z]/g, '')));
  return {
    score: Math.min(100, Math.round((changed / total) * 100 * 5 + hits.length * 8)),
    changedTokens: changed,
    keywordHits: [...new Set(hits)],
    explanation: `${changed} token changes across ${total} prior tokens${hits.length ? `; notable terms: ${[...new Set(hits)].join(', ')}` : ''}`
  };
}

function explainChange(diff, oldText = '', newText = '') {
  const changed = [...(diff?.added || []), ...(diff?.removed || [])].join(' ').toLowerCase();
  const categories = [];
  const rules = [
    ['price', /\b(price|pricing|cost|discount|sale|usd|eur|inr|gbp)\b|[$€£₹]/i],
    ['availability', /\b(available|unavailable|in stock|out of stock|sold out|backorder)\b/i],
    ['deadline-or-date', /\b(deadline|due date|launch date|release date|expires|expiry|january|february|march|april|may|june|july|august|september|october|november|december)\b/i],
    ['policy-or-security', /\b(policy|terms|privacy|security|consent|refund|return policy)\b/i],
    ['version-or-release', /\b(version|release|changelog|updated|upgrade|patch)\b/i]
  ];
  for (const [name, pattern] of rules) if (pattern.test(changed)) categories.push(name);
  if (!categories.length && (diff?.added?.length || diff?.removed?.length)) categories.push('content');
  const oldNumbers = extractNumbers(oldText).map(x => x.value);
  const newNumbers = extractNumbers(newText).map(x => x.value);
  const reasons = [];
  if (diff?.added?.length) reasons.push(`${diff.added.length} added tokens`);
  if (diff?.removed?.length) reasons.push(`${diff.removed.length} removed tokens`);
  const addedTerms = (diff?.added || []).filter(w => /price|cost|sale|available|deadline|policy|security|version|release/i.test(w));
  if (addedTerms.length) reasons.push(`notable terms added: ${[...new Set(addedTerms)].slice(0, 8).join(', ')}`);
  if (oldNumbers.length || newNumbers.length) reasons.push(`numeric values found in both versions: ${oldNumbers.length} before, ${newNumbers.length} after`);
  return { categories, reasons, numericCounts: { old: oldNumbers.length, new: newNumbers.length }, note: 'Rule-based explanation; categories indicate matching terms, not verified semantic intent.' };
}

module.exports = { cleanText, extractNumbers, diffText, summarizeChange, matchesKeywords, shouldAlert, significance, explainChange };
