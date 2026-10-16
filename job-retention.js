'use strict';

// Retain every queued/running job, plus the newest terminal jobs up to the
// configured history limit. Active work must never be discarded just to cap history.
function retainRecentJobs(jobs, limit = 500) {
  if (!Array.isArray(jobs)) throw new TypeError('jobs must be an array');
  if (!Number.isInteger(limit) || limit < 0) throw new RangeError('limit must be a non-negative integer');
  if (jobs.length <= limit) return jobs.slice();

  const active = jobs.filter(job => job && (job.status === 'queued' || job.status === 'running'));
  const terminal = jobs.filter(job => job && job.status !== 'queued' && job.status !== 'running');
  const roomForTerminal = Math.max(0, limit - active.length);
  const newestTerminal = terminal
    .slice()
    .sort((a, b) => Number(b.finishedAt || b.createdAt || 0) - Number(a.finishedAt || a.createdAt || 0))
    .slice(0, roomForTerminal);
  const keepIds = new Set([...active, ...newestTerminal].map(job => job.id));
  return jobs.filter(job => keepIds.has(job.id));
}

module.exports = { retainRecentJobs };
