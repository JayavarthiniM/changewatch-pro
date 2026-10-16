'use strict';

/** In-process API limiter. Use a shared store and trusted proxy configuration for multi-instance deployments. */
function createRateLimiter({ windowMs = 60_000, max = 120, maxBuckets = 10_000, now = Date.now, keyFor = req => req.ip || req.socket?.remoteAddress || 'unknown' } = {}) {
  if (!Number.isFinite(windowMs) || windowMs <= 0) throw new TypeError('windowMs must be positive');
  if (!Number.isInteger(max) || max < 1) throw new TypeError('max must be a positive integer');
  if (!Number.isInteger(maxBuckets) || maxBuckets < 1) throw new TypeError('maxBuckets must be a positive integer');
  const buckets = new Map();
  let lastSweep = 0;

  function consume(key, timestamp = now()) {
    key = String(key || 'unknown');
    let bucket = buckets.get(key);
    if (!bucket || timestamp >= bucket.resetAt) {
      if (buckets.size >= maxBuckets && !buckets.has(key)) {
        // Expired entries are removed first; if still full, evict the oldest entry to bound memory.
        for (const [candidate, entry] of buckets) {
          if (entry.resetAt <= timestamp) buckets.delete(candidate);
        }
        if (buckets.size >= maxBuckets) buckets.delete(buckets.keys().next().value);
      }
      bucket = { count: 0, resetAt: timestamp + windowMs };
      buckets.set(key, bucket);
    }
    bucket.count += 1;
    if (timestamp - lastSweep >= windowMs) {
      for (const [candidate, entry] of buckets) if (entry.resetAt <= timestamp) buckets.delete(candidate);
      lastSweep = timestamp;
    }
    return { allowed: bucket.count <= max, limit: max, remaining: Math.max(0, max - bucket.count), resetAt: bucket.resetAt };
  }

  function middleware(req, res, next) {
    const result = consume(String(keyFor(req)), now());
    res.setHeader('RateLimit-Limit', String(result.limit));
    res.setHeader('RateLimit-Remaining', String(result.remaining));
    res.setHeader('RateLimit-Reset', String(Math.ceil(result.resetAt / 1000)));
    if (!result.allowed) {
      res.setHeader('Retry-After', String(Math.max(1, Math.ceil((result.resetAt - now()) / 1000))));
      return res.status(429).json({ error: 'API rate limit exceeded. Retry after the current window.' });
    }
    return next();
  }
  middleware.consume = consume;
  middleware.clear = () => buckets.clear();
  middleware.size = () => buckets.size;
  return middleware;
}

module.exports = { createRateLimiter };
