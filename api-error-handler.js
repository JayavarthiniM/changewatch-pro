'use strict';

/** Express error middleware that keeps API failures machine-readable and avoids leaking internals. */
function apiErrorHandler(error, req, res, next) {
  if (res.headersSent) return next(error);
  const isApi = String(req.originalUrl || req.url || '').startsWith('/api/');
  if (!isApi) return next(error);

  const type = String(error && error.type || '');
  if (type === 'entity.too.large' || error && error.status === 413) {
    return res.status(413).json({ error: 'Request body is too large', code: 'PAYLOAD_TOO_LARGE' });
  }
  if (type === 'entity.parse.failed' || error && error.status === 400 && error instanceof SyntaxError) {
    return res.status(400).json({ error: 'Request body must contain valid JSON', code: 'INVALID_JSON' });
  }
  // Do not expose stack traces, filesystem paths, credentials, or dependency errors to clients.
  return res.status(500).json({ error: 'Internal server error', code: 'INTERNAL_ERROR' });
}

module.exports = { apiErrorHandler };
