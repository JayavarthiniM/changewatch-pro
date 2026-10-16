'use strict';

/** Build a Basic Authorization header for the optional live API smoke tester. */
function buildBasicAuthHeader(username = '', password = '') {
  const user = String(username || '');
  const pass = String(password || '');
  if (!user && !pass) return {};
  if (!user || !pass) throw new Error('Set both CW_AUTH_USER and CW_AUTH_PASSWORD, or leave both unset');
  if (user.includes(':')) throw new Error('CW_AUTH_USER cannot contain a colon when using HTTP Basic Authentication');
  return { authorization: `Basic ${Buffer.from(`${user}:${pass}`, 'utf8').toString('base64')}` };
}

module.exports = { buildBasicAuthHeader };
