'use strict';

const DISCORD_HOSTS = new Set(['discord.com', 'discordapp.com', 'canary.discord.com', 'ptb.discord.com']);
const FIELDS = new Set(['name', 'paused', 'watchSelector', 'ignoreSelector', 'keywords', 'adaptive', 'discordWebhook', 'sensitivity', 'interval', 'alertRules']);

function validateSitePatch(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Website update must be a JSON object');
  for (const key of Object.keys(input)) if (!FIELDS.has(key)) throw new Error(`Unsupported website field: ${key}`);
  const out = {};
  if (input.name !== undefined) {
    if (typeof input.name !== 'string' || !input.name.trim() || input.name.trim().length > 100) throw new Error('Website name must contain 1–100 characters');
    out.name = input.name.trim();
  }
  for (const key of ['paused', 'adaptive']) {
    if (input[key] !== undefined) {
      if (typeof input[key] !== 'boolean') throw new Error(`${key} must be true or false`);
      out[key] = input[key];
    }
  }
  for (const key of ['watchSelector', 'ignoreSelector', 'keywords']) {
    if (input[key] !== undefined) {
      const max = key === 'keywords' ? 1000 : 300;
      if (typeof input[key] !== 'string' || input[key].length > max) throw new Error(`${key} must be a string of at most ${max} characters`);
      out[key] = input[key].trim();
    }
  }
  if (input.discordWebhook !== undefined) {
    if (typeof input.discordWebhook !== 'string' || input.discordWebhook.length > 500) throw new Error('Invalid Discord webhook');
    const value = input.discordWebhook.trim();
    if (value) {
      let u;
      try { u = new URL(value); } catch { throw new Error('Discord webhook must be a valid URL'); }
      if (u.protocol !== 'https:' || !DISCORD_HOSTS.has(u.hostname.toLowerCase()) || u.username || u.password) throw new Error('Discord webhook must use an official HTTPS Discord host');
    }
    out.discordWebhook = value;
  }
  if (input.sensitivity !== undefined) {
    const n = Number(input.sensitivity);
    if (!Number.isFinite(n) || n < 0 || n > 100) throw new Error('sensitivity must be between 0 and 100');
    out.sensitivity = n;
  }
  if (input.interval !== undefined) {
    const n = Number(input.interval);
    if (!Number.isInteger(n) || n < 15 || n > 1440) throw new Error('interval must be a whole number between 15 and 1440 minutes');
    out.interval = n;
  }
  if (input.alertRules !== undefined) {
    if (!input.alertRules || typeof input.alertRules !== 'object' || Array.isArray(input.alertRules)) throw new Error('alertRules must be a JSON object');
    out.alertRules = input.alertRules;
  }
  if (!Object.keys(out).length) throw new Error('No website fields to update');
  return out;
}
module.exports = { validateSitePatch };
