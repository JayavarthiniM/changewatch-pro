'use strict';

const ALLOWED_THEMES = new Set(['dark', 'light', 'system']);
const DISCORD_HOSTS = new Set(['discord.com', 'discordapp.com', 'canary.discord.com', 'ptb.discord.com']);

function validClock(value) {
  if (typeof value !== 'string' || !/^([01]\d|2[0-3]):[0-5]\d$/.test(value)) return false;
  return true;
}

function validateSettingsPatch(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Settings must be a JSON object');
  const out = {};
  const allowed = ['email','telegramToken','telegramChatId','discordWebhook','quietStart','quietEnd','digest','theme','sensitivity'];
  for (const key of Object.keys(input)) if (!allowed.includes(key)) throw new Error(`Unsupported setting: ${key}`);
  for (const key of ['email','telegramToken','telegramChatId','discordWebhook']) {
    if (input[key] === undefined) continue;
    if (typeof input[key] !== 'string' || input[key].length > (key === 'telegramToken' ? 300 : 500)) throw new Error(`Invalid ${key}`);
    const value = input[key].trim();
    if (key === 'email' && value && (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) || value.length > 254)) throw new Error('Enter a valid email address');
    if (key === 'discordWebhook' && value) {
      let url;
      try { url = new URL(value); } catch { throw new Error('Discord webhook must be a valid URL'); }
      if (url.protocol !== 'https:' || !DISCORD_HOSTS.has(url.hostname.toLowerCase()) || url.username || url.password) throw new Error('Discord webhook must use an official HTTPS Discord host');
    }
    out[key] = value;
  }
  for (const key of ['quietStart','quietEnd']) {
    if (input[key] !== undefined) {
      if (!validClock(input[key])) throw new Error(`${key} must use HH:MM (24-hour) format`);
      out[key] = input[key];
    }
  }
  if (input.digest !== undefined) {
    if (typeof input.digest !== 'boolean') throw new Error('digest must be true or false');
    out.digest = input.digest;
  }
  if (input.theme !== undefined) {
    if (typeof input.theme !== 'string' || !ALLOWED_THEMES.has(input.theme)) throw new Error('theme must be dark, light, or system');
    out.theme = input.theme;
  }
  if (input.sensitivity !== undefined) {
    const n = Number(input.sensitivity);
    if (!Number.isFinite(n) || n < 0 || n > 100) throw new Error('sensitivity must be between 0 and 100');
    out.sensitivity = n;
  }
  return out;
}

module.exports = { validateSettingsPatch, validClock };
