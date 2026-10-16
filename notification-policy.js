'use strict';
function isQuietHours(settings = {}, now = new Date()) {
  const start = String(settings.quietStart || '22:00');
  const end = String(settings.quietEnd || '08:00');
  const current = now.getHours() * 60 + now.getMinutes();
  const parse = value => {
    const match = /^(\d{2}):(\d{2})$/.exec(value);
    if (!match) return null;
    const hour = Number(match[1]), minute = Number(match[2]);
    return hour <= 23 && minute <= 59 ? hour * 60 + minute : null;
  };
  const a = parse(start), b = parse(end);
  if (a === null || b === null || a === b) return false;
  return a < b ? current >= a && current < b : current >= a || current < b;
}
module.exports = { isQuietHours };
