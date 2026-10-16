'use strict';
const net = require('node:net');
const MAX_REDIRECT_HOPS = 10;
function normalizeHostname(hostname) {
  let h = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  // WHATWG URL may expose IPv6 literals without brackets. Normalize IPv4-mapped IPv6 below.
  return h;
}
function isPrivateIPv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a,b] = parts;
  const c = parts[2];
  return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) || (a === 198 && (b === 18 || b === 19)) ||
    // Special-purpose and documentation networks should not be monitor targets.
    (a === 192 && b === 0 && c === 0) || (a === 192 && b === 0 && c === 2) ||
    (a === 192 && b === 88 && c === 99) || (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113);
}
function ipv6MappedIPv4(ip) {
  const x = String(ip).toLowerCase();
  const dotted = x.match(/^(?:::ffff:)(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (dotted) return dotted[1];
  const hex = x.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hex) {
    const a = parseInt(hex[1], 16), b = parseInt(hex[2], 16);
    return `${a >> 8}.${a & 255}.${b >> 8}.${b & 255}`;
  }
  return null;
}
function isPrivateAddress(ip) {
  const x = String(ip || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (net.isIPv4(x)) return isPrivateIPv4(x);
  if (!net.isIPv6(x)) return true; // Fail closed for anything that isn't a parsed IP literal.
  const mapped = ipv6MappedIPv4(x);
  if (mapped) return isPrivateIPv4(mapped);
  // Block unspecified, loopback, unique-local, link-local, multicast, and IPv4-compatible ranges.
  return x === '::' || x === '::1' || x.startsWith('fc') || x.startsWith('fd') ||
    /^fe[89ab]/.test(x) || x.startsWith('ff') || x.startsWith('::') ||
    // Documentation-only and local-use transition ranges are not valid public targets.
    /^2001:db8(?::|$)/.test(x) || /^2001:0(?::|$)/.test(x) || /^2002:/.test(x);
}
module.exports = { isPrivateAddress, normalizeHostname, MAX_REDIRECT_HOPS };
