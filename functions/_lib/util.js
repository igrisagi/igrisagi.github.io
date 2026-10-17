// Shared helpers for ErenLabs Pages Functions.

export function json(body, status, extraHeaders) {
  var h = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
  if (extraHeaders) for (var k in extraHeaders) h[k] = extraHeaders[k];
  return new Response(JSON.stringify(body), { status: status || 200, headers: h });
}

export function uid() { return crypto.randomUUID(); }

export function nowIso() { return new Date().toISOString(); }

export async function sha256hex(text) {
  var buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
}

export function randomToken() {
  var b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode.apply(null, b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function constEq(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  var out = 0;
  for (var i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

export function clientIp(request) {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

export async function ipHash(request) {
  return (await sha256hex(clientIp(request) + '|eren')).slice(0, 24);
}

// Throwing abort: handlers wrap logic and let `respond` convert thrown
// Response objects into real responses.
export function abort(response) { throw response; }

export async function handle(fn) {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof Response) return err;
    return json({ error: 'internal error' }, 500);
  }
}

export async function readJson(request) {
  try { return await request.json(); } catch (e) { abort(json({ error: 'invalid JSON body' }, 400)); }
}

export function str(v, min, max, name) {
  var s = typeof v === 'string' ? v.trim() : '';
  if (s.length < min || s.length > max) abort(json({ error: name + ' must be ' + min + '-' + max + ' characters' }, 400));
  return s;
}

var EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;
export function email(v) {
  var s = typeof v === 'string' ? v.trim().toLowerCase() : '';
  if (!EMAIL_RE.test(s) || s.length > 254) abort(json({ error: 'invalid email address' }, 400));
  return s;
}

// Minimal E.164 normalization: keep leading + and digits, require 8-15 digits.
export function phoneE164(v) {
  var s = typeof v === 'string' ? v.trim() : '';
  var plus = s.charAt(0) === '+';
  var digits = s.replace(/\D/g, '');
  if (digits.length < 8 || digits.length > 15) abort(json({ error: 'invalid phone number' }, 400));
  return (plus ? '+' : '+') + digits;
}

var B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32Encode(bytes) {
  var bits = 0, val = 0, out = '';
  for (var i = 0; i < bytes.length; i++) {
    val = (val << 8) | bytes[i]; bits += 8;
    while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s) {
  var bits = 0, val = 0, out = [];
  s = s.toUpperCase().replace(/[^A-Z2-7]/g, '');
  for (var i = 0; i < s.length; i++) {
    val = (val << 5) | B32.indexOf(s.charAt(i)); bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
