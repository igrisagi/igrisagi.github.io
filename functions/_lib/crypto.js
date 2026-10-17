// Password hashing (PBKDF2-SHA-256 via WebCrypto) and TOTP (RFC 6238).
// Cloudflare Workers have no native Argon2; PBKDF2 with 600k iterations is
// the strongest WebCrypto-native KDF available on this stack.
import { base32Encode, base32Decode, constEq } from './util.js';

var ITER = 600000;

function b64(bytes) { return btoa(String.fromCharCode.apply(null, new Uint8Array(bytes))); }
function unb64(s) { return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); }); }

export async function hashPassword(password) {
  var salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  var key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  var bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: ITER }, key, 256);
  return 'pbkdf2$' + ITER + '$' + b64(salt) + '$' + b64(bits);
}

export async function verifyPassword(password, stored) {
  try {
    var parts = String(stored || '').split('$');
    if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
    var iter = parseInt(parts[1], 10);
    var salt = unb64(parts[2]);
    var key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    var bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: iter }, key, 256);
    return constEq(b64(bits), parts[3]);
  } catch (e) { return false; }
}

export function generateTotpSecret() {
  var b = new Uint8Array(20);
  crypto.getRandomValues(b);
  return base32Encode(b);
}

async function hotp(secretB32, counter) {
  var keyBytes = base32Decode(secretB32);
  var key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  var msg = new ArrayBuffer(8);
  var dv = new DataView(msg);
  dv.setUint32(0, Math.floor(counter / 0x100000000));
  dv.setUint32(4, counter >>> 0);
  var sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  var off = sig[sig.length - 1] & 0x0f;
  var code = ((sig[off] & 0x7f) << 24) | (sig[off + 1] << 16) | (sig[off + 2] << 8) | sig[off + 3];
  return String(code % 1000000).padStart(6, '0');
}

export async function verifyTotp(secretB32, code) {
  var c = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(c)) return false;
  var step = Math.floor(Date.now() / 30000);
  for (var d = -1; d <= 1; d++) {
    if (constEq(await hotp(secretB32, step + d), c)) return true;
  }
  return false;
}
