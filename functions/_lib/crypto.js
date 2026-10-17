// Password hashing (scrypt via node:crypto) and TOTP (RFC 6238).
// scrypt N=2^17, r=8, p=1 meets current OWASP guidance. workerd's node:crypto
// supports scrypt natively (nodejs_compat, default-on for this project's
// 2026-10-17 compat date); argon2 is NOT available on this platform.
// Legacy PBKDF2 hashes (pbkdf2$ prefix, workerd's 100k-iteration cap) still
// verify so existing accounts keep working; new hashes are always scrypt.
import { scrypt } from 'node:crypto';
import { base32Encode, base32Decode, constEq } from './util.js';

// Hash cost is env-tunable (SCRYPT_N) so ops can lower it without a deploy
// if platform CPU enforcement ever tightens; bounds keep it honest.
var SCRYPT_R = 8, SCRYPT_P = 1;
var PBKDF2_ITER = 100000; // legacy path only

export function scryptN(env) {
  var n = parseInt((env && env.SCRYPT_N) || '131072', 10);
  if (!(n >= 16384 && n <= 131072) || (n & (n - 1)) !== 0) return 131072;
  return n;
}

function b64(bytes) { return btoa(String.fromCharCode.apply(null, new Uint8Array(bytes))); }
function unb64(s) { return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); }); }

export async function hashPassword(password, env) {
  var N = scryptN(env);
  var salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  var key = await new Promise(function (resolve, reject) {
    scrypt(password, salt, 32, { N: N, r: SCRYPT_R, p: SCRYPT_P, maxmem: 256 * 1024 * 1024 },
      function (err, derived) { err ? reject(err) : resolve(derived); });
  });
  return 'scrypt$' + N + '$' + SCRYPT_R + '$' + SCRYPT_P + '$' + b64(salt) + '$' + b64(key);
}

export async function verifyPassword(password, stored) {
  try {
    var parts = String(stored || '').split('$');
    if (parts[0] === 'scrypt' && parts.length === 6) {
      var N = parseInt(parts[1], 10), r = parseInt(parts[2], 10), p = parseInt(parts[3], 10);
      if (!(N >= 1024 && N <= 131072) || !(r >= 1 && r <= 32) || !(p >= 1 && p <= 16)) return false;
      var salt = unb64(parts[4]);
      var key = await new Promise(function (resolve, reject) {
        scrypt(password, salt, 32, { N: N, r: r, p: p, maxmem: 256 * 1024 * 1024 },
          function (err, derived) { err ? reject(err) : resolve(derived); });
      });
      return constEq(b64(key), parts[5]);
    }
    if (parts[0] === 'pbkdf2' && parts.length === 4) {
      var iter = Math.min(parseInt(parts[1], 10) || 0, PBKDF2_ITER);
      if (iter < 1) return false;
      var psalt = unb64(parts[2]);
      var pkey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
      var bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: psalt, iterations: iter }, pkey, 256);
      return constEq(b64(bits), parts[3]);
    }
    return false;
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
