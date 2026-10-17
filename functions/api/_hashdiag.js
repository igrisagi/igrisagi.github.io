// TEMPORARY diagnostic - staging/preview only, never merge to main.
import { handle, json } from '../_lib/util.js';

export async function onRequestGet(context) {
  return handle(async function () {
    var out = {};
    try {
      var nc = await import('node:crypto');
      out.node_crypto = 'available';
      var Ns = [4096, 16384, 32768, 65536, 131072];
      for (var N of Ns) {
        var t0 = Date.now();
        try {
          var key = nc.scryptSync('test-password-123', 'saltsalt12345678', 32, { N: N, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
          out['scrypt_N' + N] = 'ok ' + (Date.now() - t0) + 'ms len=' + key.length;
        } catch (e) {
          out['scrypt_N' + N] = 'FAIL ' + (Date.now() - t0) + 'ms: ' + (e && e.message || e);
        }
      }
    } catch (e) {
      out.node_crypto = 'FAIL: ' + (e && e.message || e);
    }
    var t1 = Date.now();
    try {
      var k = await crypto.subtle.importKey('raw', new TextEncoder().encode('test-password-123'), 'PBKDF2', false, ['deriveBits']);
      await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: new Uint8Array(16), iterations: 100000 }, k, 256);
      out.pbkdf2_100k = 'ok ' + (Date.now() - t1) + 'ms';
    } catch (e) { out.pbkdf2_100k = 'FAIL: ' + (e && e.message || e); }
    return json(out);
  });
}
