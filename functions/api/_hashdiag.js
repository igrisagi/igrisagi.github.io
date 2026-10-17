// TEMPORARY diagnostic - staging/preview only, never merge to main.
import { handle, json } from '../_lib/util.js';

export async function onRequestGet(context) {
  return handle(async function () {
    var u = new URL(context.request.url);
    var N = parseInt(u.searchParams.get('n') || '0', 10);
    var nc = await import('node:crypto');
    var key = nc.scryptSync('test-password-123', 'saltsalt12345678', 32, { N: N, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
    return json({ n: N, hex: Buffer.from(key).toString('hex') });
  });
}
