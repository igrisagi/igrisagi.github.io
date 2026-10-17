// Test-side TOTP generator using the same WebCrypto math as the server.
import { base32Decode } from '../functions/_lib/util.js';

export async function totpCodeNow(secretB32) {
  const keyBytes = base32Decode(secretB32);
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const step = Math.floor(Date.now() / 30000);
  const msg = new ArrayBuffer(8);
  const dv = new DataView(msg);
  dv.setUint32(0, Math.floor(step / 0x100000000));
  dv.setUint32(4, step >>> 0);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const off = sig[sig.length - 1] & 0x0f;
  const code = ((sig[off] & 0x7f) << 24) | (sig[off + 1] << 16) | (sig[off + 2] << 8) | sig[off + 3];
  return String(code % 1000000).padStart(6, '0');
}
