import { json, handle } from '../../_lib/util.js';
import { clearSessionCookie, assertCsrf, parseCookies } from '../../_lib/auth.js';
import { sha256hex } from '../../_lib/util.js';

export async function onRequestPost(context) {
  return handle(async function () {
    assertCsrf(context.request);
    var token = parseCookies(context.request).eren_session;
    if (token) {
      await context.env.DB.prepare("UPDATE sessions SET revoked_at = datetime('now') WHERE id = ?")
        .bind(await sha256hex(token)).run();
    }
    return json({ ok: true }, 200, { 'Set-Cookie': clearSessionCookie() });
  });
}
