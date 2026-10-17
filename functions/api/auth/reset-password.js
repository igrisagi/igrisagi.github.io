import { json, abort, handle, readJson, sha256hex } from '../../_lib/util.js';
import { hashPassword } from '../../_lib/crypto.js';
import { assertCsrf, limited } from '../../_lib/auth.js';

export async function onRequestPost(context) {
  return handle(async function () {
    assertCsrf(context.request);
    await limited(context.env, context.request, 'reset-use', 10, 600);
    var data = await readJson(context.request);
    var token = String(data.token || '');
    var pw = String(data.password || '');
    if (token.length < 20) abort(json({ error: 'invalid token' }, 400));
    if (pw.length < 10 || pw.length > 128) abort(json({ error: 'password must be 10-128 characters' }, 400));
    var id = await sha256hex(token);
    var row = await context.env.DB.prepare(
      "SELECT id, user_id, expires_at, used_at FROM email_tokens WHERE id = ? AND kind = 'reset'"
    ).bind(id).first();
    if (!row || row.used_at || row.expires_at < new Date().toISOString()) {
      abort(json({ error: 'link expired or already used' }, 400));
    }
    await context.env.DB.prepare("UPDATE email_tokens SET used_at = datetime('now') WHERE id = ?").bind(id).run();
    await context.env.DB.prepare("UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?")
      .bind(await hashPassword(pw), row.user_id).run();
    // Revoke every session after a password reset.
    await context.env.DB.prepare("UPDATE sessions SET revoked_at = datetime('now') WHERE user_id = ? AND revoked_at IS NULL")
      .bind(row.user_id).run();
    return json({ ok: true });
  });
}
