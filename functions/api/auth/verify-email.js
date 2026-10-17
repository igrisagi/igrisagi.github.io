import { json, handle } from '../../_lib/util.js';
import { sha256hex } from '../../_lib/util.js';

// Email links are GET by nature; consuming the single-use token here is the
// standard email-verification pattern. Redirects back to the homepage.
export async function onRequestGet(context) {
  return handle(async function () {
    var url = new URL(context.request.url);
    var token = url.searchParams.get('token') || '';
    if (token.length < 20) return json({ error: 'invalid token' }, 400);
    var id = await sha256hex(token);
    var row = await context.env.DB.prepare(
      "SELECT id, user_id, expires_at, used_at FROM email_tokens WHERE id = ? AND kind = 'verify'"
    ).bind(id).first();
    if (!row || row.used_at || row.expires_at < new Date().toISOString()) {
      return json({ error: 'link expired or already used' }, 400);
    }
    await context.env.DB.prepare("UPDATE email_tokens SET used_at = datetime('now') WHERE id = ?").bind(id).run();
    await context.env.DB.prepare("UPDATE users SET email_verified = 1, updated_at = datetime('now') WHERE id = ?").bind(row.user_id).run();
    return Response.redirect(url.origin + '/?verified=1', 302);
  });
}
