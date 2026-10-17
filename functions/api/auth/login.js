import { json, abort, handle, readJson, email } from '../../_lib/util.js';
import { verifyPassword } from '../../_lib/crypto.js';
import { createSession, sessionCookie, clearSessionCookie, assertCsrf, limited, maybeProvisionAdmin, getSession, parseCookies } from '../../_lib/auth.js';
import { sha256hex } from '../../_lib/util.js';
import { requireTurnstile } from '../../_lib/turnstile.js';

export async function onRequestPost(context) {
  return handle(async function () {
    assertCsrf(context.request);
    await limited(context.env, context.request, 'login', 10, 600);
    var data = await readJson(context.request);
    await requireTurnstile(context.env, context.request, data.turnstile_token);
    var em = email(data.email);
    var pw = String(data.password || '');
    var user = await context.env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(em).first();
    var ok = user && user.password_hash ? await verifyPassword(pw, user.password_hash) : false;
    if (!ok) abort(json({ error: 'invalid email or password' }, 401));
    if (user.status !== 'active') abort(json({ error: 'account suspended' }, 403));

    await maybeProvisionAdmin(context.env, user);

    // Rotate the session identifier on authentication.
    var oldToken = parseCookies(context.request).eren_session;
    if (oldToken) {
      await context.env.DB.prepare("UPDATE sessions SET revoked_at = datetime('now') WHERE id = ?")
        .bind(await sha256hex(oldToken)).run();
    }
    var token = await createSession(context.env, context.request, user.id, 1);
    return json({ ok: true, display_name: user.display_name, email_verified: !!user.email_verified, is_admin: !!user.is_admin }, 200, {
      'Set-Cookie': sessionCookie(token)
    });
  });
}
