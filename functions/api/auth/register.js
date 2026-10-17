import { json, abort, handle, readJson, str, email, uid, randomToken, sha256hex } from '../../_lib/util.js';
import { hashPassword } from '../../_lib/crypto.js';
import { createSession, sessionCookie, assertCsrf, limited, maybeProvisionAdmin } from '../../_lib/auth.js';
import { sendMail } from '../../_lib/mail.js';
import { requireTurnstile } from '../../_lib/turnstile.js';

export async function onRequestPost(context) {
  return handle(async function () {
    assertCsrf(context.request);
    var data0 = await readJson(context.request);
    await requireTurnstile(context.env, context.request, data0.turnstile_token);
    var data = data0;
    await limited(context.env, context.request, 'register', 10, 3600);
    var em = email(data.email);
    var name = str(data.display_name, 1, 40, 'display name');
    var pw = String(data.password || '');
    if (pw.length < 10 || pw.length > 128) abort(json({ error: 'password must be 10-128 characters' }, 400));

    var existing = await context.env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(em).first();
    if (existing) {
      // Anti-enumeration: pretend success, create nothing.
      return json({ ok: true, verification_required: true });
    }
    var id = uid();
    await context.env.DB.prepare(
      'INSERT INTO users (id, display_name, email, password_hash) VALUES (?, ?, ?, ?)'
    ).bind(id, name, em, await hashPassword(pw, context.env)).run();

    var token = randomToken();
    var verifyExpiry = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    await context.env.DB.prepare(
      "INSERT INTO email_tokens (id, user_id, kind, expires_at) VALUES (?, ?, 'verify', ?)"
    ).bind(await sha256hex(token), id, verifyExpiry).run();
    var link = new URL(context.request.url).origin + '/api/auth/verify-email?token=' + token;
    var delivered = await sendMail(context.env, em, 'verify', 'Verify your ErenLabs account',
      'Hello ' + name + ',\n\nConfirm this email address for your ErenLabs account:\n' + link + '\n\nThe link expires in 24 hours.\n');

    var user = { id: id, email: em, is_admin: 0 };
    await maybeProvisionAdmin(context.env, user);
    var sessionToken = await createSession(context.env, context.request, id, 1);
    return json({ ok: true, verification_required: true, email_delivered: delivered }, 201, {
      'Set-Cookie': sessionCookie(sessionToken)
    });
  });
}
