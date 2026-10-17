import { json, handle, readJson, email, randomToken, sha256hex } from '../../_lib/util.js';
import { assertCsrf, limited } from '../../_lib/auth.js';
import { sendMail } from '../../_lib/mail.js';

export async function onRequestPost(context) {
  return handle(async function () {
    assertCsrf(context.request);
    await limited(context.env, context.request, 'reset', 5, 3600);
    var data = await readJson(context.request);
    var em = email(data.email);
    var user = await context.env.DB.prepare('SELECT id, display_name FROM users WHERE email = ?').bind(em).first();
    if (user) {
      var token = randomToken();
      var resetExpiry = new Date(Date.now() + 3600 * 1000).toISOString();
      await context.env.DB.prepare(
        "INSERT INTO email_tokens (id, user_id, kind, expires_at) VALUES (?, ?, 'reset', ?)"
      ).bind(await sha256hex(token), user.id, resetExpiry).run();
      var link = new URL(context.request.url).origin + '/?reset=' + token;
      await sendMail(context.env, em, 'reset', 'Reset your ErenLabs password',
        'Hello ' + user.display_name + ',\n\nReset your ErenLabs password here (valid for 1 hour):\n' + link + '\n\nIf you did not ask for this, ignore this message.\n');
    }
    // Same response whether or not the account exists (no enumeration).
    return json({ ok: true });
  });
}
