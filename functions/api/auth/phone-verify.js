import { json, abort, handle, readJson, phoneE164, sha256hex, uid } from '../../_lib/util.js';
import { assertCsrf, limited, createSession, sessionCookie } from '../../_lib/auth.js';

export async function onRequestPost(context) {
  return handle(async function () {
    var env = context.env;
    if (!(env.SMS_PROVIDER === 'twilio' && env.TWILIO_ACCOUNT_SID && env.TWILIO_AUTH_TOKEN && env.TWILIO_FROM)) {
      return json({ error: 'phone sign-in is not configured' }, 503);
    }
    assertCsrf(context.request);
    await limited(env, context.request, 'otp-verify', 10, 600);
    var data = await readJson(context.request);
    var phone = phoneE164(data.phone);
    var code = String(data.code || '').replace(/\s/g, '');
    if (!/^\d{6}$/.test(code)) abort(json({ error: 'invalid code' }, 400));

    var row = await env.DB.prepare(
      'SELECT id, code_hash, expires_at, attempts, consumed_at FROM phone_otps WHERE phone = ? ORDER BY created_at DESC LIMIT 1'
    ).bind(phone).first();
    if (!row || row.consumed_at || row.expires_at < new Date().toISOString()) {
      abort(json({ error: 'code expired - request a new one' }, 400));
    }
    if (row.attempts >= 5) abort(json({ error: 'too many attempts - request a new code' }, 429));
    await env.DB.prepare('UPDATE phone_otps SET attempts = attempts + 1 WHERE id = ?').bind(row.id).run();
    if (row.code_hash !== await sha256hex(phone + '|' + code)) {
      abort(json({ error: 'incorrect code' }, 401));
    }
    await env.DB.prepare("UPDATE phone_otps SET consumed_at = datetime('now') WHERE id = ?").bind(row.id).run();

    var user = await env.DB.prepare('SELECT * FROM users WHERE phone = ?').bind(phone).first();
    if (!user) {
      var id = uid();
      await env.DB.prepare('INSERT INTO users (id, display_name, phone, phone_verified) VALUES (?, ?, ?, 1)')
        .bind(id, 'user-' + phone.slice(-4), phone).run();
      user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
    } else if (!user.phone_verified) {
      await env.DB.prepare("UPDATE users SET phone_verified = 1, updated_at = datetime('now') WHERE id = ?").bind(user.id).run();
    }
    if (user.status !== 'active') abort(json({ error: 'account suspended' }, 403));
    var token = await createSession(env, context.request, user.id, 1);
    return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie(token) });
  });
}
