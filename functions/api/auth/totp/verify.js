import { json, abort, handle, readJson } from '../../../_lib/util.js';
import { requireUser, assertCsrf, limited } from '../../../_lib/auth.js';
import { verifyTotp } from '../../../_lib/crypto.js';

// Elevates the current session to AAL2 for 30 minutes of admin access.
export async function onRequestPost(context) {
  return handle(async function () {
    assertCsrf(context.request);
    await limited(context.env, context.request, 'totp', 5, 600);
    var ctx = await requireUser(context.env, context.request);
    if (!ctx.user.is_admin || !ctx.user.email_verified) abort(json({ error: 'not authorized' }, 403));
    if (!ctx.user.totp_confirmed) abort(json({ error: 'admin MFA enrollment required', code: 'mfa_enroll' }, 403));
    var data = await readJson(context.request);
    var row = await context.env.DB.prepare('SELECT totp_secret FROM users WHERE id = ?').bind(ctx.user.id).first();
    if (!(await verifyTotp(row.totp_secret, data.code))) abort(json({ error: 'incorrect code' }, 401));
    await context.env.DB.prepare("UPDATE sessions SET aal = 2, aal2_at = ? WHERE id = ?")
      .bind(new Date().toISOString(), ctx.session.id).run();
    return json({ ok: true });
  });
}
