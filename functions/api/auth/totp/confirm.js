import { json, abort, handle, readJson } from '../../../_lib/util.js';
import { requireUser, assertCsrf, limited, audit } from '../../../_lib/auth.js';
import { verifyTotp } from '../../../_lib/crypto.js';

export async function onRequestPost(context) {
  return handle(async function () {
    assertCsrf(context.request);
    await limited(context.env, context.request, 'totp', 10, 600);
    var ctx = await requireUser(context.env, context.request);
    if (!ctx.user.is_admin || !ctx.user.email_verified) abort(json({ error: 'not authorized' }, 403));
    var data = await readJson(context.request);
    var row = await context.env.DB.prepare('SELECT totp_secret FROM users WHERE id = ?').bind(ctx.user.id).first();
    if (!row || !row.totp_secret) abort(json({ error: 'enroll first' }, 400));
    if (!(await verifyTotp(row.totp_secret, data.code))) abort(json({ error: 'incorrect code' }, 401));
    await context.env.DB.prepare('UPDATE users SET totp_confirmed = 1 WHERE id = ?').bind(ctx.user.id).run();
    await audit(context.env, ctx.user.id, 'totp.confirm', 'user', ctx.user.id, null);
    return json({ ok: true });
  });
}
