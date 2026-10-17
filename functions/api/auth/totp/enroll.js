import { json, abort, handle } from '../../../_lib/util.js';
import { requireUser, assertCsrf, limited } from '../../../_lib/auth.js';
import { generateTotpSecret } from '../../../_lib/crypto.js';

// Starts TOTP enrollment for an admin account. The secret stays unconfirmed
// (and unusable for elevation) until /confirm succeeds.
export async function onRequestPost(context) {
  return handle(async function () {
    assertCsrf(context.request);
    await limited(context.env, context.request, 'totp', 10, 600);
    var ctx = await requireUser(context.env, context.request);
    if (!ctx.user.is_admin || !ctx.user.email_verified) abort(json({ error: 'not authorized' }, 403));
    var secret = generateTotpSecret();
    await context.env.DB.prepare('UPDATE users SET totp_secret = ?, totp_confirmed = 0 WHERE id = ?')
      .bind(secret, ctx.user.id).run();
    var label = encodeURIComponent('ErenLabs:' + ctx.user.email);
    return json({
      ok: true,
      secret: secret,
      otpauth_url: 'otpauth://totp/' + label + '?secret=' + secret + '&issuer=ErenLabs&algorithm=SHA1&digits=6&period=30'
    });
  });
}
