import { json, handle } from '../../_lib/util.js';
import { getSession } from '../../_lib/auth.js';

export async function onRequestGet(context) {
  return handle(async function () {
    var ctx = await getSession(context.env, context.request);
    if (!ctx) return json({ authenticated: false });
    var u = ctx.user;
    return json({
      authenticated: true,
      user: {
        id: u.id, display_name: u.display_name, email: u.email,
        email_verified: !!u.email_verified, phone_verified: !!u.phone_verified,
        is_admin: !!u.is_admin, aal: ctx.session.aal, totp_confirmed: !!u.totp_confirmed
      }
    });
  });
}
