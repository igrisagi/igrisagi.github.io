import { json, abort, handle, readJson, str } from '../_lib/util.js';
import { requireUser, assertCsrf } from '../_lib/auth.js';

export async function onRequestGet(context) {
  return handle(async function () {
    var ctx = await requireUser(context.env, context.request, { verified: false });
    var u = ctx.user;
    return json({
      user: {
        id: u.id, display_name: u.display_name, email: u.email,
        email_verified: !!u.email_verified, phone: u.phone, phone_verified: !!u.phone_verified,
        is_admin: !!u.is_admin, created_at: u.created_at
      }
    });
  });
}

export async function onRequestPatch(context) {
  return handle(async function () {
    assertCsrf(context.request);
    var ctx = await requireUser(context.env, context.request, { verified: false });
    var data = await readJson(context.request);
    var name = str(data.display_name, 1, 40, 'display name');
    await context.env.DB.prepare("UPDATE users SET display_name = ?, updated_at = datetime('now') WHERE id = ?")
      .bind(name, ctx.user.id).run();
    return json({ ok: true, display_name: name });
  });
}

export async function onRequestDelete(context) {
  // Session revocation: DELETE /api/me?session=all signs out everywhere.
  return handle(async function () {
    assertCsrf(context.request);
    var ctx = await requireUser(context.env, context.request, { verified: false });
    await context.env.DB.prepare("UPDATE sessions SET revoked_at = datetime('now') WHERE user_id = ? AND revoked_at IS NULL")
      .bind(ctx.user.id).run();
    return json({ ok: true });
  });
}
