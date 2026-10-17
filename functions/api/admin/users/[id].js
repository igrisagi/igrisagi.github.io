import { json, abort, handle, readJson } from '../../../_lib/util.js';
import { requireAdmin, assertCsrf, audit } from '../../../_lib/auth.js';

export async function onRequestPatch(context) {
  return handle(async function () {
    assertCsrf(context.request);
    var ctx = await requireAdmin(context.env, context.request);
    var data = await readJson(context.request);
    var status = String(data.status || '');
    if (['active', 'suspended'].indexOf(status) === -1) abort(json({ error: 'invalid status' }, 400));
    if (context.params.id === ctx.user.id) abort(json({ error: 'cannot change your own account status' }, 400));
    var r = await context.env.DB.prepare("UPDATE users SET status = ?, updated_at = datetime('now') WHERE id = ?")
      .bind(status, context.params.id).run();
    if (!r.meta || !r.meta.changes) abort(json({ error: 'user not found' }, 404));
    if (status === 'suspended') {
      await context.env.DB.prepare("UPDATE sessions SET revoked_at = datetime('now') WHERE user_id = ? AND revoked_at IS NULL")
        .bind(context.params.id).run();
    }
    await audit(context.env, ctx.user.id, 'user.' + status, 'user', context.params.id, null);
    return json({ ok: true });
  });
}
