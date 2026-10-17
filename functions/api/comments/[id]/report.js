import { json, abort, handle, readJson, str, uid } from '../../../_lib/util.js';
import { requireUser, assertCsrf, limited } from '../../../_lib/auth.js';

export async function onRequestPost(context) {
  return handle(async function () {
    assertCsrf(context.request);
    await limited(context.env, context.request, 'report', 20, 3600);
    var ctx = await requireUser(context.env, context.request);
    var data = await readJson(context.request);
    var reason = str(data.reason, 1, 200, 'reason');
    var c = await context.env.DB.prepare('SELECT id FROM comments WHERE id = ? AND deleted_at IS NULL')
      .bind(context.params.id).first();
    if (!c) abort(json({ error: 'comment not found' }, 404));
    try {
      await context.env.DB.prepare('INSERT INTO comment_reports (id, comment_id, user_id, reason) VALUES (?, ?, ?, ?)')
        .bind(uid(), c.id, ctx.user.id, reason).run();
    } catch (e) {
      abort(json({ error: 'already reported' }, 409));
    }
    return json({ ok: true }, 201);
  });
}
