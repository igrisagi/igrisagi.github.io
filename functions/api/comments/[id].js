import { json, abort, handle, readJson, str } from '../../_lib/util.js';
import { requireUser, assertCsrf, limited } from '../../_lib/auth.js';

async function ownComment(context) {
  var ctx = await requireUser(context.env, context.request);
  var c = await context.env.DB.prepare(
    'SELECT id, user_id, deleted_at, moderated FROM comments WHERE id = ?'
  ).bind(context.params.id).first();
  if (!c || c.deleted_at) abort(json({ error: 'comment not found' }, 404));
  if (c.user_id !== ctx.user.id) abort(json({ error: 'not your comment' }, 403));
  return ctx;
}

export async function onRequestPatch(context) {
  return handle(async function () {
    assertCsrf(context.request);
    await limited(context.env, context.request, 'comment-edit', 30, 3600);
    await ownComment(context);
    var data = await readJson(context.request);
    var body = str(data.body, 1, 1000, 'comment');
    await context.env.DB.prepare("UPDATE comments SET body = ?, edited_at = datetime('now') WHERE id = ?")
      .bind(body, context.params.id).run();
    return json({ ok: true });
  });
}

export async function onRequestDelete(context) {
  return handle(async function () {
    assertCsrf(context.request);
    await ownComment(context);
    await context.env.DB.prepare("UPDATE comments SET deleted_at = datetime('now') WHERE id = ?")
      .bind(context.params.id).run();
    return json({ ok: true });
  });
}
