import { json, abort, handle, readJson, str, uid } from '../../../_lib/util.js';
import { requireAdmin, assertCsrf, audit, limited } from '../../../_lib/auth.js';

export async function onRequestPatch(context) {
  return handle(async function () {
    assertCsrf(context.request);
    var ctx = await requireAdmin(context.env, context.request);
    var data = await readJson(context.request);
    var status = String(data.status || '');
    if (['unread', 'read', 'archived'].indexOf(status) === -1) abort(json({ error: 'invalid status' }, 400));
    var r = await context.env.DB.prepare('UPDATE messages SET status = ? WHERE id = ?')
      .bind(status, context.params.id).run();
    if (!r.meta || !r.meta.changes) abort(json({ error: 'message not found' }, 404));
    await audit(context.env, ctx.user.id, 'message.status', 'message', context.params.id, { status: status });
    return json({ ok: true });
  });
}

export async function onRequestDelete(context) {
  return handle(async function () {
    assertCsrf(context.request);
    var ctx = await requireAdmin(context.env, context.request);
    var r = await context.env.DB.prepare('DELETE FROM messages WHERE id = ?').bind(context.params.id).run();
    if (!r.meta || !r.meta.changes) abort(json({ error: 'message not found' }, 404));
    await audit(context.env, ctx.user.id, 'message.delete', 'message', context.params.id, null);
    return json({ ok: true });
  });
}

// Reply: creates an admin message in the same visitor's private thread.
export async function onRequestPost(context) {
  return handle(async function () {
    assertCsrf(context.request);
    await limited(context.env, context.request, 'admin-reply', 30, 3600);
    var ctx = await requireAdmin(context.env, context.request);
    var data = await readJson(context.request);
    var body = str(data.body, 1, 5000, 'reply');
    var parent = await context.env.DB.prepare('SELECT id, user_id, subject FROM messages WHERE id = ?')
      .bind(context.params.id).first();
    if (!parent) abort(json({ error: 'message not found' }, 404));
    var id = uid();
    await context.env.DB.prepare(
      'INSERT INTO messages (id, user_id, parent_id, from_admin, subject, body, status) VALUES (?, ?, ?, 1, ?, ?, \'read\')'
    ).bind(id, parent.user_id, parent.id, parent.subject, body).run();
    await context.env.DB.prepare("UPDATE messages SET status = 'read' WHERE id = ?").bind(parent.id).run();
    await audit(context.env, ctx.user.id, 'message.reply', 'message', parent.id, null);
    return json({ ok: true, id: id }, 201);
  });
}
