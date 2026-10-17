import { json, abort, handle, readJson } from '../../../_lib/util.js';
import { requireAdmin, assertCsrf, audit } from '../../../_lib/auth.js';

export async function onRequestPatch(context) {
  return handle(async function () {
    assertCsrf(context.request);
    var ctx = await requireAdmin(context.env, context.request);
    var data = await readJson(context.request);
    var r;
    if (data.moderated === true || data.moderated === 1) {
      r = await context.env.DB.prepare("UPDATE comments SET moderated = 1, moderated_by = ?, moderated_at = datetime('now') WHERE id = ?")
        .bind(ctx.user.id, context.params.id).run();
      await audit(context.env, ctx.user.id, 'comment.moderate', 'comment', context.params.id, null);
    } else if (data.moderated === false || data.moderated === 0) {
      r = await context.env.DB.prepare('UPDATE comments SET moderated = 0, moderated_by = NULL, moderated_at = NULL WHERE id = ?')
        .bind(context.params.id).run();
      await audit(context.env, ctx.user.id, 'comment.unmoderate', 'comment', context.params.id, null);
    } else {
      abort(json({ error: 'invalid moderation value' }, 400));
    }
    if (!r.meta || !r.meta.changes) abort(json({ error: 'comment not found' }, 404));
    return json({ ok: true });
  });
}

export async function onRequestDelete(context) {
  return handle(async function () {
    assertCsrf(context.request);
    var ctx = await requireAdmin(context.env, context.request);
    var r = await context.env.DB.prepare("UPDATE comments SET deleted_at = datetime('now') WHERE id = ?")
      .bind(context.params.id).run();
    if (!r.meta || !r.meta.changes) abort(json({ error: 'comment not found' }, 404));
    await audit(context.env, ctx.user.id, 'comment.delete', 'comment', context.params.id, null);
    return json({ ok: true });
  });
}
