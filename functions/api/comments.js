import { json, abort, handle, readJson, str, uid } from '../_lib/util.js';
import { requireUser, assertCsrf, limited, getSession } from '../_lib/auth.js';

export async function onRequestGet(context) {
  return handle(async function () {
    var url = new URL(context.request.url);
    var cursor = url.searchParams.get('cursor') || '';
    var limit = Math.min(parseInt(url.searchParams.get('limit') || '20', 10) || 20, 50);
    var me = await getSession(context.env, context.request);
    var rows;
    if (cursor) {
      rows = await context.env.DB.prepare(
        "SELECT c.id, c.body, c.created_at, c.edited_at, c.user_id, u.display_name FROM comments c JOIN users u ON u.id = c.user_id WHERE c.deleted_at IS NULL AND c.moderated = 0 AND c.created_at > ? ORDER BY c.created_at ASC LIMIT ?"
      ).bind(cursor, limit + 1).all();
    } else {
      rows = await context.env.DB.prepare(
        "SELECT c.id, c.body, c.created_at, c.edited_at, c.user_id, u.display_name FROM comments c JOIN users u ON u.id = c.user_id WHERE c.deleted_at IS NULL AND c.moderated = 0 ORDER BY c.created_at ASC LIMIT ?"
      ).bind(limit + 1).all();
    }
    var list = rows.results.slice(0, limit).map(function (c) {
      return {
        id: c.id, body: c.body, created_at: c.created_at, edited_at: c.edited_at,
        display_name: c.display_name, own: !!(me && me.user.id === c.user_id)
      };
    });
    var next = rows.results.length > limit ? list[list.length - 1].created_at : null;
    return json({ comments: list, next_cursor: next });
  });
}

export async function onRequestPost(context) {
  return handle(async function () {
    assertCsrf(context.request);
    await limited(context.env, context.request, 'comment', 30, 3600);
    var ctx = await requireUser(context.env, context.request);
    var data = await readJson(context.request);
    var body = str(data.body, 1, 1000, 'comment');
    var id = uid();
    await context.env.DB.prepare('INSERT INTO comments (id, user_id, body) VALUES (?, ?, ?)')
      .bind(id, ctx.user.id, body).run();
    return json({ ok: true, id: id }, 201);
  });
}
