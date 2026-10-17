import { json, abort, handle, readJson, str, uid } from '../_lib/util.js';
import { requireUser, assertCsrf, limited } from '../_lib/auth.js';

// Private messages between one visitor and ErenLabs. Never public.
export async function onRequestGet(context) {
  return handle(async function () {
    var ctx = await requireUser(context.env, context.request, { verified: false });
    var rows = await context.env.DB.prepare(
      'SELECT id, parent_id, from_admin, subject, body, status, created_at FROM messages WHERE user_id = ? ORDER BY created_at ASC LIMIT 200'
    ).bind(ctx.user.id).all();
    return json({ messages: rows.results });
  });
}

export async function onRequestPost(context) {
  return handle(async function () {
    assertCsrf(context.request);
    await limited(context.env, context.request, 'message', 20, 3600);
    var ctx = await requireUser(context.env, context.request);
    var data = await readJson(context.request);
    var subject = str(data.subject, 1, 120, 'subject');
    var body = str(data.body, 1, 5000, 'message');

    // Duplicate-submission guard: identical content from the same sender
    // within 60 seconds is rejected.
    var dupe = await context.env.DB.prepare(
      "SELECT id FROM messages WHERE user_id = ? AND from_admin = 0 AND subject = ? AND body = ? AND created_at > datetime('now', '-60 seconds')"
    ).bind(ctx.user.id, subject, body).first();
    if (dupe) abort(json({ error: 'this message was already sent' }, 409));

    var id = uid();
    await context.env.DB.prepare(
      'INSERT INTO messages (id, user_id, from_admin, subject, body) VALUES (?, ?, 0, ?, ?)'
    ).bind(id, ctx.user.id, subject, body).run();
    return json({ ok: true, id: id }, 201);
  });
}
