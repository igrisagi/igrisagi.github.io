import { json, handle } from '../../_lib/util.js';
import { requireAdmin } from '../../_lib/auth.js';

export async function onRequestGet(context) {
  return handle(async function () {
    await requireAdmin(context.env, context.request);
    var rows = await context.env.DB.prepare(
      "SELECT c.id, c.body, c.created_at, c.edited_at, c.deleted_at, c.moderated, c.user_id, u.display_name, u.email, (SELECT COUNT(*) FROM comment_reports r WHERE r.comment_id = c.id) AS reports FROM comments c JOIN users u ON u.id = c.user_id ORDER BY c.created_at DESC LIMIT 200"
    ).all();
    return json({ comments: rows.results });
  });
}
