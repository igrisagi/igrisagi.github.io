import { json, handle } from '../../_lib/util.js';
import { requireAdmin } from '../../_lib/auth.js';

export async function onRequestGet(context) {
  return handle(async function () {
    await requireAdmin(context.env, context.request);
    var rows = await context.env.DB.prepare(
      'SELECT a.id, a.action, a.target_type, a.target_id, a.meta, a.created_at, u.display_name AS actor FROM audit_log a LEFT JOIN users u ON u.id = a.actor_id ORDER BY a.created_at DESC LIMIT 200'
    ).all();
    return json({ audit: rows.results });
  });
}
