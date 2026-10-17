import { json, handle } from '../../_lib/util.js';
import { requireAdmin } from '../../_lib/auth.js';

export async function onRequestGet(context) {
  return handle(async function () {
    await requireAdmin(context.env, context.request);
    var rows = await context.env.DB.prepare(
      'SELECT id, display_name, email, email_verified, phone, phone_verified, status, is_admin, created_at FROM users ORDER BY created_at DESC LIMIT 500'
    ).all();
    return json({ users: rows.results });
  });
}
