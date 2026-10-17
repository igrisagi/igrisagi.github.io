import { json, handle } from '../../_lib/util.js';
import { requireAdmin } from '../../_lib/auth.js';

// Development fallback visibility for undelivered mail (verification/reset
// links) when no email provider is configured. Admin-only.
export async function onRequestGet(context) {
  return handle(async function () {
    await requireAdmin(context.env, context.request);
    var rows = await context.env.DB.prepare(
      'SELECT id, to_email, kind, subject, body, created_at, sent_at FROM outbox ORDER BY created_at DESC LIMIT 100'
    ).all();
    return json({ outbox: rows.results });
  });
}
