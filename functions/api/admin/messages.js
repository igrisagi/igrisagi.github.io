import { json, handle } from '../../_lib/util.js';
import { requireAdmin } from '../../_lib/auth.js';

export async function onRequestGet(context) {
  return handle(async function () {
    await requireAdmin(context.env, context.request);
    var url = new URL(context.request.url);
    var status = url.searchParams.get('status') || '';
    var q = (url.searchParams.get('q') || '').trim();
    var sql = "SELECT m.id, m.user_id, m.from_admin, m.subject, m.body, m.status, m.created_at, u.display_name, u.email FROM messages m JOIN users u ON u.id = m.user_id";
    var where = [];
    var binds = [];
    if (status && ['unread', 'read', 'archived'].indexOf(status) !== -1) { where.push('m.status = ?'); binds.push(status); }
    if (q) { where.push('(m.subject LIKE ? OR m.body LIKE ? OR u.email LIKE ? OR u.display_name LIKE ?)'); var like = '%' + q.slice(0, 60) + '%'; binds.push(like, like, like, like); }
    if (where.length) sql += ' WHERE ' + where.join(' AND ');
    sql += ' ORDER BY m.created_at DESC LIMIT 200';
    var stmt = context.env.DB.prepare(sql);
    var rows = await stmt.bind.apply(stmt, binds).all();
    return json({ messages: rows.results });
  });
}
