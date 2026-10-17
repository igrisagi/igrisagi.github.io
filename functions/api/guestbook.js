// A tiny guestbook backed by a D1 database (binding: DB).
const json = (d, s) => new Response(JSON.stringify(d), {
  status: s || 200, headers: { 'Content-Type': 'application/json' }
});

export async function onRequestGet(context) {
  try {
    const { results } = await context.env.DB
      .prepare('SELECT name, message, created_at FROM guestbook ORDER BY id DESC LIMIT 20')
      .all();
    return json({ entries: results });
  } catch (err) {
    return json({ error: 'guestbook unavailable' }, 502);
  }
}

export async function onRequestPost(context) {
  let data;
  try { data = await context.request.json(); } catch (e) { return json({ error: 'bad request' }, 400); }
  const name = String(data.name || '').trim().slice(0, 40);
  const message = String(data.message || '').trim().slice(0, 280);
  if (!name || !message) return json({ error: 'name and message required' }, 400);
  try {
    await context.env.DB
      .prepare('INSERT INTO guestbook (name, message) VALUES (?, ?)')
      .bind(name, message)
      .run();
    return json({ ok: true }, 201);
  } catch (err) {
    return json({ error: 'guestbook unavailable' }, 502);
  }
}
