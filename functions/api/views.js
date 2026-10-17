// Total page views, kept in the same D1 database (binding: DB).
export async function onRequestGet(context) {
  try {
    await context.env.DB
      .prepare("INSERT INTO counters (key, value) VALUES ('views', 1) ON CONFLICT(key) DO UPDATE SET value = value + 1")
      .run();
    const row = await context.env.DB
      .prepare("SELECT value FROM counters WHERE key = 'views'")
      .first();
    return new Response(JSON.stringify({ views: row ? row.value : 0 }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: 'unavailable' }), {
      status: 502, headers: { 'Content-Type': 'application/json' }
    });
  }
}
