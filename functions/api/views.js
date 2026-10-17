// Qualified views, counted YouTube-style: a view only counts after the
// visitor actually stays on the page (the page sends a beacon after a few
// visible seconds), and only once per visitor per day. Plain page loads,
// reloads and bots never move the number. Same D1 database (binding: DB).

var BOT = /bot|crawl|spider|slurp|curl|wget|python|httpclient|headless|lighthouse|pingdom|uptime|scan|preview/i;
var MIN_DWELL = 3; // seconds, server-side floor; the page qualifies at 5 visible seconds

function today() { return new Date().toISOString().slice(0, 10); }

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json' }
  });
}

async function vid(req) {
  var ip = req.headers.get('CF-Connecting-IP') || 'anon';
  var ua = req.headers.get('User-Agent') || '';
  var buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ip + '|' + ua + '|' + today()));
  return Array.from(new Uint8Array(buf)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('').slice(0, 24);
}

async function total(db) {
  var row = await db.prepare("SELECT value FROM counters WHERE key = 'views'").first();
  return row ? row.value : 0;
}

// GET only reads the count - it never increments.
export async function onRequestGet(context) {
  try {
    return json({ views: await total(context.env.DB) });
  } catch (err) {
    return json({ error: 'unavailable' }, 502);
  }
}

// POST is the qualified-view beacon the page sends after real dwell time.
export async function onRequestPost(context) {
  try {
    var req = context.request;
    var ua = req.headers.get('User-Agent') || '';
    if (BOT.test(ua)) return json({ ok: true, counted: false });

    var dwell = 0;
    try { dwell = Number((await req.json()).t) || 0; } catch (e) { return json({ error: 'bad request' }, 400); }
    if (dwell < MIN_DWELL) return json({ ok: true, counted: false });

    var key = 'v:' + today() + ':' + (await vid(req));
    var ins = await context.env.DB
      .prepare("INSERT INTO counters (key, value) VALUES (?, 1) ON CONFLICT(key) DO NOTHING")
      .bind(key)
      .run();
    var counted = !!(ins.meta && ins.meta.changes);
    if (counted) {
      await context.env.DB
        .prepare("INSERT INTO counters (key, value) VALUES ('views', 1) ON CONFLICT(key) DO UPDATE SET value = value + 1")
        .run();
    }
    return json({ ok: true, counted: counted, views: await total(context.env.DB) });
  } catch (err) {
    return json({ error: 'unavailable' }, 502);
  }
}
