// Latest videos from the IGRIS YouTube channel, pulled live from the
// public channel RSS feed (no API key needed). Cached at the edge.
const FEED = 'https://www.youtube.com/feeds/videos.xml?channel_id=UCJ5-8Utv7q0jPTBvb5ALrNw';

function pick(xml, re) {
  const m = xml.match(re);
  return m ? m[1].trim() : '';
}

function unescapeXml(s) {
  return s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
          .replace(/&#39;/g, "'").replace(/&amp;/g, '&');
}

export async function onRequestGet(context) {
  const cache = caches.default;
  const cacheKey = new Request(new URL(context.request.url).origin + '/api/videos');
  const hit = await cache.match(cacheKey);
  if (hit) return hit;

  try {
    const res = await fetch(FEED, { headers: { 'User-Agent': 'erenlabs.me' } });
    if (!res.ok) throw new Error('feed ' + res.status);
    const xml = await res.text();

    const channel = unescapeXml(pick(xml, /<title>([^<]*)<\/title>/));
    const entries = xml.split('<entry>').slice(1).map(function (e) {
      const id = pick(e, /<yt:videoId>([^<]+)<\/yt:videoId>/);
      return {
        id: id,
        title: unescapeXml(pick(e, /<title>([^<]*)<\/title>/)),
        url: 'https://www.youtube.com/watch?v=' + id,
        published: pick(e, /<published>([^<]+)<\/published>/),
        thumb: 'https://i.ytimg.com/vi/' + id + '/hqdefault.jpg'
      };
    }).filter(function (v) { return v.id; }).slice(0, 6);

    const body = JSON.stringify({ channel: channel, videos: entries });
    const out = new Response(body, {
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=900' }
    });
    context.waitUntil(cache.put(cacheKey, out.clone()));
    return out;
  } catch (err) {
    return new Response(JSON.stringify({ error: 'videos unavailable' }), {
      status: 502, headers: { 'Content-Type': 'application/json' }
    });
  }
}
