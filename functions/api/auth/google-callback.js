import { json, abort, handle, sha256hex, uid } from '../../_lib/util.js';
import { createSession, sessionCookie, maybeProvisionAdmin } from '../../_lib/auth.js';

async function verifyIdToken(env, jwt, nonce) {
  var parts = jwt.split('.');
  if (parts.length !== 3) return null;
  var header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
  if (header.alg !== 'RS256') return null;
  var jwks = await (await fetch('https://www.googleapis.com/oauth2/v3/certs')).json();
  var jwk = (jwks.keys || []).find(function (k) { return k.kid === header.kid; });
  if (!jwk) return null;
  var key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  var data = new TextEncoder().encode(parts[0] + '.' + parts[1]);
  var sig = Uint8Array.from(atob(parts[2].replace(/-/g, '+').replace(/_/g, '/')), function (c) { return c.charCodeAt(0); });
  var valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, data);
  if (!valid) return null;
  var claims = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
  if (claims.iss !== 'https://accounts.google.com' && claims.iss !== 'accounts.google.com') return null;
  if (claims.aud !== env.GOOGLE_CLIENT_ID) return null;
  if (claims.exp * 1000 < Date.now()) return null;
  if (claims.nonce !== nonce) return null;
  return claims;
}

export async function onRequestGet(context) {
  return handle(async function () {
    var env = context.env;
    if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) {
      return json({ error: 'Google sign-in is not configured' }, 503);
    }
    var url = new URL(context.request.url);
    var origin = url.origin;
    var errParam = url.searchParams.get('error');
    if (errParam) return Response.redirect(origin + '/?signin=failed', 302);
    var code = url.searchParams.get('code') || '';
    var state = url.searchParams.get('state') || '';
    if (!code || !state) return json({ error: 'invalid callback' }, 400);

    var st = await env.DB.prepare('SELECT id, nonce, expires_at FROM oauth_states WHERE id = ?')
      .bind(await sha256hex(state)).first();
    if (!st || st.expires_at < new Date().toISOString()) return json({ error: 'sign-in session expired - try again' }, 400);
    await env.DB.prepare('DELETE FROM oauth_states WHERE id = ?').bind(st.id).run();

    var tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code: code,
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        redirect_uri: origin + '/api/auth/google-callback',
        grant_type: 'authorization_code'
      })
    });
    if (!tokenRes.ok) return json({ error: 'Google sign-in failed' }, 502);
    var tokens = await tokenRes.json();
    var claims = await verifyIdToken(env, tokens.id_token, st.nonce);
    if (!claims || !claims.sub) return json({ error: 'could not verify Google identity' }, 502);
    var em = (claims.email || '').toLowerCase();
    if (!em) return json({ error: 'Google account has no email address' }, 400);

    var user = await env.DB.prepare('SELECT * FROM users WHERE google_sub = ?').bind(claims.sub).first();
    if (!user) {
      // Safe linking: only attach Google to an existing account when Google
      // has verified ownership of the same email address.
      user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(em).first();
      if (user) {
        if (!claims.email_verified) return json({ error: 'Google has not verified this email address' }, 403);
        await env.DB.prepare("UPDATE users SET google_sub = ?, updated_at = datetime('now') WHERE id = ?")
          .bind(claims.sub, user.id).run();
      } else {
        var id = uid();
        await env.DB.prepare(
          'INSERT INTO users (id, display_name, email, email_verified, google_sub) VALUES (?, ?, ?, ?, ?)'
        ).bind(id, (claims.name || em.split('@')[0]).slice(0, 40) || 'user', em, claims.email_verified ? 1 : 0, claims.sub).run();
        user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
      }
    }
    if (user.status !== 'active') return json({ error: 'account suspended' }, 403);
    await maybeProvisionAdmin(env, user);
    var token = await createSession(env, context.request, user.id, 1);
    return new Response(null, {
      status: 302,
      headers: { 'Location': origin + '/?signedin=1', 'Set-Cookie': sessionCookie(token) }
    });
  });
}
