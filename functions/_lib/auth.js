// Session management, authorization, CSRF, rate limiting, audit logging.
import { json, abort, sha256hex, randomToken, ipHash, clientIp } from './util.js';

var SESSION_DAYS = 30;
var ADMIN_AAL2_SECONDS = 1800; // admin elevation lasts 30 minutes

export function parseCookies(request) {
  var header = request.headers.get('Cookie') || '';
  var out = {};
  header.split(';').forEach(function (p) {
    var i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return out;
}

export function sessionCookie(token) {
  return 'eren_session=' + token + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' + SESSION_DAYS * 86400;
}

export function clearSessionCookie() {
  return 'eren_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';
}

export async function createSession(env, request, userId, aal) {
  var token = randomToken();
  var id = await sha256hex(token);
  var expires = new Date(Date.now() + SESSION_DAYS * 86400000).toISOString();
  await env.DB.prepare(
    'INSERT INTO sessions (id, user_id, aal, aal2_at, expires_at, ip_hash, ua) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, userId, aal || 1, aal === 2 ? new Date().toISOString() : null, expires,
    await ipHash(request), (request.headers.get('User-Agent') || '').slice(0, 200)).run();
  return token;
}

export async function getSession(env, request) {
  var token = parseCookies(request).eren_session;
  if (!token || token.length > 128) return null;
  var id = await sha256hex(token);
  var s = await env.DB.prepare(
    "SELECT id, user_id, aal, aal2_at, expires_at, revoked_at FROM sessions WHERE id = ?"
  ).bind(id).first();
  if (!s || s.revoked_at || s.expires_at < new Date().toISOString()) return null;
  var u = await env.DB.prepare(
    'SELECT id, display_name, email, email_verified, phone, phone_verified, status, is_admin, totp_confirmed, google_sub, created_at FROM users WHERE id = ?'
  ).bind(s.user_id).first();
  if (!u || u.status !== 'active') return null;
  return { session: s, user: u };
}

// CSRF: state-changing endpoints require a custom header, which browsers
// cannot attach cross-origin without a CORS preflight we never grant.
export function assertCsrf(request) {
  if (!request.headers.get('X-Requested-With')) {
    abort(json({ error: 'missing request header' }, 403));
  }
}

export async function requireUser(env, request, opts) {
  var ctx = await getSession(env, request);
  if (!ctx) abort(json({ error: 'sign in required' }, 401));
  if (!opts || opts.verified !== false) {
    if (!ctx.user.email_verified && !ctx.user.phone_verified) {
      abort(json({ error: 'verify your email address first', code: 'unverified' }, 403));
    }
  }
  return ctx;
}

export async function requireAdmin(env, request) {
  var ctx = await getSession(env, request);
  if (!ctx) abort(json({ error: 'sign in required' }, 401));
  if (!ctx.user.is_admin || !ctx.user.email_verified) abort(json({ error: 'not authorized' }, 403));
  if (!ctx.user.totp_confirmed) abort(json({ error: 'admin MFA enrollment required', code: 'mfa_enroll' }, 403));
  if (ctx.session.aal !== 2 || !ctx.session.aal2_at) abort(json({ error: 'admin MFA required', code: 'mfa_required' }, 403));
  var age = (Date.now() - new Date(ctx.session.aal2_at).getTime()) / 1000;
  if (age > ADMIN_AAL2_SECONDS) abort(json({ error: 'admin MFA expired', code: 'mfa_required' }, 403));
  return ctx;
}

// Fixed-window rate limiting backed by D1. Returns true when allowed.
export async function rateLimit(env, key, limit, windowSec) {
  var now = new Date();
  var row = await env.DB.prepare('SELECT count, reset_at FROM rate_limits WHERE key = ?').bind(key).first();
  if (!row || row.reset_at < now.toISOString()) {
    await env.DB.prepare('INSERT INTO rate_limits (key, count, reset_at) VALUES (?, 1, ?) ON CONFLICT(key) DO UPDATE SET count = 1, reset_at = excluded.reset_at')
      .bind(key, new Date(now.getTime() + windowSec * 1000).toISOString()).run();
    return true;
  }
  if (row.count >= limit) return false;
  await env.DB.prepare('UPDATE rate_limits SET count = count + 1 WHERE key = ?').bind(key).run();
  return true;
}

export async function limited(env, request, bucket, limit, windowSec) {
  var key = 'rl:' + bucket + ':' + (await ipHash(request));
  if (!(await rateLimit(env, key, limit, windowSec))) {
    abort(json({ error: 'too many attempts - wait a few minutes and try again' }, 429));
  }
}

export async function audit(env, actorId, action, targetType, targetId, meta) {
  await env.DB.prepare(
    'INSERT INTO audit_log (id, actor_id, action, target_type, target_id, meta) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(crypto.randomUUID(), actorId, action, targetType, targetId || null,
    meta ? JSON.stringify(meta).slice(0, 500) : null).run();
}

export function adminEmails(env) {
  return (env.ADMIN_EMAILS || '').split(',').map(function (e) { return e.trim().toLowerCase(); }).filter(Boolean);
}

// Grant admin to verified accounts whose email is provisioned via env config.
export async function maybeProvisionAdmin(env, user) {
  if (user.is_admin) return;
  if (adminEmails(env).indexOf((user.email || '').toLowerCase()) === -1) return;
  await env.DB.prepare('UPDATE users SET is_admin = 1, updated_at = datetime(\'now\') WHERE id = ?').bind(user.id).run();
  user.is_admin = 1;
}
