import { readFileSync } from 'node:fs';

export function makeEnv(db, extra = {}) {
  return { DB: db, ADMIN_EMAILS: 'admin@erenlabs.test', ...extra };
}

export function req({ method = 'GET', url = 'https://erenlabs.test', body, headers = {}, cookie } = {}) {
  const h = { 'CF-Connecting-IP': '203.0.113.7', 'User-Agent': 'test-agent', ...headers };
  if (body !== undefined) {
    h['Content-Type'] = 'application/json';
    h['X-Requested-With'] = 'fetch';
    body = JSON.stringify(body);
  }
  if (cookie) h['Cookie'] = 'eren_session=' + cookie;
  return new Request(url, { method, headers: h, body });
}

export function ctx(env, request, params = {}) {
  return { env, request, params, waitUntil() {} };
}

export function sessionCookieOf(response) {
  const sc = response.headers.get('Set-Cookie') || '';
  const m = sc.match(/eren_session=([^;]*)/);
  return m ? m[1] : null;
}

export const migrationSql = readFileSync(new URL('../migrations/0001_init.sql', import.meta.url), 'utf8');

// Register + verify a user end-to-end, returning { cookie, id, email }.
export async function registerUser(db, env, email, name = 'Test User') {
  const mod = await import('../functions/api/auth/register.js');
  const res = await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/register', body: { email, display_name: name, password: 'password-long-enough' } })));
  const cookie = sessionCookieOf(res);
  const row = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  // verify via the outbox link
  const mail = await env.DB.prepare("SELECT body FROM outbox WHERE to_email = ? AND kind = 'verify' ORDER BY created_at DESC LIMIT 1").bind(email).first();
  const token = mail.body.match(/token=([A-Za-z0-9_-]+)/)[1];
  const vmod = await import('../functions/api/auth/verify-email.js');
  await vmod.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/auth/verify-email?token=' + token })));
  return { cookie, id: row.id, email };
}
