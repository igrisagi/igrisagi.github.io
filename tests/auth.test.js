import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createD1, migrate } from './d1shim.js';
import { makeEnv, req, ctx, sessionCookieOf, migrationSql, registerUser } from './helpers.js';

function setup() {
  const db = createD1();
  migrate(db, migrationSql);
  return { db, env: makeEnv(db) };
}

test('register creates an unverified user and a session; verification flips the flag (crit 3,4)', async () => {
  const { env } = setup();
  const mod = await import('../functions/api/auth/register.js');
  const res = await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/register', body: { email: 'a@b.co', display_name: 'A', password: 'password-long-enough' } })));
  assert.equal(res.status, 201);
  assert.ok(sessionCookieOf(res));
  const u = await env.DB.prepare('SELECT email_verified FROM users WHERE email = ?').bind('a@b.co').first();
  assert.equal(u.email_verified, 0);
  const mail = await env.DB.prepare("SELECT body FROM outbox WHERE to_email='a@b.co'").first();
  const token = mail.body.match(/token=([A-Za-z0-9_-]+)/)[1];
  const vmod = await import('../functions/api/auth/verify-email.js');
  const vres = await vmod.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/auth/verify-email?token=' + token })));
  assert.equal(vres.status, 302);
  const u2 = await env.DB.prepare('SELECT email_verified FROM users WHERE email = ?').bind('a@b.co').first();
  assert.equal(u2.email_verified, 1);
  // token is single-use
  const vres2 = await vmod.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/auth/verify-email?token=' + token })));
  assert.equal(vres2.status, 400);
});

test('registering the same email twice does not enumerate (crit 10: no account enumeration)', async () => {
  const { env } = setup();
  await registerUser(env.DB, env, 'dupe@x.co');
  const mod = await import('../functions/api/auth/register.js');
  const res = await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/register', body: { email: 'dupe@x.co', display_name: 'B', password: 'password-long-enough' } })));
  assert.equal(res.status, 200);
  const n = await env.DB.prepare("SELECT COUNT(*) c FROM users WHERE email='dupe@x.co'").first();
  assert.equal(n.c, 1);
});

test('login succeeds with correct password, rejects wrong one, rotates session (crit 3)', async () => {
  const { env } = setup();
  const first = await registerUser(env.DB, env, 'c@d.co');
  const mod = await import('../functions/api/auth/login.js');
  const bad = await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/login', body: { email: 'c@d.co', password: 'wrong-password-1' } })));
  assert.equal(bad.status, 401);
  const good = await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/login', body: { email: 'c@d.co', password: 'password-long-enough' }, cookie: first.cookie })));
  assert.equal(good.status, 200);
  const cookie2 = sessionCookieOf(good);
  assert.ok(cookie2 && cookie2 !== first.cookie, 'session rotated on login');
  // old session revoked
  const smod = await import('../functions/api/auth/session.js');
  const sres = await smod.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/auth/session', cookie: first.cookie })));
  const sdata = await sres.json();
  assert.equal(sdata.authenticated, false);
});

test('CSRF: mutations without the custom header are rejected', async () => {
  const { env } = setup();
  const mod = await import('../functions/api/auth/login.js');
  const r = new Request('https://erenlabs.test/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'x@y.z', password: 'whatever-long' }) });
  const res = await mod.onRequestPost(ctx(env, r));
  assert.equal(res.status, 403);
});

test('password reset: token is single-use and revokes sessions', async () => {
  const { env } = setup();
  const u = await registerUser(env.DB, env, 'r@e.co');
  const rmod = await import('../functions/api/auth/request-reset.js');
  await rmod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/request-reset', body: { email: 'r@e.co' } })));
  const mail = await env.DB.prepare("SELECT body FROM outbox WHERE to_email='r@e.co' AND kind='reset'").first();
  const token = mail.body.match(/reset=([A-Za-z0-9_-]+)/)[1];
  const pmod = await import('../functions/api/auth/reset-password.js');
  const res = await pmod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/reset-password', body: { token, password: 'new-password-1234' } })));
  assert.equal(res.status, 200);
  const again = await pmod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/reset-password', body: { token, password: 'another-password-9' } })));
  assert.equal(again.status, 400);
  const smod = await import('../functions/api/auth/session.js');
  const sdata = await (await smod.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/auth/session', cookie: u.cookie })))).json();
  assert.equal(sdata.authenticated, false);
  // new password works
  const lmod = await import('../functions/api/auth/login.js');
  const ok = await lmod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/login', body: { email: 'r@e.co', password: 'new-password-1234' } })));
  assert.equal(ok.status, 200);
});

test('rate limiting kicks in on repeated logins (crit 13)', async () => {
  const { env } = setup();
  await registerUser(env.DB, env, 'rl@f.co');
  const mod = await import('../functions/api/auth/login.js');
  let last;
  for (let i = 0; i < 11; i++) {
    last = await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/login', body: { email: 'rl@f.co', password: 'nope-nope-nope' } })));
  }
  assert.equal(last.status, 429);
});

test('unconfigured providers answer 503, never fake success (no fabricated integrations)', async () => {
  const { env } = setup();
  const g = await import('../functions/api/auth/google.js');
  const gres = await g.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/auth/google' })));
  assert.equal(gres.status, 503);
  const p = await import('../functions/api/auth/phone-start.js');
  const pres = await p.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/phone-start', body: { phone: '+14155552671' } })));
  assert.equal(pres.status, 503);
});
