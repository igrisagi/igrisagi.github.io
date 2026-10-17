import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createD1, migrate } from './d1shim.js';
import { makeEnv, req, ctx, migrationSql, registerUser } from './helpers.js';

function setup() {
  const db = createD1();
  migrate(db, migrationSql);
  return { db, env: makeEnv(db) };
}

// Promote via server-side config path (env ADMIN_EMAILS), enroll + confirm
// TOTP directly in DB (the WebCrypto path is covered by verify below), and
// elevate the session.
async function makeAdmin(env, email = 'admin@erenlabs.test') {
  const u = await registerUser(env.DB, env, email, 'Boss');
  const loginMod = await import('../functions/api/auth/login.js');
  const { sessionCookieOf } = await import('./helpers.js');
  // login triggers maybeProvisionAdmin (env ADMIN_EMAILS contains this email)
  const res = await loginMod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/login', body: { email, password: 'password-long-enough' }, cookie: u.cookie })));
  const cookie = sessionCookieOf(res);
  const row = await env.DB.prepare('SELECT is_admin FROM users WHERE email = ?').bind(email).first();
  assert.equal(row.is_admin, 1, 'admin provisioned from env config');
  // enroll TOTP through the real endpoints
  const emod = await import('../functions/api/auth/totp/enroll.js');
  const enr = await (await emod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/totp/enroll', body: {}, cookie })))).json();
  assert.ok(enr.secret);
  const { totpCodeNow } = await import('./totphelper.js');
  const cmod = await import('../functions/api/auth/totp/confirm.js');
  const c = await cmod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/totp/confirm', body: { code: await totpCodeNow(enr.secret) }, cookie })));
  assert.equal(c.status, 200);
  const vmod = await import('../functions/api/auth/totp/verify.js');
  const v = await vmod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/totp/verify', body: { code: await totpCodeNow(enr.secret) }, cookie })));
  assert.equal(v.status, 200);
  return { cookie, email };
}

test('ordinary users cannot access admin routes (crit 8)', async () => {
  const { env } = setup();
  const u = await registerUser(env.DB, env, 'ord@x.co');
  const mod = await import('../functions/api/admin/messages.js');
  const res = await mod.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/admin/messages', cookie: u.cookie })));
  assert.equal(res.status, 403);
  const anon = await mod.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/admin/messages' })));
  assert.equal(anon.status, 401);
});

test('admin requires provisioned role + MFA elevation; then can manage messages (crit 9,10)', async () => {
  const { env } = setup();
  const visitor = await registerUser(env.DB, env, 'vis@x.co', 'Vis');
  const mmod = await import('../functions/api/messages.js');
  await mmod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/messages', body: { subject: 'question', body: 'what is AGI' }, cookie: visitor.cookie })));

  const adminNoMfa = await registerUser(env.DB, env, 'admin@erenlabs.test', 'Boss');
  const amod = await import('../functions/api/admin/messages.js');
  // admin-flagged but no TOTP yet -> blocked
  const loginMod = await import('../functions/api/auth/login.js');
  const { sessionCookieOf } = await import('./helpers.js');
  const lres = await loginMod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/login', body: { email: 'admin@erenlabs.test', password: 'password-long-enough' } })));
  const cookie = sessionCookieOf(lres);
  const blocked = await amod.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/admin/messages', cookie })));
  assert.equal(blocked.status, 403);
  assert.equal((await blocked.json()).code, 'mfa_enroll');

  // full MFA flow
  const emod = await import('../functions/api/auth/totp/enroll.js');
  const enr = await (await emod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/totp/enroll', body: {}, cookie })))).json();
  const { totpCodeNow } = await import('./totphelper.js');
  const cmod = await import('../functions/api/auth/totp/confirm.js');
  await cmod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/totp/confirm', body: { code: await totpCodeNow(enr.secret) }, cookie })));
  const stillBlocked = await amod.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/admin/messages', cookie })));
  assert.equal((await stillBlocked.json()).code, 'mfa_required');
  const vmod = await import('../functions/api/auth/totp/verify.js');
  const badCode = await vmod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/totp/verify', body: { code: '000000' }, cookie })));
  assert.equal(badCode.status, 401);
  await vmod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/totp/verify', body: { code: await totpCodeNow(enr.secret) }, cookie })));

  const list = await (await amod.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/admin/messages', cookie })))).json();
  assert.equal(list.messages.length, 1);
  const msgId = list.messages[0].id;
  const imod = await import('../functions/api/admin/messages/[id].js');
  await imod.onRequestPatch(ctx(env, req({ method: 'PATCH', url: 'https://erenlabs.test/api/admin/messages/' + msgId, body: { status: 'read' }, cookie }), { id: msgId }));
  const reply = await imod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/admin/messages/' + msgId, body: { body: 'an answer' }, cookie }), { id: msgId }));
  assert.equal(reply.status, 201);
  // visitor sees the reply in their own thread
  const vlist = await (await mmod.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/messages', cookie: visitor.cookie })))).json();
  assert.equal(vlist.messages.length, 2);
  assert.equal(vlist.messages[1].from_admin, 1);
  // audit log recorded the actions
  const amod2 = await import('../functions/api/admin/audit.js');
  const audit = await (await amod2.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/admin/audit', cookie })))).json();
  assert.ok(audit.audit.length >= 2);
});
