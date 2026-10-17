import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createD1, migrate } from './d1shim.js';
import { makeEnv, req, ctx, migrationSql, registerUser } from './helpers.js';

function setup() {
  const db = createD1();
  migrate(db, migrationSql);
  return { db, env: makeEnv(db) };
}

test('unauthenticated visitors cannot send messages (crit 5)', async () => {
  const { env } = setup();
  const mod = await import('../functions/api/messages.js');
  const res = await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/messages', body: { subject: 'hi', body: 'there' } })));
  assert.equal(res.status, 401);
});

test('unverified users cannot send messages; verified users can and messages persist (crit 4,6)', async () => {
  const { env } = setup();
  const rmod = await import('../functions/api/auth/register.js');
  const { sessionCookieOf } = await import('./helpers.js');
  const res = await rmod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/register', body: { email: 'v@w.co', display_name: 'V', password: 'password-long-enough' } })));
  const cookie = sessionCookieOf(res);
  const mod = await import('../functions/api/messages.js');
  const blocked = await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/messages', body: { subject: 'hi', body: 'there' }, cookie })));
  assert.equal(blocked.status, 403);
  // verify email via outbox link
  const mail = await env.DB.prepare("SELECT body FROM outbox WHERE to_email='v@w.co' AND kind='verify'").first();
  const token = mail.body.match(/token=([A-Za-z0-9_-]+)/)[1];
  const vmod = await import('../functions/api/auth/verify-email.js');
  await vmod.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/auth/verify-email?token=' + token })));
  const ok = await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/messages', body: { subject: 'hi', body: 'there' }, cookie })));
  assert.equal(ok.status, 201);
  // persistence: re-import the handler against the same DB and read back
  const again = await import('../functions/api/messages.js?x=2').catch(() => mod);
  const list = await (await (again.onRequestGet || mod.onRequestGet)(ctx(env, req({ url: 'https://erenlabs.test/api/messages', cookie })))).json();
  assert.equal(list.messages.length, 1);
  assert.equal(list.messages[0].subject, 'hi');
});

test('one user cannot read another user\'s messages (crit 7)', async () => {
  const { env } = setup();
  const a = await registerUser(env.DB, env, 'a1@x.co', 'A One');
  const b = await registerUser(env.DB, env, 'b1@x.co', 'B One');
  const mod = await import('../functions/api/messages.js');
  await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/messages', body: { subject: 'secret', body: 'for admin only' }, cookie: a.cookie })));
  const listB = await (await mod.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/messages', cookie: b.cookie })))).json();
  assert.equal(listB.messages.length, 0);
});

test('comments: auth required, owners can edit/delete, others cannot (crit 11)', async () => {
  const { env } = setup();
  const a = await registerUser(env.DB, env, 'ca@x.co', 'C A');
  const b = await registerUser(env.DB, env, 'cb@x.co', 'C B');
  const mod = await import('../functions/api/comments.js');
  const noauth = await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/comments', body: { body: 'hello' } })));
  assert.equal(noauth.status, 401);
  const created = await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/comments', body: { body: 'hello world' }, cookie: a.cookie })));
  assert.equal(created.status, 201);
  const { id } = await created.json();
  const item = await import('../functions/api/comments/[id].js');
  const notYours = await item.onRequestPatch(ctx(env, req({ method: 'PATCH', url: 'https://erenlabs.test/api/comments/' + id, body: { body: 'hijack' }, cookie: b.cookie }), { id }));
  assert.equal(notYours.status, 403);
  const notYours2 = await item.onRequestDelete(ctx(env, req({ method: 'DELETE', url: 'https://erenlabs.test/api/comments/' + id, body: {}, cookie: b.cookie }), { id }));
  assert.equal(notYours2.status, 403);
  const edit = await item.onRequestPatch(ctx(env, req({ method: 'PATCH', url: 'https://erenlabs.test/api/comments/' + id, body: { body: 'edited' }, cookie: a.cookie }), { id }));
  assert.equal(edit.status, 200);
  const list = await (await mod.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/comments' })))).json();
  assert.equal(list.comments[0].body, 'edited');
  assert.ok(list.comments[0].edited_at);
  const del = await item.onRequestDelete(ctx(env, req({ method: 'DELETE', url: 'https://erenlabs.test/api/comments/' + id, body: {}, cookie: a.cookie }), { id }));
  assert.equal(del.status, 200);
  const list2 = await (await mod.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/comments' })))).json();
  assert.equal(list2.comments.length, 0);
});

test('visitor counter preserved: GET never increments, qualified POST does, bots do not (crit 2)', async () => {
  const { env } = setup();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS counters (key TEXT PRIMARY KEY, value INTEGER NOT NULL)").run();
  await env.DB.prepare("INSERT INTO counters (key, value) VALUES ('views', 0)").run();
  const mod = await import('../functions/api/views.js');
  const g1 = await (await mod.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/views' })))).json();
  const g2 = await (await mod.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/views' })))).json();
  assert.equal(g1.views, g2.views);
  const bot = await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/views', body: { t: 9 }, headers: { 'User-Agent': 'Googlebot' } })));
  assert.equal((await bot.json()).counted, false);
  const quick = await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/views', body: { t: 1 } })));
  assert.equal((await quick.json()).counted, false);
  const real = await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/views', body: { t: 6 } })));
  assert.equal((await real.json()).counted, true);
  const dup = await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/views', body: { t: 6 } })));
  assert.equal((await dup.json()).counted, false);
});

test('guestbook endpoint still works after migration (crit 16)', async () => {
  const { env } = setup();
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS guestbook (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT DEFAULT (datetime(\'now\')))').run();
  const mod = await import('../functions/api/guestbook.js');
  await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/guestbook', body: { name: 'n', message: 'm' } })));
  const list = await (await mod.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/guestbook' })))).json();
  assert.equal(list.entries.length, 1);
});
