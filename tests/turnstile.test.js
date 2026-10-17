import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createD1, migrate } from './d1shim.js';
import { makeEnv, req, ctx, migrationSql } from './helpers.js';

function setup(extra = {}) {
  const db = createD1();
  migrate(db, migrationSql);
  return { db, env: makeEnv(db, extra) };
}

function withSiteverify(success, fn) {
  const orig = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes('siteverify')) return new Response(JSON.stringify({ success }), { status: 200 });
    return orig(url);
  };
  return Promise.resolve().then(fn).finally(() => { globalThis.fetch = orig; });
}

test('turnstile unset: register works without a token (feature off)', async () => {
  const { env } = setup();
  const mod = await import('../functions/api/auth/register.js');
  const res = await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/register', body: { email: 't1@b.co', display_name: 'T', password: 'password-long-enough' } })));
  assert.equal(res.status, 201);
});

test('turnstile set: register without token is rejected (fail closed)', async () => {
  const { env } = setup({ TURNSTILE_SITE_KEY: 'k', TURNSTILE_SECRET_KEY: 's' });
  await withSiteverify(false, async () => {
    const mod = await import('../functions/api/auth/register.js');
    const res = await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/register', body: { email: 't2@b.co', display_name: 'T', password: 'password-long-enough' } })));
    assert.equal(res.status, 403);
    const d = await res.json();
    assert.equal(d.code, 'captcha');
  });
  const u = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind('t2@b.co').first();
  assert.equal(u, null);
});

test('turnstile set: register with a passing token succeeds', async () => {
  const { env } = setup({ TURNSTILE_SITE_KEY: 'k', TURNSTILE_SECRET_KEY: 's' });
  await withSiteverify(true, async () => {
    const mod = await import('../functions/api/auth/register.js');
    const res = await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/register', body: { email: 't3@b.co', display_name: 'T', password: 'password-long-enough', turnstile_token: 'tok' } })));
    assert.equal(res.status, 201);
  });
});

test('turnstile set: login without token is rejected', async () => {
  const { env } = setup({ TURNSTILE_SITE_KEY: 'k', TURNSTILE_SECRET_KEY: 's' });
  await withSiteverify(false, async () => {
    const mod = await import('../functions/api/auth/login.js');
    const res = await mod.onRequestPost(ctx(env, req({ method: 'POST', url: 'https://erenlabs.test/api/auth/login', body: { email: 'x@b.co', password: 'password-long-enough' } })));
    assert.equal(res.status, 403);
  });
});

test('providers reports the site key only when configured', async () => {
  const { env } = setup({ TURNSTILE_SITE_KEY: 'site-key-1', TURNSTILE_SECRET_KEY: 's' });
  const mod = await import('../functions/api/auth/providers.js');
  const res = await mod.onRequestGet(ctx(env, req({ url: 'https://erenlabs.test/api/auth/providers' })));
  const d = await res.json();
  assert.equal(d.turnstile_site_key, 'site-key-1');
  const { env: env2 } = setup();
  const res2 = await mod.onRequestGet(ctx(env2, req({ url: 'https://erenlabs.test/api/auth/providers' })));
  const d2 = await res2.json();
  assert.equal(d2.turnstile_site_key, null);
});
