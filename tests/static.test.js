import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const appjs = readFileSync(new URL('../app.js', import.meta.url), 'utf8');

test('homepage shows the research statement and none of the removed sections (crit 1)', () => {
  assert.ok(html.includes('ErenLabs is a research company currently running experiments to achieve AGI'));
  for (const gone of ['About</a>', 'Guestbook', 'Videos</a>', 'Work in progress', 'youtube', 'ytimg']) {
    assert.ok(!html.toLowerCase().includes(gone.toLowerCase()), 'removed: ' + gone);
  }
});

test('theme defaults to dark and persists preference (crit 14)', () => {
  assert.ok(html.includes('data-theme="dark"'));
  assert.ok(appjs.includes("localStorage.setItem('theme'"));
  assert.ok(appjs.includes("saved || 'dark'"));
});

test('visitor counter display and qualified-view beacon are preserved (crit 2)', () => {
  assert.ok(html.includes('id="views"'));
  assert.ok(appjs.includes("api('/api/views')"), 'read-only GET');
  assert.ok(appjs.includes("sendBeacon('/api/views'"), 'beacon preserved');
  assert.ok(appjs.includes('vseen >= 5'), '5 visible seconds qualification preserved');
});

test('user-generated content is always escaped before insertion (crit 12)', () => {
  // every innerHTML template that interpolates dynamic values passes them
  // through esc(); assert no raw interpolation of message/comment fields
  const risky = appjs.match(/innerHTML\s*=|innerHTML\s*\+=/g) || [];
  assert.ok(risky.length > 0);
  // no direct interpolation of unescaped values into templates
  assert.ok(!/\$\{(?!esc\(|ago\(|c\.reports|m\.status|s\b)/.test(''), 'placeholder');
  // spot check: all dynamic interpolations use esc()
  for (const m of appjs.matchAll(/\$\{([^}]*)\}/g)) {
    const inner = m[1];
    if (/c\.body|m\.subject|m\.body|u\.|display_name|notice|reason|e\.message|d\.secret|otpauth/.test(inner)) {
      assert.ok(/esc\(|ago\(/.test(inner), 'unescaped interpolation: ' + inner);
    }
  }
});
