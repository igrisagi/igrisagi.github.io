// Cloudflare Turnstile (bot check). Off unless TURNSTILE_SECRET_KEY is set.
// When configured, state-changing public endpoints fail closed without a
// valid token - never silently skip.
import { json, abort } from './util.js';

export function turnstileOn(env) { return !!env.TURNSTILE_SECRET_KEY; }

export async function requireTurnstile(env, request, token) {
  if (!turnstileOn(env)) return;
  var form = new URLSearchParams();
  form.set('secret', env.TURNSTILE_SECRET_KEY);
  form.set('response', String(token || ''));
  var ip = request.headers.get('CF-Connecting-IP');
  if (ip) form.set('remoteip', ip);
  var ok = false;
  try {
    var res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
    var d = await res.json();
    ok = !!(d && d.success);
  } catch (e) { ok = false; }
  if (!ok) abort(json({ error: 'bot check failed - please try again', code: 'captcha' }, 403));
}
