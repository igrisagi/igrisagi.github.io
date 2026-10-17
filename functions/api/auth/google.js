import { json, handle, randomToken, sha256hex, uid } from '../../_lib/util.js';
import { limited } from '../../_lib/auth.js';

// Google OIDC start: only active when the OAuth client is configured.
export async function onRequestGet(context) {
  return handle(async function () {
    var env = context.env;
    if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) {
      return json({ error: 'Google sign-in is not configured' }, 503);
    }
    await limited(env, context.request, 'oauth', 20, 600);
    var state = randomToken();
    var nonce = randomToken();
    await env.DB.prepare(
      "INSERT INTO oauth_states (id, nonce, expires_at) VALUES (?, ?, ?)"
    ).bind(await sha256hex(state), nonce, new Date(Date.now() + 600 * 1000).toISOString()).run();
    var origin = new URL(context.request.url).origin;
    var params = new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      redirect_uri: origin + '/api/auth/google-callback',
      response_type: 'code',
      scope: 'openid email profile',
      state: state,
      nonce: nonce,
      prompt: 'select_account'
    });
    return Response.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + params.toString(), 302);
  });
}
