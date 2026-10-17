import { json, abort, handle, readJson, phoneE164, sha256hex, uid } from '../../_lib/util.js';
import { assertCsrf, limited } from '../../_lib/auth.js';

// Phone OTP via Twilio. Disabled (503) until the provider is configured.
export async function onRequestPost(context) {
  return handle(async function () {
    var env = context.env;
    if (!(env.SMS_PROVIDER === 'twilio' && env.TWILIO_ACCOUNT_SID && env.TWILIO_AUTH_TOKEN && env.TWILIO_FROM)) {
      return json({ error: 'phone sign-in is not configured' }, 503);
    }
    assertCsrf(context.request);
    await limited(env, context.request, 'otp', 5, 600);
    var data = await readJson(context.request);
    var phone = phoneE164(data.phone);

    // Resend cooldown: at most one code per 60 seconds per number.
    var recent = await env.DB.prepare(
      "SELECT created_at FROM phone_otps WHERE phone = ? AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1"
    ).bind(phone).first();
    if (recent && (Date.now() - new Date(recent.created_at + 'Z').getTime()) < 60000) {
      abort(json({ error: 'a code was just sent - wait a minute before requesting another' }, 429));
    }
    var code = String(Math.floor(100000 + crypto.getRandomValues(new Uint32Array(1))[0] % 900000));
    await env.DB.prepare(
      "INSERT INTO phone_otps (id, phone, code_hash, expires_at) VALUES (?, ?, ?, ?)"
    ).bind(uid(), phone, await sha256hex(phone + '|' + code), new Date(Date.now() + 600 * 1000).toISOString()).run();

    var res = await fetch('https://api.twilio.com/2010-04-01/Accounts/' + env.TWILIO_ACCOUNT_SID + '/Messages.json', {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + btoa(env.TWILIO_ACCOUNT_SID + ':' + env.TWILIO_AUTH_TOKEN),
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({ To: phone, From: env.TWILIO_FROM, Body: 'Your ErenLabs code: ' + code + ' (expires in 10 minutes)' })
    });
    if (!res.ok) return json({ error: 'could not send the code' }, 502);
    return json({ ok: true });
  });
}
