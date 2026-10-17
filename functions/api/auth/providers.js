import { json, handle } from '../../_lib/util.js';

// Tells the frontend which sign-in methods are actually configured, so
// unconfigured providers are never shown as available.
export async function onRequestGet(context) {
  return handle(async function () {
    return json({
      email: true,
      turnstile_site_key: context.env.TURNSTILE_SITE_KEY || null,
      google: !!(context.env.GOOGLE_CLIENT_ID && context.env.GOOGLE_CLIENT_SECRET),
      phone: !!(context.env.SMS_PROVIDER === 'twilio' && context.env.TWILIO_ACCOUNT_SID && context.env.TWILIO_AUTH_TOKEN && context.env.TWILIO_FROM)
    });
  });
}
