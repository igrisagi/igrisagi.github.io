// Outbound email adapter. With EMAIL_PROVIDER=resend and RESEND_API_KEY set,
// mail is delivered through Resend. Without a provider, mail is stored in the
// admin-visible `outbox` table (development fallback - nothing is delivered,
// which keeps verification honest instead of fabricated).
import { uid } from './util.js';

export async function sendMail(env, to, kind, subject, body) {
  if (env.EMAIL_PROVIDER === 'resend' && env.RESEND_API_KEY) {
    var res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + env.RESEND_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: env.EMAIL_FROM || 'ErenLabs <no-reply@erenlabs.me>',
        to: [to], subject: subject, text: body
      })
    });
    if (!res.ok) throw new Error('mail provider rejected: ' + res.status);
    await env.DB.prepare('INSERT INTO outbox (id, to_email, kind, subject, body, sent_at) VALUES (?, ?, ?, ?, ?, datetime(\'now\'))')
      .bind(uid(), to, kind, subject, body).run();
    return true;
  }
  await env.DB.prepare('INSERT INTO outbox (id, to_email, kind, subject, body) VALUES (?, ?, ?, ?, ?)')
    .bind(uid(), to, kind, subject, body).run();
  return false; // stored, not delivered
}
