# ErenLabs

Minimalist AGI research site on Cloudflare Pages + Pages Functions + D1.

## What this is

- `index.html`, `app.js` — the homepage: one research statement, sign-in,
  theme toggle (dark default), visitor counter, discussion, private messaging.
- `admin/` — administrator dashboard at `/admin` (not linked in navigation).
- `functions/api/**` — the backend (Cloudflare Pages Functions).
- `migrations/0001_init.sql` — database schema (applied to the D1 database).
- Existing tables `counters` (visitor counter) and `guestbook` are preserved.

## Stack and data

- Hosting: Cloudflare Pages (deploys from the `main` branch of this repo).
- Compute: Pages Functions (`functions/`), D1 binding named `DB`.
- Auth: email+password (PBKDF2-SHA-256, 600k iterations — the strongest KDF
  available in Workers' WebCrypto; see "Known limitations"), Google OIDC,
  phone OTP via Twilio. Sessions: random tokens stored as SHA-256 hashes,
  HttpOnly Secure SameSite=Lax cookies, rotated on login, revocable.
- Admin: provisioned via the `ADMIN_EMAILS` environment variable; requires a
  verified email and TOTP (RFC 6238) enrollment; admin sessions are elevated
  (AAL2) and expire after 30 minutes, then require re-verification.
- All SQL is parameterized. Mutating endpoints require an `X-Requested-With`
  header (CSRF) and are rate-limited in D1.

## Database migrations

Apply migrations with the Cloudflare API or `wrangler`:

  wrangler d1 execute erenlabs --file=migrations/0001_init.sql

Migrations are additive (`CREATE TABLE IF NOT EXISTS`); existing data,
including the visitor counter, is never dropped.

## Configuration (Pages project environment variables)

See `.env.example`. Nothing works with fake values: unconfigured providers
answer 503 and are hidden from the UI.

- `ADMIN_EMAILS` — comma-separated admin emails (currently eren2026io@gmail.com).
- `EMAIL_PROVIDER=resend`, `RESEND_API_KEY`, `EMAIL_FROM` — outbound mail.
  Without these, verification/reset mail is stored in the admin-visible
  `outbox` table (development fallback; nothing is delivered).
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` — Google sign-in. Create an
  OAuth client (Web) in Google Cloud Console with authorized redirect URI
  `https://erenlabs.me/api/auth/google-callback`.
- `SMS_PROVIDER=twilio`, `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`,
  `TWILIO_FROM` — phone OTP. Disabled until configured.

## First administrator setup

1. Register on the site with the email listed in `ADMIN_EMAILS`.
2. Verify the email (link by email, or from the admin `outbox` fallback
   visible after step 3, or set by the operator directly in D1:
   `UPDATE users SET email_verified = 1 WHERE email = '...'`).
3. Sign in again (the login provisions the admin role from `ADMIN_EMAILS`).
4. Open `/admin`, enroll TOTP with an authenticator app, and verify a code.

## Tests

  npm test

Node 22+, no dependencies: the suite runs the real Pages Function handlers
against an in-memory SQLite stand-in for D1. It covers registration,
verification, login, session rotation, reset, CSRF, rate limiting,
unconfigured providers, messaging privacy and persistence, comment
ownership, admin access control with MFA, moderation, audit logging, the
preserved visitor counter, and static checks on the homepage.

## Known limitations

- Argon2id is unavailable in Workers' WebCrypto; PBKDF2-SHA-256 with 600,000
  iterations is used instead (OWASP-recommended parameter).
- Without `EMAIL_PROVIDER`, verification and reset links are not delivered;
  they appear only in the admin outbox (development mode).
- YouTube embeds on the old homepage were removed with the Videos section.
