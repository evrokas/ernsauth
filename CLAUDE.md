# ErnsAuth — Centralized Authentication Gateway

## Tech Stack
- PHP 7.4+ / MySQL / vanilla JS (no frameworks, no build tools)
- Apache with .htaccess

## Project Structure
- `web/` — Apache DocumentRoot (public-facing PHP, CSS, JS)
- `src/` — PHP classes (Config, Auth, TOTP, SSO, RateLimit, AuditLog, Mailer)
- `config/settings.php` — Deployment config (DB creds, SMTP, URLs)
- `client/ErnsAuthClient.php` — Drop-in client library for integrating apps
- `client/VersionCheck.php` — Lets an integrating app detect when its client-library clone is behind the latest commit on GitHub
- `lib/phpmailer/` — PHPMailer (external dependency, git-ignored)

## Key Patterns
- **Config**: MySQL PDO singleton via `Config::getInstance()`
- **Auth**: Session + cookie-based, adapted from tracker's auth.php
- **Cookie SameSite must stay `Lax`** (`Auth::COOKIE_SAMESITE`, used by both
  the PHP session cookie and the `ea_session` "remember me" cookie). This is
  an SSO gateway, so users arrive by following a link/redirect *from* the
  integrating app — a cross-site navigation. `Strict` makes the browser
  withhold the cookie on exactly that navigation, so an arriving user gets
  the login form despite a valid 30-day cookie, while direct visits (typed
  URL, bookmark) keep working — which makes it look like "remember me" is
  broken at random. `Lax` still withholds the cookie from cross-site POSTs,
  so the CSRF protections are unaffected.
- **`schema.php --init` reconciles added columns**, not just whole tables:
  every `CREATE` is `IF NOT EXISTS`, which silently leaves an older database
  missing columns introduced later, and the app then dies at runtime on the
  first query naming one. New nullable columns belong in the `$addedColumns`
  map at the end of that script.
- **API dispatch**: `api.php?action=xxx` switch pattern, JSON in/out
- **SSO API**: `sso-api.php?action=xxx` — requires `X-API-Key` header
- **CSRF**: Token in `<meta name="csrf-token">`, sent via `X-CSRF-Token` header
- **Rate limiting**: MySQL-backed sliding window in `rate_limits` table
- **All user output**: escaped with `htmlspecialchars($s, ENT_QUOTES, 'UTF-8')`
- **All DB queries**: PDO prepared statements with bound parameters

## Database
- Name: `ernsauth`, charset: `utf8mb4`
- Init: `php src/schema.php --init`
- Reset: `php src/schema.php --reset`
- Tables: settings, users, totp_backup_codes, sessions, client_apps, sso_challenges, otp_codes, rate_limits, audit_log

## First Client App
- Route Tracker at `/var/www/html/apps/tracker`
- Uses `client/ErnsAuthClient.php` for SSO integration

## Branches
- `main` — active development
- `stable` — latest stable release; integrating apps clone this branch
  (e.g. `git clone -b stable ... lib/ernsauth`), not `main`, so their
  vendored client library only moves forward on a deliberate update, not
  every in-progress commit. Fast-forward it to a vetted `main` commit when
  cutting a release; `client/VersionCheck.php` is what lets an integrating
  app detect that a newer commit has landed here.
