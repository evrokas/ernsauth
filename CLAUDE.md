# ErnsAuth — Centralized Authentication Gateway

## Tech Stack
- PHP 7.4+ / MySQL / vanilla JS (no frameworks, no build tools)
- Apache with .htaccess

## Project Structure
- `web/` — Apache DocumentRoot (public-facing PHP, CSS, JS)
- `src/` — PHP classes (Config, Auth, TOTP, SSO, RateLimit, AuditLog, Mailer)
- `config/settings.php` — Deployment config (DB creds, SMTP, URLs)
- `client/ErnsAuthClient.php` — Drop-in client library for integrating apps
- `lib/phpmailer/` — PHPMailer (external dependency, git-ignored)

## Key Patterns
- **Config**: MySQL PDO singleton via `Config::getInstance()`
- **Auth**: Session + cookie-based, adapted from tracker's auth.php
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
