# ErnsAuth

Centralized authentication gateway for PHP application ecosystems. Provides SSO (Single Sign-On), TOTP two-factor authentication, email OTP, session management, and a drop-in client library for integrating apps.

## Features

- **Session-based authentication** with secure cookie handling
- **TOTP 2FA** — RFC 6238 pure-PHP implementation with backup codes
- **SSO** — number-matching challenge-response flow across apps
- **Email OTP & password reset** via PHPMailer
- **Rate limiting** — MySQL-backed sliding window
- **Audit log** — queryable event trail
- **Admin dashboard** — sessions, pending logins, security settings, user management
- **Drop-in client library** — `client/ErnsAuthClient.php` for integrating apps

## Tech Stack

- PHP 7.4+ / MySQL / vanilla JS (no frameworks, no build tools)
- Apache with `.htaccess`

## Project Structure

```
src/            PHP classes (Config, Auth, TOTP, SSO, RateLimit, AuditLog, Mailer)
web/            Apache DocumentRoot (public-facing PHP, CSS, JS)
config/         Deployment config (DB credentials, SMTP, URLs)
client/         Drop-in client library for integrating apps
lib/            External dependencies (PHPMailer — git-ignored)
```

## Setup

### 1. Configuration

```bash
cp config/settings.example.php config/settings.php
# Edit config/settings.php with your DB credentials, SMTP settings, and URLs
```

### 2. Database

```bash
# Initialize schema
php src/schema.php --init

# Reset (drops and recreates all tables)
php src/schema.php --reset
```

### 3. Web Server

Point Apache DocumentRoot to `web/`. The `.htaccess` handles routing.

### 4. PHPMailer

Place PHPMailer in `lib/phpmailer/` (not tracked in git).

## API

### Internal API (`web/api.php`)

Requires an active session and `X-CSRF-Token` header.

```
GET/POST api.php?action=<action>
```

### SSO API (`web/sso-api.php`)

Requires `X-API-Key` header (registered client app key).

```
GET/POST sso-api.php?action=<action>
```

## Client Integration

**See [CLIENT-INTEGRATION.md](CLIENT-INTEGRATION.md) for the full guide** — both sign-in flows (number matching without a username, and email OTP where the user identifies themselves first), worked examples, error and rate-limit handling, and an implementation checklist. The quick version follows.

Clone this repo's `stable` branch into your app (e.g. `lib/ernsauth`) rather than hand-copying `client/ErnsAuthClient.php` — `stable` always holds the latest stable release, and `git pull` there picks up updates without a manual re-copy that can silently drift from upstream:

```bash
git clone -b stable https://github.com/evrokas/ernsauth.git lib/ernsauth
```

```php
require_once 'lib/ernsauth/client/ErnsAuthClient.php';

$client = new ErnsAuthClient('https://auth.example.com/sso-api.php', 'your-app-api-key');
```

### Checking for updates

`client/VersionCheck.php` compares the app's local clone against `stable`'s current commit on GitHub (`git ls-remote`, no auth needed since this repo is public) and reports whether a newer version is available, so an integrating app can prompt an admin to update instead of silently drifting:

```php
require_once 'lib/ernsauth/client/VersionCheck.php';

$result = VersionCheck::check(__DIR__ . '/lib/ernsauth');
if ($result['status'] === 'update_available') {
    // show a notice: run `cd lib/ernsauth && git pull`
}
```

`$result['status']` is one of `up_to_date`, `update_available`, or `unknown` (network unreachable, not a git checkout, etc. -- see `$result['reason']`); it never throws, but it does make a network call with up to a few seconds' timeout, so cache the result (e.g. once a day) rather than calling it on every request. See the docblock in `client/VersionCheck.php` for the full signature.

## Database Tables

`settings`, `users`, `totp_backup_codes`, `sessions`, `client_apps`, `sso_challenges`, `otp_codes`, `rate_limits`, `audit_log`

## License

MIT — see [LICENSE](LICENSE).
