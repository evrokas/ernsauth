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

Copy `client/ErnsAuthClient.php` into your app and configure it with your app's API key and the ErnsAuth base URL:

```php
require_once 'ErnsAuthClient.php';

$client = new ErnsAuthClient([
    'base_url' => 'https://auth.example.com',
    'api_key'  => 'your-app-api-key',
]);
```

## Database Tables

`settings`, `users`, `totp_backup_codes`, `sessions`, `client_apps`, `sso_challenges`, `otp_codes`, `rate_limits`, `audit_log`

## License

MIT — see [LICENSE](LICENSE).
