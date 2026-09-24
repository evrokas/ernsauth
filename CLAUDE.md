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
- **State changes are POSTs.** `api.php` takes its action from the query
  string but only CSRF-checks POSTs, so a mutating action reachable by GET
  is a credentialed cross-site request (and `SameSite=Lax` sends the cookie
  on cross-site *navigation*). `$readOnlyActions` there is an allowlist —
  anything not on it must be POSTed — so a newly added action defaults to
  protected rather than exposed. Signing out is a POST form for the same
  reason.
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

## Backups + health monitoring (`lib/zops`, `deploy/{backup,health}-handler.php`)

ErnsAuth's first backup/health-check setup, on **zops**
(<https://github.com/evrokas/zops>, cloned as `lib/zops/` — see
`lib/zops/docs/INSTALL.md`), the shared backup + health-monitoring engine
used across this practice's app suite. zops carries no knowledge of this
app's schema at all — it invokes `deploy/backup-handler.php` and
`deploy/health-handler.php` as separate subprocesses, each speaking the
plain JSON protocol documented in `lib/zops/docs/PROTOCOL.md`/`HANDLERS.md`.

**Why this app's backup matters more than most in this suite**: ErnsAuth
is the single shared credential store — every integrating app trusts it
to say who's who — so its `users`/`sessions`/`totp_backup_codes`/
`client_apps`/`audit_log` tables are the one dataset a compromise or loss
here can't be recovered from any other app's own backup.

**`deploy/backup-handler.php`** ships 2 elements: `db` (`mysqldump
--single-transaction` of the `ernsauth` database) and `config`
(`config/settings.php` — DB + SMTP credentials, so this makes every
generation credential-bearing; see `lib/zops/docs/SECURITY.md`). No
file-store element — this app writes nothing to disk at runtime beyond
the database itself.

**`deploy/health-handler.php`** checks the database connects; that
`sso-api.php` with no `X-API-Key` returns 401 (the entire trust boundary
every integrating app relies on — a 200 here would mean SSO is
completely open); that a logged-out request to `dashboard.php` never
renders the dashboard; and flags (as a `warn`, not a `fail` — there's no
cron for this, only the admin API's manual `cleanup` action) a large
backlog of expired `sessions`/stale `rate_limits` rows, which otherwise
just grow forever unnoticed. `info` surfaces `users_total`,
`active_sessions`, `logins_today`, `failed_logins_today` (from
`audit_log`'s `login`/`login_failed` actions), and the two
pending-cleanup counts. Both route checks use **no credentials** — the
point is to catch auth breaking entirely, not to exercise a real
client-app or user session.

**Setup**: `deploy/backup.conf.example` (copy to
`/etc/zops/sites.d/ernsauth.conf`), `deploy/ernsauth-backup.cron`,
`deploy/ernsauth-logrotate`. `bash lib/zops/bin/zops-doctor
--site=ernsauth` verifies the setup before trusting cron with it;
`lib/zops/bin/zops-backup --site=ernsauth --dry-run` shows exactly what a
real run would ship.

**Verified in this sandbox** (no live MySQL server/client tools here —
same "honest limits" disclosed for every other app in this suite):
`php -l` clean on both handlers; `describe` clean on both; `zops-doctor
--site=ernsauth` reports every check passing (config loads, both
handlers exist/executable/respond to `describe`, hardlinking works under
`WORK_DIR`, the local test destination is writable); `zops-backup
--site=ernsauth --dry-run` correctly reaches the `mysqldump` invocation
and fails cleanly with a proper JSON failure report (`stage: "prepare"`,
no partial elements) when the binary itself is absent from this sandbox;
`health-handler.php check` degrades cleanly with no live MySQL/dev-server
(every check reports a real, specific `fail`, never an uncaught
exception). Has not been run against a live MySQL server or a real
Apache/PHP deployment in this sandbox.
