#!/usr/bin/env php
<?php
/**
 * ernsauth's zops health handler. See ../../zops/docs/HANDLERS.md.
 */
declare(strict_types=1);

require __DIR__ . '/../lib/zops/lib/handler/bootstrap.php';

use ZOps\Handler\Handler;
use ZOps\Handler\HealthCtx;

Handler::health([
    'id' => 'ernsauth',
    'name' => 'ErnsAuth',
    'check' => function (HealthCtx $h): void {
        $appRoot = dirname(__DIR__);
        $settingsFile = $appRoot . '/config/settings.php';
        $settings = is_file($settingsFile) ? (array) require $settingsFile : [];

        $pdo = null;
        try {
            $pdo = new PDO(
                sprintf(
                    'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
                    $settings['db_host'] ?? '127.0.0.1',
                    $settings['db_port'] ?? 3306,
                    $settings['db_name'] ?? 'ernsauth',
                ),
                $settings['db_user'] ?? 'ernsauth',
                $settings['db_pass'] ?? '',
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
            );
            $pdo->query('SELECT 1');
            $h->ok('db.connect', 'MySQL connects');
        } catch (Throwable $e) {
            $h->fail('db.connect', 'MySQL connects', $e->getMessage());
        }

        $baseUrl = rtrim(getenv('ERNSAUTH_HEALTH_BASE_URL') ?: 'http://127.0.0.1', '/');

        // sso-api.php with no X-API-Key must never succeed -- this is the
        // entire trust boundary integrating client apps rely on, so the
        // point is to catch it breaking entirely, not to exercise a real
        // client-app credential.
        $sso = $h->httpGet($baseUrl . '/web/sso-api.php?action=create_challenge');
        ($sso['code'] === 401)
            ? $h->ok('route.sso_api.gate', 'sso-api.php rejects an unauthenticated request')
            : $h->fail('route.sso_api.gate', 'sso-api.php rejects an unauthenticated request', "HTTP {$sso['code']}" . ($sso['error'] ? " ({$sso['error']})" : ''));

        // A logged-out session must never render the dashboard.
        $dash = $h->httpGet($baseUrl . '/web/dashboard.php');
        (in_array($dash['code'], [301, 302, 303, 307, 308], true) || stripos($dash['body'], 'login') !== false)
            ? $h->ok('route.dashboard.gate', 'Logged-out dashboard redirects to login')
            : $h->fail('route.dashboard.gate', 'Logged-out dashboard redirects to login', "HTTP {$dash['code']}" . ($dash['error'] ? " ({$dash['error']})" : ''));

        if ($pdo !== null) {
            $now = time();
            $h->info('users_total', (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn());
            $h->info('active_sessions', (int) $pdo->query("SELECT COUNT(*) FROM sessions WHERE expires_at > {$now}")->fetchColumn());

            $loginsToday = (int) $pdo->query("SELECT COUNT(*) FROM audit_log WHERE action = 'login' AND created_at >= " . strtotime('today'))->fetchColumn();
            $failedLoginsToday = (int) $pdo->query("SELECT COUNT(*) FROM audit_log WHERE action = 'login_failed' AND created_at >= " . strtotime('today'))->fetchColumn();
            $h->info('logins_today', $loginsToday);
            $h->info('failed_logins_today', $failedLoginsToday);

            // Not a failure by itself (there's no cron for this -- see
            // web/api.php's admin "cleanup" action), but a large backlog
            // of rows that should already be gone is worth surfacing: it
            // means an admin hasn't run cleanup in a while, and these
            // tables will otherwise just grow forever.
            $expiredSessions = (int) $pdo->query("SELECT COUNT(*) FROM sessions WHERE expires_at <= {$now}")->fetchColumn();
            $staleRateLimits = (int) $pdo->query("SELECT COUNT(*) FROM rate_limits WHERE window_start < " . ($now - 86400))->fetchColumn();
            $h->info('expired_sessions_pending_cleanup', $expiredSessions);
            $h->info('stale_rate_limits_pending_cleanup', $staleRateLimits);
            ($expiredSessions + $staleRateLimits < 5000)
                ? $h->ok('db.cleanup_backlog', 'Expired sessions/rate-limit rows are not piling up')
                : $h->warn('db.cleanup_backlog', 'Expired sessions/rate-limit rows are not piling up', "{$expiredSessions} expired sessions, {$staleRateLimits} stale rate-limit rows -- run the admin Cleanup action");
        }
    },
]);
