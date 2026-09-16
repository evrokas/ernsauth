#!/usr/bin/env php
<?php
/**
 * ernsauth's zops backup handler. See ../../zops/docs/HANDLERS.md.
 *
 * Elements shipped:
 *   - db      mysqldump of the ernsauth MySQL database (--single-transaction) --
 *             users, sessions, TOTP backup codes, client app API-key hashes,
 *             the audit log; every piece of real data this app has
 *   - config  config/settings.php -- DB + SMTP credentials, so this makes
 *             every generation credential-bearing (see
 *             ../../zops/docs/SECURITY.md)
 *
 * No file-store element -- ernsauth writes nothing to disk at runtime
 * beyond the database itself (confirmed: no upload path, no libpath-style
 * directory anywhere in web/ or src/).
 */
declare(strict_types=1);

require __DIR__ . '/../lib/zops/lib/handler/bootstrap.php';

use ZOps\Handler\ConfigBundle;
use ZOps\Handler\Ctx;
use ZOps\Handler\Handler;
use ZOps\Handler\MysqlDump;

Handler::backup([
    'id' => 'ernsauth',
    'name' => 'ErnsAuth',
    'prepare' => function (Ctx $c): void {
        $appRoot = dirname(__DIR__);
        $settingsFile = $appRoot . '/config/settings.php';
        $settings = is_file($settingsFile) ? (array) require $settingsFile : [];

        $dbConfig = [
            'host' => $settings['db_host'] ?? '127.0.0.1',
            'user' => $settings['db_user'] ?? 'ernsauth',
            'pass' => $settings['db_pass'] ?? '',
            'db' => $settings['db_name'] ?? 'ernsauth',
        ];

        $c->add(MysqlDump::zip($c, 'db', $dbConfig));
        $c->add(ConfigBundle::zip($c, 'config', [$settingsFile]));

        $stats = ['users' => 0, 'active_sessions' => 0, 'client_apps' => 0];
        try {
            $pdo = new PDO(
                sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $dbConfig['host'], $settings['db_port'] ?? 3306, $dbConfig['db']),
                $dbConfig['user'],
                $dbConfig['pass'],
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
            );
            $stats['users'] = (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
            $stats['active_sessions'] = (int) $pdo->query('SELECT COUNT(*) FROM sessions WHERE expires_at > UNIX_TIMESTAMP()')->fetchColumn();
            $stats['client_apps'] = (int) $pdo->query('SELECT COUNT(*) FROM client_apps WHERE active = 1')->fetchColumn();
        } catch (Throwable $e) {
            // Non-fatal for the stats block -- mysqldump above either
            // already succeeded (the backup itself is fine) or already
            // threw and aborted the run before this point.
        }
        $c->setStats($stats);
    },
]);
