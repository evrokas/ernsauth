#!/usr/bin/env php
<?php

/**
 * schema.php -- ErnsAuth database initializer
 *
 * Usage:
 *   php schema.php          # Alias for --init
 *   php schema.php --init   # Create tables (safe to re-run)
 *   php schema.php --reset  # Drop all tables, recreate (DELETES ALL DATA)
 */

$baseDir = dirname(__DIR__);
$configFile = $baseDir . '/config/settings.php';

if (!file_exists($configFile)) {
    die("Config file not found: {$configFile}\nCopy config/settings.php and fill in DB credentials.\n");
}

$cfg = (array)(require $configFile);

$init  = in_array('--init',  $argv ?? [], true);
$reset = in_array('--reset', $argv ?? [], true);
if (!$init && !$reset) $init = true;

// Connect
$dsn = sprintf('mysql:host=%s;port=%d;charset=utf8mb4',
    $cfg['db_host'] ?? '127.0.0.1',
    $cfg['db_port'] ?? 3306
);

try {
    $pdo = new PDO($dsn, $cfg['db_user'] ?? 'ernsauth', $cfg['db_pass'] ?? '', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
} catch (Exception $e) {
    die("Cannot connect to MySQL: " . $e->getMessage() . "\n");
}

$dbName = $cfg['db_name'] ?? 'ernsauth';

// Create database if needed
$pdo->exec("CREATE DATABASE IF NOT EXISTS `{$dbName}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
$pdo->exec("USE `{$dbName}`");
$pdo->exec("SET sql_mode='STRICT_ALL_TABLES'");

echo "Database: {$dbName}\n\n";

// Reset
if ($reset) {
    echo "RESET mode: dropping all tables...\n";
    $pdo->exec("SET FOREIGN_KEY_CHECKS=0");
    $tables = ['audit_log', 'rate_limits', 'otp_codes', 'sso_challenges', 'client_apps',
               'sessions', 'totp_backup_codes', 'users', 'settings'];
    foreach ($tables as $t) {
        $pdo->exec("DROP TABLE IF EXISTS `{$t}`");
    }
    $pdo->exec("SET FOREIGN_KEY_CHECKS=1");
    echo "Tables dropped.\n\n";
    $init = true;
}

// Create tables
$pdo->exec("
CREATE TABLE IF NOT EXISTS settings (
    setting_key   VARCHAR(100) NOT NULL PRIMARY KEY,
    setting_value TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
");
echo "  Table: settings\n";

$pdo->exec("
CREATE TABLE IF NOT EXISTS users (
    id            CHAR(16)     NOT NULL PRIMARY KEY,
    username      VARCHAR(50)  NOT NULL,
    email         VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    display_name  VARCHAR(100) NOT NULL DEFAULT '',
    totp_secret   VARCHAR(64)  DEFAULT NULL,
    totp_enabled  TINYINT(1)   NOT NULL DEFAULT 0,
    is_admin      TINYINT(1)   NOT NULL DEFAULT 0,
    active        TINYINT(1)   NOT NULL DEFAULT 1,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_username (username),
    UNIQUE KEY uk_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
");
echo "  Table: users\n";

$pdo->exec("
CREATE TABLE IF NOT EXISTS totp_backup_codes (
    id         INT          NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id    CHAR(16)     NOT NULL,
    code_hash  CHAR(64)     NOT NULL,
    used       TINYINT(1)   NOT NULL DEFAULT 0,
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_backup_user (user_id),
    CONSTRAINT fk_backup_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
");
echo "  Table: totp_backup_codes\n";

$pdo->exec("
CREATE TABLE IF NOT EXISTS sessions (
    id           CHAR(64)     NOT NULL PRIMARY KEY,
    user_id      CHAR(16)     NOT NULL,
    token_hash   CHAR(64)     NOT NULL,
    ip_address   VARCHAR(45)  DEFAULT NULL,
    user_agent   VARCHAR(500) DEFAULT NULL,
    device_label VARCHAR(100) DEFAULT '',
    csrf_token   CHAR(64)     DEFAULT NULL,
    created_at   INT UNSIGNED NOT NULL,
    last_active  INT UNSIGNED NOT NULL,
    expires_at   INT UNSIGNED NOT NULL,
    UNIQUE KEY uk_token_hash (token_hash),
    INDEX idx_sessions_user (user_id),
    INDEX idx_sessions_expiry (expires_at),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
");
echo "  Table: sessions\n";

$pdo->exec("
CREATE TABLE IF NOT EXISTS client_apps (
    id           VARCHAR(50)  NOT NULL PRIMARY KEY,
    label        VARCHAR(100) NOT NULL,
    api_key_hash CHAR(64)     NOT NULL,
    callback_url VARCHAR(500) NOT NULL DEFAULT '',
    icon_emoji   VARCHAR(10)  DEFAULT '',
    active       TINYINT(1)   NOT NULL DEFAULT 1,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
");
echo "  Table: client_apps\n";

$pdo->exec("
CREATE TABLE IF NOT EXISTS sso_challenges (
    id                CHAR(32)     NOT NULL PRIMARY KEY,
    client_app_id     VARCHAR(50)  NOT NULL,
    challenge_number  SMALLINT     NOT NULL,
    client_ip         VARCHAR(45)  DEFAULT NULL,
    client_user_agent VARCHAR(500) DEFAULT NULL,
    requested_identity VARCHAR(128) DEFAULT NULL,
    status            ENUM('pending','approved','rejected','expired') NOT NULL DEFAULT 'pending',
    approved_by       CHAR(16)     DEFAULT NULL,
    auth_code         CHAR(32)     DEFAULT NULL,
    created_at        INT UNSIGNED NOT NULL,
    expires_at        INT UNSIGNED NOT NULL,
    INDEX idx_challenges_status (status, expires_at),
    INDEX idx_challenges_app (client_app_id),
    CONSTRAINT fk_challenges_app FOREIGN KEY (client_app_id) REFERENCES client_apps(id),
    CONSTRAINT fk_challenges_user FOREIGN KEY (approved_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
");
echo "  Table: sso_challenges\n";

$pdo->exec("
CREATE TABLE IF NOT EXISTS otp_codes (
    id         CHAR(32)     NOT NULL PRIMARY KEY,
    user_id    CHAR(16)     DEFAULT NULL,
    email      VARCHAR(255) NOT NULL,
    code_hash  CHAR(64)     NOT NULL,
    purpose    ENUM('login','password_reset') NOT NULL,
    used       TINYINT(1)   NOT NULL DEFAULT 0,
    created_at INT UNSIGNED NOT NULL,
    expires_at INT UNSIGNED NOT NULL,
    INDEX idx_otp_email (email, purpose),
    CONSTRAINT fk_otp_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
");
echo "  Table: otp_codes\n";

$pdo->exec("
CREATE TABLE IF NOT EXISTS rate_limits (
    rate_key     VARCHAR(200) NOT NULL PRIMARY KEY,
    attempts     INT UNSIGNED NOT NULL DEFAULT 1,
    window_start INT UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
");
echo "  Table: rate_limits\n";

$pdo->exec("
CREATE TABLE IF NOT EXISTS audit_log (
    id         INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id    CHAR(16)     DEFAULT NULL,
    action     VARCHAR(50)  NOT NULL,
    ip_address VARCHAR(45)  DEFAULT NULL,
    user_agent VARCHAR(500) DEFAULT NULL,
    details    JSON         DEFAULT NULL,
    created_at INT UNSIGNED NOT NULL,
    INDEX idx_audit_user (user_id),
    INDEX idx_audit_action (action, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
");
echo "  Table: audit_log\n";

// Bring an existing database up to date ---------------------------------------
// Every CREATE above is IF NOT EXISTS, which does nothing at all to a table
// that already exists -- so a database created by an older release keeps that
// release's columns forever, even though --init is documented as "safe to
// re-run" and reports "Database ready" with every table present. The failure
// then lands at runtime on the first query naming a newer column: upgrading
// across the commit that added sessions.csrf_token, for instance, leaves
// login.php dying with an uncaught "Unknown column 'csrf_token'" 500 while
// the schema looks complete.
//
// So reconcile the columns that were added after their table was introduced.
// Each is nullable with a default, so adding one to a populated table is
// non-destructive and needs no backfill. Checked against information_schema
// rather than caught from a failed ALTER, so re-running stays silent and
// idempotent once everything is present.
$addedColumns = [
    'sessions' => [
        'csrf_token' => 'ALTER TABLE sessions ADD COLUMN csrf_token CHAR(64) DEFAULT NULL',
    ],
    'sso_challenges' => [
        'requested_identity' => 'ALTER TABLE sso_challenges ADD COLUMN requested_identity VARCHAR(128) DEFAULT NULL',
    ],
];
$colStmt = $pdo->prepare(
    "SELECT COUNT(*) FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND COLUMN_NAME = ?"
);
$upgraded = 0;
foreach ($addedColumns as $tbl => $cols) {
    foreach ($cols as $col => $ddl) {
        $colStmt->execute([$dbName, $tbl, $col]);
        if (!$colStmt->fetchColumn()) {
            $pdo->exec($ddl);
            echo "  Added missing column: {$tbl}.{$col}\n";
            $upgraded++;
        }
    }
}
if ($upgraded > 0) {
    echo "\nUpgraded {$upgraded} column(s) on an existing database.\n";
}

// Verify
$tables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);
echo "\nDatabase ready.\n";
echo "Tables: " . implode(', ', $tables) . "\n";
