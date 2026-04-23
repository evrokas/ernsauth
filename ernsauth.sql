-- ErnsAuth — Database bootstrap script
-- Creates the MySQL user and full database schema.
--
-- Usage (run as MySQL root):
--   mysql -u root -p < ernsauth.sql
--
-- Adjust 'ernsauth_password' below before running.

-- ---------------------------------------------------------------------------
-- 1. User
-- ---------------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'ernsauth'@'localhost' IDENTIFIED BY 'ernsauth_password';

-- ---------------------------------------------------------------------------
-- 2. Database
-- ---------------------------------------------------------------------------
CREATE DATABASE IF NOT EXISTS `ernsauth`
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

GRANT ALL PRIVILEGES ON `ernsauth`.* TO 'ernsauth'@'localhost';
FLUSH PRIVILEGES;

USE `ernsauth`;
SET sql_mode = 'STRICT_ALL_TABLES';

-- ---------------------------------------------------------------------------
-- 3. Tables
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS settings (
    setting_key   VARCHAR(100) NOT NULL PRIMARY KEY,
    setting_value TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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
    UNIQUE KEY uk_email    (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS totp_backup_codes (
    id         INT          NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id    CHAR(16)     NOT NULL,
    code_hash  CHAR(64)     NOT NULL,
    used       TINYINT(1)   NOT NULL DEFAULT 0,
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_backup_user (user_id),
    CONSTRAINT fk_backup_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sessions (
    id           CHAR(64)     NOT NULL PRIMARY KEY,
    user_id      CHAR(16)     NOT NULL,
    token_hash   CHAR(64)     NOT NULL,
    ip_address   VARCHAR(45)  DEFAULT NULL,
    user_agent   VARCHAR(500) DEFAULT NULL,
    device_label VARCHAR(100) DEFAULT '',
    created_at   INT UNSIGNED NOT NULL,
    last_active  INT UNSIGNED NOT NULL,
    expires_at   INT UNSIGNED NOT NULL,
    UNIQUE KEY uk_token_hash  (token_hash),
    INDEX idx_sessions_user   (user_id),
    INDEX idx_sessions_expiry (expires_at),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS client_apps (
    id           VARCHAR(50)  NOT NULL PRIMARY KEY,
    label        VARCHAR(100) NOT NULL,
    api_key_hash CHAR(64)     NOT NULL,
    callback_url VARCHAR(500) NOT NULL DEFAULT '',
    icon_emoji   VARCHAR(10)  DEFAULT '',
    active       TINYINT(1)   NOT NULL DEFAULT 1,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sso_challenges (
    id                CHAR(32)     NOT NULL PRIMARY KEY,
    client_app_id     VARCHAR(50)  NOT NULL,
    challenge_number  SMALLINT     NOT NULL,
    client_ip         VARCHAR(45)  DEFAULT NULL,
    client_user_agent VARCHAR(500) DEFAULT NULL,
    status            ENUM('pending','approved','rejected','expired') NOT NULL DEFAULT 'pending',
    approved_by       CHAR(16)     DEFAULT NULL,
    auth_code         CHAR(32)     DEFAULT NULL,
    created_at        INT UNSIGNED NOT NULL,
    expires_at        INT UNSIGNED NOT NULL,
    INDEX idx_challenges_status (status, expires_at),
    INDEX idx_challenges_app    (client_app_id),
    CONSTRAINT fk_challenges_app  FOREIGN KEY (client_app_id) REFERENCES client_apps(id),
    CONSTRAINT fk_challenges_user FOREIGN KEY (approved_by)   REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS rate_limits (
    rate_key     VARCHAR(200) NOT NULL PRIMARY KEY,
    attempts     INT UNSIGNED NOT NULL DEFAULT 1,
    window_start INT UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS audit_log (
    id         INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id    CHAR(16)     DEFAULT NULL,
    action     VARCHAR(50)  NOT NULL,
    ip_address VARCHAR(45)  DEFAULT NULL,
    user_agent VARCHAR(500) DEFAULT NULL,
    details    JSON         DEFAULT NULL,
    created_at INT UNSIGNED NOT NULL,
    INDEX idx_audit_user   (user_id),
    INDEX idx_audit_action (action, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Done
-- ---------------------------------------------------------------------------
SELECT CONCAT('ErnsAuth schema ready. Tables: ',
    GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR ', '))
FROM information_schema.tables
WHERE table_schema = 'ernsauth';
