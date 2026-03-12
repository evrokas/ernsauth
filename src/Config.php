<?php

class Config
{
    private static ?Config $instance = null;
    private PDO $db;
    private array $deployConfig;

    private function __construct()
    {
        $file = dirname(__DIR__) . '/config/settings.php';
        $this->deployConfig = file_exists($file) ? (array)(require $file) : [];

        $dsn = sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
            $this->deployConfig['db_host'] ?? '127.0.0.1',
            $this->deployConfig['db_port'] ?? 3306,
            $this->deployConfig['db_name'] ?? 'ernsauth'
        );

        $this->db = new PDO($dsn,
            $this->deployConfig['db_user'] ?? 'ernsauth',
            $this->deployConfig['db_pass'] ?? '',
            [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]
        );
        $this->db->exec("SET sql_mode='STRICT_ALL_TABLES'");
    }

    public static function getInstance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public static function reset(): void
    {
        self::$instance = null;
    }

    public function db(): PDO
    {
        return $this->db;
    }

    public function get(string $key, $default = null)
    {
        return $this->deployConfig[$key] ?? $default;
    }

    // ── Settings table ──────────────────────────────────────────────────────

    public function getSetting(string $key): ?string
    {
        $st = $this->db->prepare("SELECT setting_value FROM settings WHERE setting_key = :k");
        $st->execute([':k' => $key]);
        $row = $st->fetch();
        return $row ? $row['setting_value'] : null;
    }

    public function setSetting(string $key, string $value): void
    {
        $st = $this->db->prepare(
            "INSERT INTO settings (setting_key, setting_value) VALUES (:k, :v)
             ON DUPLICATE KEY UPDATE setting_value = :v2"
        );
        $st->execute([':k' => $key, ':v' => $value, ':v2' => $value]);
    }

    // ── User methods ────────────────────────────────────────────────────────

    public function getUserById(string $id): ?array
    {
        $st = $this->db->prepare("SELECT * FROM users WHERE id = :id");
        $st->execute([':id' => $id]);
        return $st->fetch() ?: null;
    }

    public function getUserByUsername(string $username): ?array
    {
        $st = $this->db->prepare("SELECT * FROM users WHERE username = :u");
        $st->execute([':u' => $username]);
        return $st->fetch() ?: null;
    }

    public function getUserByEmail(string $email): ?array
    {
        $st = $this->db->prepare("SELECT * FROM users WHERE email = :e");
        $st->execute([':e' => $email]);
        return $st->fetch() ?: null;
    }

    public function getUserByLogin(string $login): ?array
    {
        $st = $this->db->prepare("SELECT * FROM users WHERE username = :l OR email = :l2");
        $st->execute([':l' => $login, ':l2' => $login]);
        return $st->fetch() ?: null;
    }

    public function createUser(array $data): string
    {
        $id = bin2hex(random_bytes(8));
        $st = $this->db->prepare(
            "INSERT INTO users (id, username, email, password_hash, display_name, is_admin)
             VALUES (:id, :username, :email, :password_hash, :display_name, :is_admin)"
        );
        $st->execute([
            ':id'            => $id,
            ':username'      => $data['username'],
            ':email'         => $data['email'],
            ':password_hash' => $data['password_hash'],
            ':display_name'  => $data['display_name'] ?? '',
            ':is_admin'      => $data['is_admin'] ?? 0,
        ]);
        return $id;
    }

    public function updateUser(string $id, array $data): void
    {
        $sets = [];
        $params = [':id' => $id];
        foreach ($data as $col => $val) {
            $sets[] = "{$col} = :{$col}";
            $params[":{$col}"] = $val;
        }
        if (empty($sets)) return;
        $sql = "UPDATE users SET " . implode(', ', $sets) . " WHERE id = :id";
        $this->db->prepare($sql)->execute($params);
    }

    public function listUsers(): array
    {
        return $this->db->query(
            "SELECT id, username, email, display_name, totp_enabled, is_admin, active, created_at
             FROM users ORDER BY created_at"
        )->fetchAll();
    }

    public function userCount(): int
    {
        return (int) $this->db->query("SELECT COUNT(*) FROM users")->fetchColumn();
    }

    // ── Session methods ─────────────────────────────────────────────────────

    public function createSession(string $userId, string $tokenHash, string $ip, string $ua, int $expiresAt): string
    {
        $id = bin2hex(random_bytes(32));
        $now = time();
        $st = $this->db->prepare(
            "INSERT INTO sessions (id, user_id, token_hash, ip_address, user_agent, device_label, created_at, last_active, expires_at)
             VALUES (:id, :user_id, :token_hash, :ip, :ua, :device_label, :created_at, :last_active, :expires_at)"
        );
        $st->execute([
            ':id'           => $id,
            ':user_id'      => $userId,
            ':token_hash'   => $tokenHash,
            ':ip'           => $ip,
            ':ua'           => $ua,
            ':device_label' => self::parseDeviceLabel($ua),
            ':created_at'   => $now,
            ':last_active'  => $now,
            ':expires_at'   => $expiresAt,
        ]);
        return $id;
    }

    public function getSessionByToken(string $tokenHash): ?array
    {
        $st = $this->db->prepare(
            "SELECT s.*, u.username, u.email, u.display_name, u.is_admin, u.active as user_active,
                    u.totp_enabled, u.totp_secret
             FROM sessions s JOIN users u ON s.user_id = u.id
             WHERE s.token_hash = :h AND s.expires_at > :now"
        );
        $st->execute([':h' => $tokenHash, ':now' => time()]);
        return $st->fetch() ?: null;
    }

    public function updateSessionActivity(string $id): void
    {
        $st = $this->db->prepare("UPDATE sessions SET last_active = :now WHERE id = :id");
        $st->execute([':now' => time(), ':id' => $id]);
    }

    public function deleteSession(string $id): void
    {
        $this->db->prepare("DELETE FROM sessions WHERE id = :id")->execute([':id' => $id]);
    }

    public function deleteUserSessions(string $userId, ?string $exceptId = null): int
    {
        if ($exceptId) {
            $st = $this->db->prepare("DELETE FROM sessions WHERE user_id = :uid AND id != :eid");
            $st->execute([':uid' => $userId, ':eid' => $exceptId]);
        } else {
            $st = $this->db->prepare("DELETE FROM sessions WHERE user_id = :uid");
            $st->execute([':uid' => $userId]);
        }
        return $st->rowCount();
    }

    public function getUserSessions(string $userId): array
    {
        $st = $this->db->prepare(
            "SELECT id, ip_address, user_agent, device_label, created_at, last_active, expires_at
             FROM sessions WHERE user_id = :uid AND expires_at > :now ORDER BY last_active DESC"
        );
        $st->execute([':uid' => $userId, ':now' => time()]);
        return $st->fetchAll();
    }

    public function cleanExpiredSessions(): int
    {
        $st = $this->db->prepare("DELETE FROM sessions WHERE expires_at < :now");
        $st->execute([':now' => time()]);
        return $st->rowCount();
    }

    // ── Client app methods ──────────────────────────────────────────────────

    public function getClientApp(string $id): ?array
    {
        $st = $this->db->prepare("SELECT * FROM client_apps WHERE id = :id");
        $st->execute([':id' => $id]);
        return $st->fetch() ?: null;
    }

    public function getClientAppByApiKey(string $apiKeyHash): ?array
    {
        $st = $this->db->prepare("SELECT * FROM client_apps WHERE api_key_hash = :h AND active = 1");
        $st->execute([':h' => $apiKeyHash]);
        return $st->fetch() ?: null;
    }

    public function createClientApp(array $data): void
    {
        $st = $this->db->prepare(
            "INSERT INTO client_apps (id, label, api_key_hash, callback_url, icon_emoji, active)
             VALUES (:id, :label, :api_key_hash, :callback_url, :icon_emoji, :active)"
        );
        $st->execute([
            ':id'           => $data['id'],
            ':label'        => $data['label'],
            ':api_key_hash' => $data['api_key_hash'],
            ':callback_url' => $data['callback_url'] ?? '',
            ':icon_emoji'   => $data['icon_emoji'] ?? '',
            ':active'       => $data['active'] ?? 1,
        ]);
    }

    public function updateClientApp(string $id, array $data): void
    {
        $sets = [];
        $params = [':id' => $id];
        foreach ($data as $col => $val) {
            $sets[] = "{$col} = :{$col}";
            $params[":{$col}"] = $val;
        }
        if (empty($sets)) return;
        $sql = "UPDATE client_apps SET " . implode(', ', $sets) . " WHERE id = :id";
        $this->db->prepare($sql)->execute($params);
    }

    public function deleteClientApp(string $id): void
    {
        $this->db->prepare("DELETE FROM client_apps WHERE id = :id")->execute([':id' => $id]);
    }

    public function listClientApps(): array
    {
        return $this->db->query("SELECT * FROM client_apps ORDER BY created_at")->fetchAll();
    }

    // ── Backup codes ────────────────────────────────────────────────────────

    public function storeBackupCodes(string $userId, array $hashes): void
    {
        // Delete existing codes first
        $this->db->prepare("DELETE FROM totp_backup_codes WHERE user_id = :uid")->execute([':uid' => $userId]);
        $st = $this->db->prepare(
            "INSERT INTO totp_backup_codes (user_id, code_hash) VALUES (:uid, :hash)"
        );
        foreach ($hashes as $hash) {
            $st->execute([':uid' => $userId, ':hash' => $hash]);
        }
    }

    public function verifyBackupCode(string $userId, string $code): bool
    {
        $hash = hash('sha256', $code);
        $st = $this->db->prepare(
            "SELECT id FROM totp_backup_codes WHERE user_id = :uid AND code_hash = :h AND used = 0"
        );
        $st->execute([':uid' => $userId, ':h' => $hash]);
        $row = $st->fetch();
        if (!$row) return false;
        $this->db->prepare("UPDATE totp_backup_codes SET used = 1 WHERE id = :id")
            ->execute([':id' => $row['id']]);
        return true;
    }

    // ── OTP codes ───────────────────────────────────────────────────────────

    public function createOtp(string $email, string $codeHash, string $purpose, ?string $userId = null): string
    {
        $id = bin2hex(random_bytes(16));
        $ttl = $purpose === 'password_reset'
            ? $this->get('reset_ttl', 1800)
            : $this->get('otp_ttl', 600);
        $st = $this->db->prepare(
            "INSERT INTO otp_codes (id, user_id, email, code_hash, purpose, created_at, expires_at)
             VALUES (:id, :uid, :email, :hash, :purpose, :created_at, :expires_at)"
        );
        $st->execute([
            ':id'         => $id,
            ':uid'        => $userId,
            ':email'      => $email,
            ':hash'       => $codeHash,
            ':purpose'    => $purpose,
            ':created_at' => time(),
            ':expires_at' => time() + $ttl,
        ]);
        return $id;
    }

    public function verifyOtp(string $otpId, string $code, string $purpose): ?array
    {
        $st = $this->db->prepare(
            "SELECT * FROM otp_codes WHERE id = :id AND purpose = :p AND used = 0 AND expires_at > :now"
        );
        $st->execute([':id' => $otpId, ':p' => $purpose, ':now' => time()]);
        $row = $st->fetch();
        if (!$row) return null;
        if (!hash_equals($row['code_hash'], hash('sha256', $code))) return null;
        $this->db->prepare("UPDATE otp_codes SET used = 1 WHERE id = :id")->execute([':id' => $otpId]);
        return $row;
    }

    public function cleanExpiredOtps(): int
    {
        $st = $this->db->prepare("DELETE FROM otp_codes WHERE expires_at < :now");
        $st->execute([':now' => time()]);
        return $st->rowCount();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    public static function parseDeviceLabel(string $ua): string
    {
        if (empty($ua)) return 'Unknown';

        $device = 'Unknown';
        if (preg_match('/iPhone/', $ua)) $device = 'iPhone';
        elseif (preg_match('/iPad/', $ua)) $device = 'iPad';
        elseif (preg_match('/Android/', $ua)) $device = 'Android';
        elseif (preg_match('/Windows/', $ua)) $device = 'Windows';
        elseif (preg_match('/Macintosh/', $ua)) $device = 'Mac';
        elseif (preg_match('/Linux/', $ua)) $device = 'Linux';

        $browser = '';
        if (preg_match('/Firefox\/[\d.]+/', $ua)) $browser = 'Firefox';
        elseif (preg_match('/Edg\/[\d.]+/', $ua)) $browser = 'Edge';
        elseif (preg_match('/Chrome\/[\d.]+/', $ua)) $browser = 'Chrome';
        elseif (preg_match('/Safari\/[\d.]+/', $ua) && !preg_match('/Chrome/', $ua)) $browser = 'Safari';

        return $browser ? "{$device} / {$browser}" : $device;
    }
}
