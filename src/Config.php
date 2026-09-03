<?php

class Config
{
    private static ?Config $instance = null;
    private PDO $db;
    private array $deployConfig;

    // Every throttle applied to a client-facing request, in one place: what
    // RateLimit::attempt() is called with, [max attempts, window seconds].
    // This is the allowlist for getRateLimit()/setRateLimit() -- an admin
    // can retune any of these live (see the dashboard's Admin > Rate Limits
    // tab), but can't invent a new, unvetted key through that API. Label is
    // shown there; default is what applies until a row exists in `settings`
    // for it (config/settings.php's rate_* values are the old, deploy-only
    // way to set these and still work as the fallback beneath that).
    public const RATE_LIMIT_KEYS = [
        'rate_login'      => ['label' => 'Password login attempts',        'default' => [5, 900]],
        'rate_totp'       => ['label' => 'TOTP code verification',        'default' => [5, 900]],
        'rate_otp_send'   => ['label' => 'Email OTP send requests',       'default' => [3, 900]],
        'rate_otp_verify' => ['label' => 'Email OTP / reset-code verification', 'default' => [5, 900]],
        'rate_challenge'  => ['label' => 'SSO challenge create (client apps)', 'default' => [30, 300]],
        'rate_reset'      => ['label' => 'Password reset requests',       'default' => [3, 3600]],
        'rate_exchange'   => ['label' => 'SSO auth code exchange (client apps)', 'default' => [20, 300]],
    ];

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

    public function deleteSetting(string $key): void
    {
        $this->db->prepare("DELETE FROM settings WHERE setting_key = :k")->execute([':k' => $key]);
    }

    // ── Rate limits (customizable throttles) ──────────────────────────────
    //
    // [max attempts, window seconds], same shape RateLimit::attempt() takes.
    // An admin-set value lives in the `settings` table under "rate_limit:
    // {$key}" as JSON (e.g. "[30,300]"); getRateLimit() prefers that, then
    // falls back to config/settings.php's own rate_* entry (the pre-existing,
    // deploy-only way to set these), then to the hardcoded default in
    // RATE_LIMIT_KEYS. $key must be one of RATE_LIMIT_KEYS -- callers pass a
    // literal, not user input, so an unknown key is a programming error, not
    // something to degrade gracefully for.

    public function getRateLimit(string $key): array
    {
        if (!isset(self::RATE_LIMIT_KEYS[$key])) {
            throw new InvalidArgumentException("Unknown rate limit key: {$key}");
        }

        $stored = $this->getSetting("rate_limit:{$key}");
        if ($stored !== null) {
            $decoded = json_decode($stored, true);
            if (is_array($decoded) && count($decoded) === 2
                && is_int($decoded[0]) && $decoded[0] > 0
                && is_int($decoded[1]) && $decoded[1] > 0) {
                return $decoded;
            }
            // A malformed/tampered row shouldn't take the throttle out
            // entirely -- fall through to the deploy-file/hardcoded default
            // exactly as if no override existed.
        }

        return $this->get($key, self::RATE_LIMIT_KEYS[$key]['default']);
    }

    public function setRateLimit(string $key, int $maxAttempts, int $windowSeconds): void
    {
        if (!isset(self::RATE_LIMIT_KEYS[$key])) {
            throw new InvalidArgumentException("Unknown rate limit key: {$key}");
        }
        if ($maxAttempts < 1 || $windowSeconds < 1) {
            throw new InvalidArgumentException('Max attempts and window must be positive integers');
        }
        $this->setSetting("rate_limit:{$key}", json_encode([$maxAttempts, $windowSeconds]));
    }

    // Whether getRateLimit($key) is currently returning an admin override
    // rather than the deploy-file/hardcoded default -- purely for the
    // dashboard to show "customized" vs "default" next to each row.
    public function hasRateLimitOverride(string $key): bool
    {
        return $this->getSetting("rate_limit:{$key}") !== null;
    }

    public function resetRateLimit(string $key): void
    {
        if (!isset(self::RATE_LIMIT_KEYS[$key])) {
            throw new InvalidArgumentException("Unknown rate limit key: {$key}");
        }
        $this->deleteSetting("rate_limit:{$key}");
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

    // $csrfToken is stored alongside the session so a later checkCookie()
    // revival of this same row (see Auth::checkCookie()) can restore the
    // exact CSRF token already embedded in any page rendered from the
    // PHP session this persistent one is backing, instead of minting a
    // fresh random one every time PHP's own session data is lost and has
    // to be rebuilt from this cookie -- see Auth.php's own docblock on
    // checkCookie() for the bug this fixes.
    public function createSession(string $userId, string $tokenHash, string $ip, string $ua, int $expiresAt, string $csrfToken): string
    {
        $id = bin2hex(random_bytes(32));
        $now = time();
        $st = $this->db->prepare(
            "INSERT INTO sessions (id, user_id, token_hash, ip_address, user_agent, device_label, csrf_token, created_at, last_active, expires_at)
             VALUES (:id, :user_id, :token_hash, :ip, :ua, :device_label, :csrf_token, :created_at, :last_active, :expires_at)"
        );
        $st->execute([
            ':id'           => $id,
            ':user_id'      => $userId,
            ':token_hash'   => $tokenHash,
            ':ip'           => $ip,
            ':ua'           => $ua,
            ':device_label' => self::parseDeviceLabel($ua),
            ':csrf_token'   => $csrfToken,
            ':created_at'   => $now,
            ':last_active'  => $now,
            ':expires_at'   => $expiresAt,
        ]);
        return $id;
    }

    // Backfills csrf_token for a session row created before this column
    // existed (NULL) or one that somehow still has none -- see
    // Auth::checkCookie(), which calls this on exactly that case so the
    // row is stable (not regenerated again) on every later revival.
    public function updateSessionCsrfToken(string $id, string $csrfToken): void
    {
        $st = $this->db->prepare("UPDATE sessions SET csrf_token = :t WHERE id = :id");
        $st->execute([':t' => $csrfToken, ':id' => $id]);
    }

    // "Remember me" token rotation -- see Auth::checkCookie(). The UPDATE
    // is conditioned on the token_hash still being $oldTokenHash (the same
    // conditional-UPDATE-plus-rowCount() pattern already used for
    // exchange_code's one-time auth_code in SSO.php::exchangeCode()) so a
    // token can only ever be rotated once: if two requests somehow present
    // the same not-yet-rotated cookie concurrently, exactly one wins this
    // UPDATE and gets the new token; the other's rowCount() comes back 0,
    // which Auth::checkCookie() treats as an invalid/already-used token
    // rather than silently handing out a second valid rotation. Returns
    // whether the rotation actually took effect.
    public function rotateSessionToken(string $id, string $oldTokenHash, string $newTokenHash): bool
    {
        $st = $this->db->prepare(
            "UPDATE sessions SET token_hash = :new WHERE id = :id AND token_hash = :old"
        );
        $st->execute([':new' => $newTokenHash, ':id' => $id, ':old' => $oldTokenHash]);
        return $st->rowCount() > 0;
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

    /**
     * Same as deleteSession(), but only when the session actually belongs
     * to $userId. Use this for any deletion driven by a session ID the
     * caller supplied (e.g. the "revoke a device" button) rather than one
     * this app itself looked up from the caller's own cookie -- session
     * IDs are 256-bit random and not practically guessable, but the code
     * shouldn't rely on that alone as the only thing stopping one logged-in
     * user from deleting another user's session. Returns whether a row was
     * actually deleted, so the caller can tell "not yours" from "not found"
     * without the two being distinguishable to the client either way.
     */
    public function deleteSessionForUser(string $id, string $userId): bool
    {
        $st = $this->db->prepare("DELETE FROM sessions WHERE id = :id AND user_id = :uid");
        $st->execute([':id' => $id, ':uid' => $userId]);
        return $st->rowCount() > 0;
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
