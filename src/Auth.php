<?php

class Auth
{
    private static bool $started = false;

    public static function startSession(): void
    {
        if (!self::$started && session_status() === PHP_SESSION_NONE) {
            $config = Config::getInstance();
            session_set_cookie_params([
                'lifetime' => 0,
                'path'     => $config->get('cookie_path', '/'),
                'secure'   => self::isSecure(),
                'httponly'  => true,
                'samesite'  => 'Strict',
            ]);
            session_start();
            self::$started = true;
        }
    }

    public static function requireLogin(): void
    {
        self::startSession();

        if (!empty($_SESSION['ea_authed'])) {
            self::ensureCsrf();
            return;
        }

        if (self::checkCookie()) {
            self::ensureCsrf();
            return;
        }

        header('Location: login.php');
        exit;
    }

    public static function requireLoginOrJson(): void
    {
        self::startSession();

        if (!empty($_SESSION['ea_authed'])) {
            self::ensureCsrf();
            return;
        }

        if (self::checkCookie()) {
            self::ensureCsrf();
            return;
        }

        http_response_code(401);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'Not authenticated', 'login_url' => 'login.php']);
        exit;
    }

    public static function requireAdmin(): void
    {
        self::requireLoginOrJson();
        if (!self::isAdmin()) {
            http_response_code(403);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['error' => 'Admin access required']);
            exit;
        }
    }

    public static function login(Config $config, array $user): void
    {
        session_regenerate_id(true);

        $_SESSION['ea_user_id'] = $user['id'];
        $_SESSION['ea_user'] = [
            'id'           => $user['id'],
            'username'     => $user['username'],
            'email'        => $user['email'],
            'display_name' => $user['display_name'],
            'is_admin'     => (int)$user['is_admin'],
            'totp_enabled' => (int)$user['totp_enabled'],
        ];
        $_SESSION['ea_authed'] = true;
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

        // Create persistent session with cookie
        $token = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $token);
        $ttl = $config->get('session_ttl', 2592000);
        $expiresAt = time() + $ttl;

        $sessionId = $config->createSession(
            $user['id'],
            $tokenHash,
            $_SERVER['REMOTE_ADDR'] ?? '',
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            $expiresAt
        );
        $_SESSION['ea_session_id'] = $sessionId;

        setcookie($config->get('cookie_name', 'ea_session'), $token, [
            'expires'  => $expiresAt,
            'path'     => $config->get('cookie_path', '/'),
            'secure'   => self::isSecure(),
            'httponly'  => true,
            'samesite'  => 'Strict',
        ]);
    }

    public static function logout(Config $config): void
    {
        self::startSession();

        // Delete DB session via cookie token
        $cookieName = $config->get('cookie_name', 'ea_session');
        $token = $_COOKIE[$cookieName] ?? '';
        if ($token !== '') {
            $tokenHash = hash('sha256', $token);
            $session = $config->getSessionByToken($tokenHash);
            if ($session) {
                $config->deleteSession($session['id']);
            }
        }

        // Clear cookie
        setcookie($cookieName, '', [
            'expires'  => time() - 3600,
            'path'     => $config->get('cookie_path', '/'),
            'secure'   => self::isSecure(),
            'httponly'  => true,
            'samesite'  => 'Strict',
        ]);

        $_SESSION = [];
        session_destroy();
        self::$started = false;
    }

    public static function getCurrentUser(): ?array
    {
        return $_SESSION['ea_user'] ?? null;
    }

    public static function getCurrentUserId(): ?string
    {
        return $_SESSION['ea_user_id'] ?? null;
    }

    public static function isAdmin(): bool
    {
        return !empty($_SESSION['ea_user']['is_admin']);
    }

    public static function getCsrfToken(): string
    {
        return $_SESSION['csrf_token'] ?? '';
    }

    public static function verifyCsrfToken(): void
    {
        $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!hash_equals($_SESSION['csrf_token'] ?? '', $token)) {
            http_response_code(403);
            echo json_encode(['error' => 'CSRF token invalid']);
            exit;
        }
    }

    public static function isSecure(): bool
    {
        if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
            return true;
        }
        return ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
    }

    private static function ensureCsrf(): void
    {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
    }

    private static function checkCookie(): bool
    {
        try {
            $config = Config::getInstance();
        } catch (Exception $e) {
            return false;
        }

        $cookieName = $config->get('cookie_name', 'ea_session');
        $token = $_COOKIE[$cookieName] ?? '';
        if ($token === '') return false;

        $tokenHash = hash('sha256', $token);
        $session = $config->getSessionByToken($tokenHash);
        if (!$session) return false;

        // Check user is still active
        if (empty($session['user_active'])) return false;

        // Hydrate session
        session_regenerate_id(true);
        $_SESSION['ea_user_id'] = $session['user_id'];
        $_SESSION['ea_user'] = [
            'id'           => $session['user_id'],
            'username'     => $session['username'],
            'email'        => $session['email'],
            'display_name' => $session['display_name'],
            'is_admin'     => (int)$session['is_admin'],
            'totp_enabled' => (int)$session['totp_enabled'],
        ];
        $_SESSION['ea_authed'] = true;

        // Update last active
        $config->updateSessionActivity($session['id']);
        // Store session DB id for revocation
        $_SESSION['ea_session_id'] = $session['id'];

        return true;
    }
}
