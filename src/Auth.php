<?php

require_once __DIR__ . '/AuditLog.php';

class Auth
{
    private static bool $started = false;

    // How long a live (non-"remember me") PHP session tolerates zero
    // requests before it's treated as abandoned and torn down. This limits
    // the window a stolen PHPSESSID cookie value stays usable, and stops a
    // browser tab left open and unattended from staying silently
    // authenticated indefinitely -- see checkSessionFreshness() below.
    // Deliberately does NOT touch the separate "remember me" persistent
    // cookie/DB session, which has its own, much longer session_ttl by
    // design (that's the whole point of "remember me") -- on a device
    // where that matters, don't check the box.
    private const IDLE_TIMEOUT_SECONDS = 1800; // 30 minutes

    public static function startSession(): void
    {
        if (!self::$started && session_status() === PHP_SESSION_NONE) {
            $config = Config::getInstance();

            // Belt-and-suspenders beyond session_set_cookie_params() below:
            // use_strict_mode rejects any session ID the client supplies
            // that this server never generated (blocks classic session
            // fixation -- an attacker priming a victim's cookie with a
            // known ID before they log in); use_only_cookies stops a
            // session ID from ever being accepted via the URL/GET, where it
            // could leak through Referer headers, browser history, or
            // server access logs. Both must be set before session_start().
            ini_set('session.use_strict_mode', '1');
            ini_set('session.use_only_cookies', '1');

            session_set_cookie_params([
                'lifetime' => 0,
                'path'     => $config->get('cookie_path', '/'),
                'secure'   => self::isSecure(),
                'httponly'  => true,
                'samesite'  => 'Strict',
            ]);
            session_start();
            self::$started = true;

            self::sendSecurityHeaders();
        }
    }

    // Sent on every request that touches a session -- i.e. effectively
    // every page in this app, since startSession() is the one choke point
    // every entry script (login.php, index.php, and every requireLogin()/
    // requireLoginOrJson()/requireAdmin() caller) passes through. Not
    // .htaccess-only: this app is also expected to run behind PHP's own
    // built-in server in dev, which never reads .htaccess, and a
    // PHP-level header is the one thing that reliably applies regardless
    // of which server ends up in front of it.
    private static function sendSecurityHeaders(): void
    {
        if (headers_sent()) {
            return;
        }
        // HSTS only makes sense once we know this request actually arrived
        // over HTTPS -- sending it over plain HTTP would be a lie the
        // browser can't act on, and could be misleading during local
        // HTTP-only development.
        if (self::isSecure()) {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }
        header('X-Content-Type-Options: nosniff');
        // This app has no legitimate reason to ever be framed by another
        // site -- an auth gateway is exactly the kind of page clickjacking
        // targets (tricking a logged-in user into clicking an invisible
        // "approve" button).
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: same-origin');
    }

    public static function requireLogin(): void
    {
        self::startSession();

        if (!empty($_SESSION['ea_authed']) && self::checkSessionFreshness()) {
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

        if (!empty($_SESSION['ea_authed']) && self::checkSessionFreshness()) {
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

    public static function login(Config $config, array $user, bool $remember = false): void
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

        // Bound at the moment of login, checked on every later request by
        // checkSessionFreshness() -- see that method's docblock. Neither
        // value is secret, so stored as plain strings, not hashed.
        $_SESSION['ea_last_activity'] = time();
        $_SESSION['ea_bound_ua'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $_SESSION['ea_bound_ip'] = $_SERVER['REMOTE_ADDR'] ?? '';

        // Without "remember me", the PHP session above is the whole story:
        // its cookie has lifetime=0 (browser-session only, see startSession()),
        // so closing the browser ends the login. No DB session row and no
        // ea_session cookie means checkCookie() has nothing to revive later.
        if (!$remember) {
            return;
        }

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
            $expiresAt,
            $_SESSION['csrf_token']
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

        self::destroySession();
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

        // A "remember me" cookie is the highest-value hijack target in this
        // app -- it's valid for session_ttl (30 days by default), far
        // longer than a live PHP session. If the browser presenting it
        // doesn't match the one that created it, treat the cookie as
        // invalid rather than silently trusting it: refuse to revive this
        // session, and let the caller fall through to a real login. A
        // browser's own User-Agent string does not change between one
        // request and the next on its own -- a mismatch here means this
        // token is being replayed from a different browser/device than the
        // one it was issued to.
        $currentUa = $_SERVER['HTTP_USER_AGENT'] ?? '';
        if ($currentUa !== ($session['user_agent'] ?? '')) {
            self::logSecurityEvent('session_ua_mismatch', $session['user_id'] ?? null);
            return false;
        }

        // IP, unlike User-Agent, changes for entirely legitimate reasons
        // (mobile network handoff, Wi-Fi to cellular, a rotating NAT pool)
        // over a cookie that can live for weeks -- logged as a signal for
        // review, never blocking on it alone.
        $currentIp = $_SERVER['REMOTE_ADDR'] ?? '';
        if ($currentIp !== ($session['ip_address'] ?? '')) {
            self::logSecurityEvent('session_ip_changed_on_revival', $session['user_id'] ?? null);
        }

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

        // Restore this persistent session's own CSRF token rather than
        // leaving $_SESSION['csrf_token'] empty for ensureCsrf() to mint a
        // fresh random one -- that used to happen on *every* revival
        // (PHP's own session data can be lost between requests for
        // ordinary reasons: gc_maxlifetime expiry, a backgrounded tab
        // resuming, multiple app servers without shared session storage),
        // which silently invalidated the CSRF token any already-open page
        // still had embedded -- clicking a button on that page (e.g.
        // approving a pending SSO login) then 403'd with no clear signal
        // why, "fixed" only by a full logout/login that re-rendered the
        // page with a fresh, matching token. A row from before this
        // column existed has none yet -- generate one now and persist it
        // so this exact row is stable on every later revival too.
        $csrfToken = $session['csrf_token'] ?? '';
        if ($csrfToken === '') {
            $csrfToken = bin2hex(random_bytes(32));
            $config->updateSessionCsrfToken($session['id'], $csrfToken);
        }
        $_SESSION['csrf_token'] = $csrfToken;

        // Same freshness-tracking keys login() sets, so checkSessionFreshness()
        // behaves identically regardless of which path established this
        // live PHP session.
        $_SESSION['ea_last_activity'] = time();
        $_SESSION['ea_bound_ua'] = $currentUa;
        $_SESSION['ea_bound_ip'] = $currentIp;

        // Update last active
        $config->updateSessionActivity($session['id']);
        // Store session DB id for revocation
        $_SESSION['ea_session_id'] = $session['id'];

        return true;
    }

    // Checked on every request for an already-live PHP session (i.e. one
    // that didn't just come through checkCookie()'s own, separate checks
    // above) -- three independent things:
    //   1. Idle timeout: a session with no activity in IDLE_TIMEOUT_SECONDS
    //      is torn down outright, whether or not the underlying cookie is
    //      technically still valid. Note this does NOT invalidate a
    //      "remember me" persistent cookie/DB session if one exists --
    //      the very next request would just silently revive a fresh PHP
    //      session via checkCookie(). Real protection against an
    //      unattended, unlocked device with "remember me" checked would
    //      need re-authentication (password/TOTP) on revival, which this
    //      does not add -- don't check "remember me" on a shared device.
    //   2. User-Agent binding (hard): identical reasoning to checkCookie()'s
    //      own check -- a real browser's UA cannot change mid-session, so a
    //      mismatch means this session's cookie is being used from a
    //      different browser/device than the one that logged in.
    //   3. IP binding (soft): logged only, never blocking -- see
    //      checkCookie()'s own comment on why.
    private static function checkSessionFreshness(): bool
    {
        $now = time();
        $lastActivity = $_SESSION['ea_last_activity'] ?? $now;
        if (($now - $lastActivity) > self::IDLE_TIMEOUT_SECONDS) {
            self::destroySession();
            return false;
        }

        $currentUa = $_SERVER['HTTP_USER_AGENT'] ?? '';
        if (($_SESSION['ea_bound_ua'] ?? null) !== $currentUa) {
            self::logSecurityEvent('session_hijack_suspected', $_SESSION['ea_user_id'] ?? null);
            self::destroySession();
            return false;
        }

        $currentIp = $_SERVER['REMOTE_ADDR'] ?? '';
        if (($_SESSION['ea_bound_ip'] ?? null) !== $currentIp) {
            self::logSecurityEvent('session_ip_changed', $_SESSION['ea_user_id'] ?? null);
            // Update, not re-log on every subsequent request from the same
            // (now legitimate-looking) new IP -- only the transition itself
            // is the useful signal.
            $_SESSION['ea_bound_ip'] = $currentIp;
        }

        $_SESSION['ea_last_activity'] = $now;
        return true;
    }

    // AuditLog itself never throws for a normal insert, but Config::getInstance()
    // can (no DB reachable) -- a logging failure must never be the reason a
    // security check itself doesn't take effect, so this only ever affects
    // whether the event got recorded, never the caller's control flow.
    private static function logSecurityEvent(string $event, ?string $userId): void
    {
        try {
            AuditLog::log(Config::getInstance(), $event, $userId);
        } catch (Exception $e) {
            error_log('ernsauth ' . $event . ' (audit log failed: ' . $e->getMessage() . ')');
        }
    }

    private static function destroySession(): void
    {
        $_SESSION = [];
        session_destroy();
        self::$started = false;
    }
}
