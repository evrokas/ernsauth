<?php

$baseDir = dirname(__DIR__);
require_once $baseDir . '/src/Config.php';
require_once $baseDir . '/src/Auth.php';
require_once $baseDir . '/src/TOTP.php';
require_once $baseDir . '/src/SSO.php';
require_once $baseDir . '/src/RateLimit.php';
require_once $baseDir . '/src/AuditLog.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-cache, no-store');

function jsonOut(array $data): void
{
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function jsonError(string $msg, int $code = 400): void
{
    http_response_code($code);
    jsonOut(['error' => $msg]);
}

try {
    $config = Config::getInstance();
} catch (Exception $e) {
    jsonError('Database unavailable', 500);
}

$action = $_GET['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];

// Parse JSON body for POST
$input = [];
if ($method === 'POST') {
    $raw = file_get_contents('php://input');
    if ($raw) {
        $input = json_decode($raw, true) ?: [];
    }
    if (empty($input)) {
        $input = $_POST;
    }
}

// ── Auth check ────────────────────────────────────────────────────────────

Auth::requireLoginOrJson();

if ($method === 'POST') {
    Auth::verifyCsrfToken();
}

$adminActions = ['get_client_apps', 'save_client_app', 'delete_client_app',
                 'get_users', 'save_user', 'toggle_user', 'audit_log', 'cleanup',
                 'get_rate_limits', 'save_rate_limit', 'reset_rate_limit'];
if (in_array($action, $adminActions) && !Auth::isAdmin()) {
    jsonError('Admin access required', 403);
}

$userId = Auth::getCurrentUserId();
$user = Auth::getCurrentUser();

switch ($action) {

    // ── Pending Logins ────────────────────────────────────────────────────

    case 'pending_logins':
        $challenges = SSO::getPendingChallenges($config);
        $result = [];
        $decoyCount = $config->get('challenge_decoys', 3);
        foreach ($challenges as $ch) {
            $numbers = SSO::generateDecoys((int)$ch['challenge_number'], $decoyCount);
            $result[] = [
                'id'        => $ch['id'],
                'app_label' => $ch['app_label'],
                'app_emoji' => $ch['app_emoji'],
                'client_ip' => $ch['client_ip'],
                'requested_identity' => $ch['requested_identity'],
                'time_ago'  => timeAgo($ch['created_at']),
                'numbers'   => $numbers,
            ];
        }
        jsonOut(['challenges' => $result]);

    case 'approve_login':
        $challengeId = $input['challenge_id'] ?? '';
        $selectedNumber = (int)($input['selected_number'] ?? 0);
        if (empty($challengeId) || $selectedNumber < 10) {
            jsonError('Invalid request');
        }
        $result = SSO::approveChallenge($config, $challengeId, $selectedNumber, $userId);
        if (isset($result['error'])) {
            jsonError($result['error']);
        }
        AuditLog::log($config, 'sso_approve', $userId, ['challenge_id' => $challengeId]);
        jsonOut(['success' => true]);

    case 'reject_login':
        $challengeId = $input['challenge_id'] ?? '';
        if (empty($challengeId)) jsonError('Invalid request');
        SSO::rejectChallenge($config, $challengeId, $userId);
        AuditLog::log($config, 'sso_reject', $userId, ['challenge_id' => $challengeId]);
        jsonOut(['success' => true]);

    // ── Sessions ──────────────────────────────────────────────────────────

    case 'active_sessions':
        $sessions = $config->getUserSessions($userId);
        $currentSessionId = $_SESSION['ea_session_id'] ?? '';
        foreach ($sessions as &$s) {
            $s['is_current'] = ($s['id'] === $currentSessionId);
        }
        unset($s);
        jsonOut(['sessions' => $sessions]);

    case 'revoke_session':
        $sessionId = $input['session_id'] ?? '';
        if (empty($sessionId)) jsonError('Invalid request');
        // Don't allow revoking current session
        if ($sessionId === ($_SESSION['ea_session_id'] ?? '')) {
            jsonError('Cannot revoke current session');
        }
        // Ownership-checked delete -- a bare deleteSession($sessionId) would
        // let any logged-in user delete any OTHER user's session by ID.
        // Session IDs are 256-bit random and not practically guessable, but
        // this shouldn't be the only thing stopping that.
        if (!$config->deleteSessionForUser($sessionId, $userId)) {
            jsonError('Session not found');
        }
        jsonOut(['success' => true]);

    case 'revoke_all_sessions':
        $currentSessionId = $_SESSION['ea_session_id'] ?? '';
        $count = $config->deleteUserSessions($userId, $currentSessionId ?: null);
        jsonOut(['success' => true, 'revoked' => $count]);

    // ── Profile ───────────────────────────────────────────────────────────

    case 'get_profile':
        $fullUser = $config->getUserById($userId);
        jsonOut(['user' => [
            'id'           => $fullUser['id'],
            'username'     => $fullUser['username'],
            'email'        => $fullUser['email'],
            'display_name' => $fullUser['display_name'],
            'totp_enabled' => (bool)$fullUser['totp_enabled'],
        ]]);

    case 'change_password':
        $current  = $input['current'] ?? '';
        $newPass  = $input['new_password'] ?? '';
        $confirm  = $input['confirm'] ?? '';

        if (empty($current) || empty($newPass) || empty($confirm)) {
            jsonError('All fields are required');
        }
        if ($newPass !== $confirm) {
            jsonError('Passwords do not match');
        }
        if (strlen($newPass) < 12) {
            jsonError('Password must be at least 12 characters');
        }

        $fullUser = $config->getUserById($userId);
        if (!password_verify($current, $fullUser['password_hash'])) {
            jsonError('Current password is incorrect');
        }

        $config->updateUser($userId, [
            'password_hash' => password_hash($newPass, PASSWORD_DEFAULT),
        ]);
        // Log out every other session -- the one making this request stays
        // logged in (the user just proved they know the current password),
        // but a password change should not leave a stolen session anywhere
        // else still valid.
        $config->deleteUserSessions($userId, $_SESSION['ea_session_id'] ?? null);
        AuditLog::log($config, 'password_change', $userId);
        jsonOut(['success' => true]);

    // ── TOTP ──────────────────────────────────────────────────────────────

    case 'setup_totp':
        $secret = TOTP::generateSecret();
        $fullUser = $config->getUserById($userId);
        $uri = TOTP::getProvisioningUri($secret, $fullUser['username']);
        $backup = TOTP::generateBackupCodes();

        // Store secret (not yet enabled)
        $config->updateUser($userId, ['totp_secret' => $secret]);
        $config->storeBackupCodes($userId, $backup['hashes']);

        jsonOut([
            'secret'           => $secret,
            'provisioning_uri' => $uri,
            'backup_codes'     => $backup['plaintexts'],
        ]);

    case 'confirm_totp':
        $code = $input['code'] ?? '';
        if (strlen($code) !== 6 || !ctype_digit($code)) {
            jsonError('Enter a valid 6-digit code');
        }
        $fullUser = $config->getUserById($userId);
        if (empty($fullUser['totp_secret'])) {
            jsonError('Run setup first');
        }
        if (!TOTP::verify($fullUser['totp_secret'], $code)) {
            jsonError('Invalid code. Make sure your authenticator is synced.');
        }
        $config->updateUser($userId, ['totp_enabled' => 1]);
        $_SESSION['ea_user']['totp_enabled'] = 1;
        AuditLog::log($config, 'totp_enable', $userId);
        jsonOut(['success' => true]);

    case 'disable_totp':
        $password = $input['password'] ?? '';
        $fullUser = $config->getUserById($userId);
        if (!password_verify($password, $fullUser['password_hash'])) {
            jsonError('Incorrect password');
        }
        $config->updateUser($userId, ['totp_enabled' => 0, 'totp_secret' => null]);
        $_SESSION['ea_user']['totp_enabled'] = 0;
        AuditLog::log($config, 'totp_disable', $userId);
        jsonOut(['success' => true]);

    // ── Admin: Client Apps ────────────────────────────────────────────────

    case 'get_client_apps':
        jsonOut(['apps' => $config->listClientApps()]);

    case 'save_client_app':
        $appId = trim($input['id'] ?? '');
        $label = trim($input['label'] ?? '');
        $callbackUrl = trim($input['callback_url'] ?? '');
        $iconEmoji = trim($input['icon_emoji'] ?? '');

        if (empty($appId) || empty($label)) {
            jsonError('ID and label are required');
        }
        if (!preg_match('/^[a-z0-9_-]+$/', $appId)) {
            jsonError('ID must be lowercase alphanumeric with hyphens/underscores');
        }

        $existing = $config->getClientApp($appId);
        if ($existing) {
            $config->updateClientApp($appId, [
                'label'        => $label,
                'callback_url' => $callbackUrl,
                'icon_emoji'   => $iconEmoji,
            ]);
            // Regenerate key if requested
            if (!empty($input['regenerate_key'])) {
                $apiKey = bin2hex(random_bytes(32));
                $config->updateClientApp($appId, ['api_key_hash' => hash('sha256', $apiKey)]);
                AuditLog::log($config, 'app_key_regenerated', $userId, ['app_id' => $appId]);
                jsonOut(['success' => true, 'api_key' => $apiKey]);
            }
            jsonOut(['success' => true]);
        } else {
            $apiKey = bin2hex(random_bytes(32));
            $config->createClientApp([
                'id'           => $appId,
                'label'        => $label,
                'api_key_hash' => hash('sha256', $apiKey),
                'callback_url' => $callbackUrl,
                'icon_emoji'   => $iconEmoji,
            ]);
            AuditLog::log($config, 'app_created', $userId, ['app_id' => $appId]);
            jsonOut(['success' => true, 'api_key' => $apiKey]);
        }

    case 'delete_client_app':
        $appId = $input['id'] ?? '';
        if (empty($appId)) jsonError('ID required');
        $config->deleteClientApp($appId);
        AuditLog::log($config, 'app_deleted', $userId, ['app_id' => $appId]);
        jsonOut(['success' => true]);

    // ── Admin: Rate limits (throttles on client-facing requests) ──────────

    case 'get_rate_limits':
        $limits = [];
        foreach (Config::RATE_LIMIT_KEYS as $key => $meta) {
            [$maxAttempts, $windowSeconds] = $config->getRateLimit($key);
            $limits[] = [
                'key'             => $key,
                'label'           => $meta['label'],
                'max_attempts'    => $maxAttempts,
                'window_seconds'  => $windowSeconds,
                'default'         => $meta['default'],
                'is_customized'   => $config->hasRateLimitOverride($key),
            ];
        }
        jsonOut(['limits' => $limits]);

    case 'save_rate_limit':
        $key = $input['key'] ?? '';
        $maxAttempts = (int)($input['max_attempts'] ?? 0);
        $windowSeconds = (int)($input['window_seconds'] ?? 0);

        if (!array_key_exists($key, Config::RATE_LIMIT_KEYS)) {
            jsonError('Unknown rate limit key');
        }
        // Same floor as Config::setRateLimit()'s own guard, checked here
        // too so the error message is specific rather than a generic 500
        // from the thrown InvalidArgumentException.
        if ($maxAttempts < 1 || $maxAttempts > 100000 || $windowSeconds < 1 || $windowSeconds > 604800) {
            jsonError('Max attempts must be 1-100000 and window 1 second-7 days');
        }

        $config->setRateLimit($key, $maxAttempts, $windowSeconds);
        AuditLog::log($config, 'rate_limit_changed', $userId, [
            'key' => $key, 'max_attempts' => $maxAttempts, 'window_seconds' => $windowSeconds,
        ]);
        jsonOut(['success' => true]);

    case 'reset_rate_limit':
        $key = $input['key'] ?? '';
        if (!array_key_exists($key, Config::RATE_LIMIT_KEYS)) {
            jsonError('Unknown rate limit key');
        }
        $config->resetRateLimit($key);
        AuditLog::log($config, 'rate_limit_reset', $userId, ['key' => $key]);
        jsonOut(['success' => true]);

    // ── Admin: Users ──────────────────────────────────────────────────────

    case 'get_users':
        jsonOut(['users' => $config->listUsers()]);

    case 'save_user':
        $uid       = $input['id'] ?? '';
        $username  = trim($input['username'] ?? '');
        $email     = trim($input['email'] ?? '');
        $displayName = trim($input['display_name'] ?? '');
        $password  = $input['password'] ?? '';
        $isAdmin   = (int)($input['is_admin'] ?? 0);

        if (empty($username) || empty($email)) {
            jsonError('Username and email are required');
        }

        if ($uid) {
            // Update
            $updates = [
                'username'     => $username,
                'email'        => $email,
                'display_name' => $displayName,
                'is_admin'     => $isAdmin,
            ];
            if (!empty($password)) {
                if (strlen($password) < 12) jsonError('Password must be at least 12 characters');
                $updates['password_hash'] = password_hash($password, PASSWORD_DEFAULT);
            }
            $config->updateUser($uid, $updates);
            // An admin resetting someone else's password is exactly the
            // "I think this account is compromised" case a session wipe is
            // for -- there's no session of the admin's own to preserve here.
            if (!empty($password)) {
                $config->deleteUserSessions($uid);
            }
            jsonOut(['success' => true, 'user_id' => $uid]);
        } else {
            // Create
            if (empty($password) || strlen($password) < 12) {
                jsonError('Password must be at least 12 characters');
            }
            $newId = $config->createUser([
                'username'      => $username,
                'email'         => $email,
                'password_hash' => password_hash($password, PASSWORD_DEFAULT),
                'display_name'  => $displayName,
                'is_admin'      => $isAdmin,
            ]);
            AuditLog::log($config, 'user_created', $userId, ['new_user_id' => $newId]);
            jsonOut(['success' => true, 'user_id' => $newId]);
        }

    case 'toggle_user':
        $uid    = $input['id'] ?? '';
        $active = (int)($input['active'] ?? 0);
        if (empty($uid)) jsonError('User ID required');
        if ($uid === $userId) jsonError('Cannot deactivate yourself');
        $config->updateUser($uid, ['active' => $active]);
        jsonOut(['success' => true]);

    // ── Admin: Audit Log ──────────────────────────────────────────────────

    case 'audit_log':
        $filters = [];
        if (!empty($_GET['user_id'])) $filters['user_id'] = $_GET['user_id'];
        if (!empty($_GET['action_filter'])) $filters['action'] = $_GET['action_filter'];
        $limit  = min((int)($_GET['limit'] ?? 50), 200);
        $offset = max((int)($_GET['offset'] ?? 0), 0);
        jsonOut(AuditLog::query($config, $filters, $limit, $offset));

    // ── Admin: Cleanup ────────────────────────────────────────────────────

    case 'cleanup':
        $sessions   = $config->cleanExpiredSessions();
        $challenges = SSO::cleanExpired($config);
        $otps       = $config->cleanExpiredOtps();
        $rates      = RateLimit::cleanup($config);
        jsonOut([
            'expired_sessions'   => $sessions,
            'expired_challenges' => $challenges,
            'expired_otps'       => $otps,
            'expired_rates'      => $rates,
        ]);

    default:
        jsonError('Unknown action', 404);
}

// ── Helpers ───────────────────────────────────────────────────────────────

function timeAgo(int $timestamp): string
{
    $diff = time() - $timestamp;
    if ($diff < 60) return 'just now';
    if ($diff < 3600) return (int)($diff / 60) . ' min ago';
    if ($diff < 86400) return (int)($diff / 3600) . ' hours ago';
    return (int)($diff / 86400) . ' days ago';
}
