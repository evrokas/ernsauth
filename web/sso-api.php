<?php

$baseDir = dirname(__DIR__);
require_once $baseDir . '/src/Config.php';
require_once $baseDir . '/src/SSO.php';
require_once $baseDir . '/src/RateLimit.php';
require_once $baseDir . '/src/AuditLog.php';
require_once $baseDir . '/src/Mailer.php';

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
    jsonError('Service unavailable', 503);
}

$action = $_GET['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

// Parse JSON body
$input = [];
if ($method === 'POST') {
    $raw = file_get_contents('php://input');
    if ($raw) $input = json_decode($raw, true) ?: [];
    if (empty($input)) $input = $_POST;
}

// ── Authenticate API key ──────────────────────────────────────────────────

$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? '';
if (empty($apiKey)) {
    jsonError('Missing X-API-Key header', 401);
}

$apiKeyHash = hash('sha256', $apiKey);
$clientApp = $config->getClientAppByApiKey($apiKeyHash);
if (!$clientApp) {
    jsonError('Invalid API key', 401);
}

$appId = $clientApp['id'];

// ── Actions ───────────────────────────────────────────────────────────────

switch ($action) {

    case 'create_challenge':
        if ($method !== 'POST') jsonError('POST required', 405);

        // Rate limit
        $rateKey = "challenge:{$appId}:{$ip}";
        $rateConfig = $config->getRateLimit('rate_challenge');
        // attempt() records this attempt and reports whether it's
        // still within budget in one atomic step -- see RateLimit::attempt().
        if (!RateLimit::attempt($config, $rateKey, $rateConfig[0], $rateConfig[1])) {
            jsonError('Rate limited. Try again later.', 429);
        }

        $clientIp = $input['client_ip'] ?? $ip;
        $clientUa = $input['client_user_agent'] ?? '';
        // Display-only -- see SSO::createChallenge()'s own docblock. Never
        // used here, or anywhere else in this file, for any decision.
        $requestedIdentity = (string)($input['requested_identity'] ?? '');

        $result = SSO::createChallenge($config, $appId, $clientIp, $clientUa, $requestedIdentity);
        AuditLog::log($config, 'sso_challenge_created', null, [
            'app_id' => $appId, 'challenge_id' => $result['challenge_id']
        ]);
        if ($result['superseded_count'] > 0) {
            AuditLog::log($config, 'sso_challenge_superseded', null, [
                'app_id' => $appId, 'challenge_id' => $result['challenge_id'],
                'superseded_count' => $result['superseded_count'],
            ]);
        }
        jsonOut($result);

    case 'poll_challenge':
        if ($method !== 'GET') jsonError('GET required', 405);

        $challengeId = $_GET['challenge_id'] ?? '';
        if (empty($challengeId)) jsonError('challenge_id required');

        // Rate limit polling
        $rateKey = "poll:{$ip}";
        $rateConfig = $config->getRateLimit('rate_challenge');
        // attempt() records this attempt and reports whether it's
        // still within budget in one atomic step -- see RateLimit::attempt().
        if (!RateLimit::attempt($config, $rateKey, $rateConfig[0] * 10, $rateConfig[1])) {
            jsonError('Rate limited', 429);
        }

        $result = SSO::pollChallenge($config, $challengeId, $appId);
        jsonOut($result);

    case 'exchange_code':
        if ($method !== 'POST') jsonError('POST required', 405);

        $authCode = $input['auth_code'] ?? '';
        if (empty($authCode)) jsonError('auth_code required');

        // Rate limit -- this was the one client-facing SSO action with no
        // throttle at all. The code itself is 128-bit random and single-use
        // (see SSO::exchangeCode()'s own row-locked nullify), so guessing it
        // is impractical regardless; this is defense in depth, not the only
        // thing standing in the way.
        $rateKey = "exchange:{$appId}:{$ip}";
        $rateConfig = $config->getRateLimit('rate_exchange');
        if (!RateLimit::attempt($config, $rateKey, $rateConfig[0], $rateConfig[1])) {
            jsonError('Rate limited. Try again later.', 429);
        }

        $result = SSO::exchangeCode($config, $authCode, $appId);
        if (isset($result['error'])) {
            jsonError($result['error']);
        }

        AuditLog::log($config, 'sso_exchange', $result['user_id'] ?? null, ['app_id' => $appId]);
        jsonOut($result);

    case 'send_otp':
        if ($method !== 'POST') jsonError('POST required', 405);

        $email = trim($input['email'] ?? '');
        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            jsonError('Valid email required');
        }

        // Rate limit
        $rateKey = "otp_send:{$ip}";
        $rateConfig = $config->getRateLimit('rate_otp_send');
        // attempt() records this attempt and reports whether it's
        // still within budget in one atomic step -- see RateLimit::attempt().
        if (!RateLimit::attempt($config, $rateKey, $rateConfig[0], $rateConfig[1])) {
            jsonError('Too many OTP requests. Try again later.', 429);
        }

        $user = $config->getUserByEmail($email);
        if (!$user || !$user['active']) {
            // Don't reveal whether email exists, but still return otp_id
            jsonOut(['otp_id' => bin2hex(random_bytes(16))]);
        }

        // Generate 6-digit code
        $code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $otpId = $config->createOtp($email, hash('sha256', $code), 'login', $user['id']);

        Mailer::sendOtp($config, $email, $code);
        AuditLog::log($config, 'otp_sent', $user['id'], ['email' => $email]);

        jsonOut(['otp_id' => $otpId]);

    case 'verify_otp':
        if ($method !== 'POST') jsonError('POST required', 405);

        $otpId = $input['otp_id'] ?? '';
        $code  = $input['code'] ?? '';
        if (empty($otpId) || empty($code)) jsonError('otp_id and code required');

        // Rate limit
        $rateKey = "otp_verify:{$ip}";
        $rateConfig = $config->getRateLimit('rate_otp_verify');
        // attempt() records this attempt and reports whether it's
        // still within budget in one atomic step -- see RateLimit::attempt().
        if (!RateLimit::attempt($config, $rateKey, $rateConfig[0], $rateConfig[1])) {
            jsonError('Too many attempts. Try again later.', 429);
        }

        $otp = $config->verifyOtp($otpId, $code, 'login');
        if (!$otp) {
            jsonError('Invalid or expired code');
        }

        $user = $otp['user_id'] ? $config->getUserById($otp['user_id']) : null;
        if (!$user || !$user['active']) {
            jsonError('User not found or inactive');
        }

        RateLimit::reset($config, $rateKey);
        AuditLog::log($config, 'otp_verified', $user['id']);

        jsonOut([
            'user_id'      => $user['id'],
            'username'     => $user['username'],
            'email'        => $user['email'],
            'display_name' => $user['display_name'],
        ]);

    case 'request_password_reset':
        if ($method !== 'POST') jsonError('POST required', 405);

        $email = trim($input['email'] ?? '');
        if (empty($email)) jsonError('Email required');

        // Rate limit
        $rateKey = "reset:{$ip}";
        $rateConfig = $config->getRateLimit('rate_reset');
        // attempt() records this attempt and reports whether it's
        // still within budget in one atomic step -- see RateLimit::attempt().
        if (!RateLimit::attempt($config, $rateKey, $rateConfig[0], $rateConfig[1])) {
            jsonError('Too many requests. Try again later.', 429);
        }

        // Always return success to prevent email enumeration
        $user = $config->getUserByEmail($email);
        if ($user && $user['active']) {
            $code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
            $config->createOtp($email, hash('sha256', $code), 'password_reset', $user['id']);
            Mailer::sendPasswordReset($config, $email, $code);
            AuditLog::log($config, 'reset_requested', $user['id']);
        }

        jsonOut(['success' => true]);

    case 'verify_password_reset':
        if ($method !== 'POST') jsonError('POST required', 405);

        $email    = trim($input['email'] ?? '');
        $code     = $input['code'] ?? '';
        $newPass  = $input['new_password'] ?? '';

        if (empty($email) || empty($code) || empty($newPass)) {
            jsonError('All fields required');
        }
        if (strlen($newPass) < 12) {
            jsonError('Password must be at least 12 characters');
        }

        // Rate limit
        $rateKey = "reset_verify:{$ip}";
        $rateConfig = $config->getRateLimit('rate_otp_verify');
        // attempt() records this attempt and reports whether it's
        // still within budget in one atomic step -- see RateLimit::attempt().
        if (!RateLimit::attempt($config, $rateKey, $rateConfig[0], $rateConfig[1])) {
            jsonError('Too many attempts', 429);
        }

        // Find a valid OTP for this email
        $st = $config->db()->prepare(
            "SELECT * FROM otp_codes WHERE email = :email AND purpose = 'password_reset' AND used = 0 AND expires_at > :now ORDER BY created_at DESC LIMIT 1"
        );
        $st->execute([':email' => $email, ':now' => time()]);
        $otp = $st->fetch();

        if (!$otp || !hash_equals($otp['code_hash'], hash('sha256', $code))) {
            jsonError('Invalid or expired reset code');
        }

        // Mark used
        $config->db()->prepare("UPDATE otp_codes SET used = 1 WHERE id = :id")
            ->execute([':id' => $otp['id']]);

        // Update password
        $user = $config->getUserByEmail($email);
        if (!$user) jsonError('User not found');

        $config->updateUser($user['id'], [
            'password_hash' => password_hash($newPass, PASSWORD_DEFAULT),
        ]);

        // A password reset is often done *because* the old password (or a
        // stolen session) is suspected compromised -- so any session that
        // already exists shouldn't survive it. There's no "current session"
        // to exclude here: this is an unauthenticated reset flow, done by
        // email code, not from an existing logged-in session.
        $config->deleteUserSessions($user['id']);

        RateLimit::reset($config, $rateKey);
        AuditLog::log($config, 'password_reset', $user['id']);

        jsonOut(['success' => true]);

    default:
        jsonError('Unknown action', 404);
}
