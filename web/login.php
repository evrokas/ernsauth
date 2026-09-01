<?php

$baseDir = dirname(__DIR__);
require_once $baseDir . '/src/Config.php';
require_once $baseDir . '/src/Auth.php';
require_once $baseDir . '/src/TOTP.php';
require_once $baseDir . '/src/RateLimit.php';
require_once $baseDir . '/src/AuditLog.php';

$error = '';
$totpStep = false;

try {
    $config = Config::getInstance();
} catch (Exception $e) {
    $error = 'Database error: ' . $e->getMessage();
}

Auth::startSession();

// Logout -- must run before the "already logged in" check below: the Sign
// Out link only ever gets clicked while ea_authed is still true, so if that
// redirect ran first it would always win and Auth::logout() would never be
// reached at all (this was the exact bug: clicking Sign Out silently bounced
// straight back to the dashboard without clearing the session or cookie).
if (isset($_GET['logout']) && !empty($config)) {
    Auth::logout($config);
    header('Location: login.php');
    exit;
}

// Already logged in
if (!empty($_SESSION['ea_authed'])) {
    header('Location: dashboard.php');
    exit;
}

// Setup message
$setupSuccess = !empty($_GET['setup']);

// Cancel TOTP step
if (isset($_GET['cancel_totp'])) {
    unset($_SESSION['ea_totp_pending'], $_SESSION['ea_remember_pending']);
    header('Location: login.php');
    exit;
}

// Check for pending TOTP
if (!empty($_SESSION['ea_totp_pending'])) {
    $totpStep = true;
}

$h = function($s) { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); };

// A separate token from the post-login $_SESSION['csrf_token'] api.php
// checks (that one doesn't exist yet -- there's no authenticated session at
// this point). Generated once per PHP session and reused across the
// password step and the TOTP step that follows it in the same session,
// rather than regenerated on every load, so a slow-typing user or a page
// left open through the TOTP redirect doesn't get a stale-token error.
if (empty($_SESSION['login_csrf'])) {
    $_SESSION['login_csrf'] = bin2hex(random_bytes(32));
}
$loginCsrf = $_SESSION['login_csrf'];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($error) &&
    !hash_equals($loginCsrf, $_POST['csrf_token'] ?? '')) {
    // Without a login CSRF token, a third-party page can silently submit
    // this form with attacker-chosen credentials, logging the victim into
    // the attacker's account (a well-known "login CSRF" -- useful for
    // tracking a victim's activity under an account the attacker controls,
    // among other tricks). Rejected before touching the rate limiter or
    // any credential check: a mismatch here is a stale/missing token, not
    // a guessed password, and shouldn't cost the real user an attempt.
    $error = 'Your session expired. Please try again.';
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($error)) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    if ($totpStep) {
        // TOTP verification step
        $code = trim($_POST['totp_code'] ?? '');
        $userId = $_SESSION['ea_totp_pending'];

        $rateKey = "totp:{$ip}";
        $rateConfig = $config->get('rate_totp', [5, 900]);

        // attempt() both records this attempt and reports whether it's
        // still within budget, atomically -- see RateLimit::attempt() for
        // why that has to be one step rather than a separate check first.
        if (!RateLimit::attempt($config, $rateKey, $rateConfig[0], $rateConfig[1])) {
            $remaining = RateLimit::getRemainingSeconds($config, $rateKey, $rateConfig[1]);
            $minutes = (int) ceil($remaining / 60);
            $error = "Too many attempts. Try again in {$minutes} minute(s).";
        } else {
            $user = $config->getUserById($userId);
            if (!$user) {
                unset($_SESSION['ea_totp_pending']);
                $error = 'Session expired. Please login again.';
                $totpStep = false;
            } else {
                $verified = false;

                // Check if it's a backup code (8 digits)
                if (strlen($code) === 8 && ctype_digit($code)) {
                    $verified = $config->verifyBackupCode($userId, $code);
                }

                // Check TOTP code (6 digits)
                if (!$verified && strlen($code) === 6 && ctype_digit($code)) {
                    $verified = TOTP::verify($user['totp_secret'], $code);
                }

                if ($verified) {
                    $remember = !empty($_SESSION['ea_remember_pending']);
                    unset($_SESSION['ea_totp_pending'], $_SESSION['ea_remember_pending']);
                    Auth::login($config, $user, $remember);
                    RateLimit::reset($config, $rateKey);
                    AuditLog::log($config, 'login', $user['id']);
                    header('Location: dashboard.php');
                    exit;
                } else {
                    // Already recorded by attempt() above.
                    sleep(1);
                    $error = 'Invalid code. Enter your 6-digit TOTP code or 8-digit backup code.';
                }
            }
        }
    } else {
        // Password step
        $login    = trim($_POST['login'] ?? '');
        $password = $_POST['password'] ?? '';
        $remember = !empty($_POST['remember_me']);

        $rateKey = "login:{$ip}";
        $rateConfig = $config->get('rate_login', [5, 900]);

        if (!RateLimit::attempt($config, $rateKey, $rateConfig[0], $rateConfig[1])) {
            $remaining = RateLimit::getRemainingSeconds($config, $rateKey, $rateConfig[1]);
            $minutes = (int) ceil($remaining / 60);
            $error = "Too many attempts. Try again in {$minutes} minute(s).";
        } elseif (empty($login) || empty($password)) {
            $error = 'Please enter your username/email and password.';
        } else {
            $user = $config->getUserByLogin($login);
            if ($user && $user['active'] && password_verify($password, $user['password_hash'])) {
                if ($user['totp_enabled']) {
                    $_SESSION['ea_totp_pending'] = $user['id'];
                    // Carried across to the TOTP step below, since the
                    // checkbox itself only exists on this password form --
                    // Auth::login() isn't called until TOTP succeeds.
                    $_SESSION['ea_remember_pending'] = $remember;
                    $totpStep = true;
                } else {
                    Auth::login($config, $user, $remember);
                    RateLimit::reset($config, $rateKey);
                    AuditLog::log($config, 'login', $user['id']);
                    header('Location: dashboard.php');
                    exit;
                }
            } else {
                // Already recorded by attempt() above.
                sleep(1);
                $error = 'Invalid username/email or password.';
                if ($user) {
                    AuditLog::log($config, 'login_failed', $user['id']);
                } else {
                    AuditLog::log($config, 'login_failed', null, ['login' => $login]);
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ErnsAuth — Login</title>
<link rel="stylesheet" href="css/auth.css">
</head>
<body>
<div class="auth-box">
  <h1>Erns<span>Auth</span></h1>
  <p class="subtitle"><?= $totpStep ? 'Enter your verification code' : 'Sign in to your account' ?></p>

  <?php if ($setupSuccess && !$error): ?>
  <div class="success">Admin account created. Please sign in.</div>
  <?php endif; ?>

  <?php if ($error): ?>
  <div class="error"><?= $h($error) ?></div>
  <?php endif; ?>

  <?php if ($totpStep): ?>
  <form method="post" action="login.php" autocomplete="off">
    <input type="hidden" name="csrf_token" value="<?= $h($loginCsrf) ?>">
    <label for="totp_code">Verification Code</label>
    <input type="text" id="totp_code" name="totp_code" inputmode="numeric" pattern="[0-9]*"
           placeholder="6-digit TOTP or 8-digit backup" maxlength="8" autofocus autocomplete="one-time-code">
    <p class="hint">Enter the code from your authenticator app, or an 8-digit backup code.</p>
    <button type="submit">Verify</button>
    <a href="login.php?cancel_totp=1" class="cancel-link">Back to login</a>
  </form>
  <?php else: ?>
  <form method="post" action="login.php">
    <input type="hidden" name="csrf_token" value="<?= $h($loginCsrf) ?>">
    <label for="login">Username or Email</label>
    <input type="text" id="login" name="login" value="<?= $h($_POST['login'] ?? '') ?>" required autofocus autocomplete="username">

    <label for="password">Password</label>
    <input type="password" id="password" name="password" required autocomplete="current-password">

    <label class="checkbox-label">
      <input type="checkbox" id="remember_me" name="remember_me" value="1" <?= !empty($_POST['remember_me']) ? 'checked' : '' ?>>
      Remember me for 30 days
    </label>

    <button type="submit">Sign In</button>
  </form>
  <?php endif; ?>
</div>
</body>
</html>
