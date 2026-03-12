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

// Already logged in
if (!empty($_SESSION['ea_authed'])) {
    header('Location: dashboard.php');
    exit;
}

// Setup message
$setupSuccess = !empty($_GET['setup']);

// Logout
if (isset($_GET['logout']) && !empty($config)) {
    Auth::logout($config);
    header('Location: login.php');
    exit;
}

// Cancel TOTP step
if (isset($_GET['cancel_totp'])) {
    unset($_SESSION['ea_totp_pending']);
    header('Location: login.php');
    exit;
}

// Check for pending TOTP
if (!empty($_SESSION['ea_totp_pending'])) {
    $totpStep = true;
}

$h = function($s) { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); };

if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($error)) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    if ($totpStep) {
        // TOTP verification step
        $code = trim($_POST['totp_code'] ?? '');
        $userId = $_SESSION['ea_totp_pending'];

        $rateKey = "totp:{$ip}";
        $rateConfig = $config->get('rate_totp', [5, 900]);

        if (!RateLimit::check($config, $rateKey, $rateConfig[0], $rateConfig[1])) {
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
                    unset($_SESSION['ea_totp_pending']);
                    Auth::login($config, $user);
                    RateLimit::reset($config, $rateKey);
                    AuditLog::log($config, 'login', $user['id']);
                    header('Location: dashboard.php');
                    exit;
                } else {
                    RateLimit::increment($config, $rateKey, $rateConfig[1]);
                    sleep(1);
                    $error = 'Invalid code. Enter your 6-digit TOTP code or 8-digit backup code.';
                }
            }
        }
    } else {
        // Password step
        $login    = trim($_POST['login'] ?? '');
        $password = $_POST['password'] ?? '';

        $rateKey = "login:{$ip}";
        $rateConfig = $config->get('rate_login', [5, 900]);

        if (!RateLimit::check($config, $rateKey, $rateConfig[0], $rateConfig[1])) {
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
                    $totpStep = true;
                } else {
                    Auth::login($config, $user);
                    RateLimit::reset($config, $rateKey);
                    AuditLog::log($config, 'login', $user['id']);
                    header('Location: dashboard.php');
                    exit;
                }
            } else {
                RateLimit::increment($config, $rateKey, $rateConfig[1]);
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
    <label for="totp_code">Verification Code</label>
    <input type="text" id="totp_code" name="totp_code" inputmode="numeric" pattern="[0-9]*"
           placeholder="6-digit TOTP or 8-digit backup" maxlength="8" autofocus autocomplete="one-time-code">
    <p class="hint">Enter the code from your authenticator app, or an 8-digit backup code.</p>
    <button type="submit">Verify</button>
    <a href="login.php?cancel_totp=1" class="cancel-link">Back to login</a>
  </form>
  <?php else: ?>
  <form method="post" action="login.php">
    <label for="login">Username or Email</label>
    <input type="text" id="login" name="login" value="<?= $h($_POST['login'] ?? '') ?>" required autofocus autocomplete="username">

    <label for="password">Password</label>
    <input type="password" id="password" name="password" required autocomplete="current-password">

    <button type="submit">Sign In</button>
  </form>
  <?php endif; ?>
</div>
</body>
</html>
