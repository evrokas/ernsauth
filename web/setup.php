<?php

$baseDir = dirname(__DIR__);
require_once $baseDir . '/src/Config.php';
require_once $baseDir . '/src/Auth.php';

$error = '';
$success = '';

try {
    $config = Config::getInstance();

    // If users exist, setup is disabled
    if ($config->userCount() > 0) {
        header('Location: login.php');
        exit;
    }
} catch (Exception $e) {
    $error = 'Database error: ' . $e->getMessage() . ' — Run: php src/schema.php --init';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($error)) {
    $username    = trim($_POST['username'] ?? '');
    $email       = trim($_POST['email'] ?? '');
    $displayName = trim($_POST['display_name'] ?? '');
    $password    = $_POST['password'] ?? '';
    $confirm     = $_POST['confirm'] ?? '';

    if (empty($username) || empty($email) || empty($password)) {
        $error = 'All fields are required.';
    } elseif (strlen($username) < 3 || strlen($username) > 50) {
        $error = 'Username must be 3-50 characters.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Invalid email address.';
    } elseif (strlen($password) < 12) {
        $error = 'Password must be at least 12 characters.';
    } elseif ($password !== $confirm) {
        $error = 'Passwords do not match.';
    } else {
        try {
            $config->createUser([
                'username'      => $username,
                'email'         => $email,
                'password_hash' => password_hash($password, PASSWORD_DEFAULT),
                'display_name'  => $displayName ?: $username,
                'is_admin'      => 1,
            ]);
            header('Location: login.php?setup=1');
            exit;
        } catch (PDOException $e) {
            if (strpos($e->getMessage(), 'Duplicate') !== false) {
                $error = 'Username or email already exists.';
            } else {
                $error = 'Database error: ' . $e->getMessage();
            }
        }
    }
}

$h = function($s) { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); };
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ErnsAuth — Setup</title>
<link rel="stylesheet" href="css/auth.css">
</head>
<body>
<div class="auth-box">
  <h1>ErnsAuth <span>Setup</span></h1>
  <p class="subtitle">Create your admin account</p>

  <?php if ($error): ?>
  <div class="error"><?= $h($error) ?></div>
  <?php endif; ?>

  <form method="post" action="setup.php" autocomplete="off">
    <label for="username">Username</label>
    <input type="text" id="username" name="username" value="<?= $h($_POST['username'] ?? '') ?>" required autofocus autocomplete="username">

    <label for="email">Email</label>
    <input type="email" id="email" name="email" value="<?= $h($_POST['email'] ?? '') ?>" required autocomplete="email">

    <label for="display_name">Display Name</label>
    <input type="text" id="display_name" name="display_name" value="<?= $h($_POST['display_name'] ?? '') ?>" placeholder="Optional">

    <label for="password">Password</label>
    <input type="password" id="password" name="password" required minlength="12" autocomplete="new-password">

    <label for="confirm">Confirm Password</label>
    <input type="password" id="confirm" name="confirm" required minlength="12" autocomplete="new-password">

    <button type="submit">Create Admin Account</button>
  </form>
</div>
</body>
</html>
