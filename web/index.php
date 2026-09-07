<?php

$baseDir = dirname(__DIR__);
require_once $baseDir . '/src/Config.php';
require_once $baseDir . '/src/Auth.php';

try {
    $config = Config::getInstance();
    Auth::startSession();

    if ($config->userCount() === 0) {
        header('Location: setup.php');
        exit;
    }

    if (Auth::isAuthenticated()) {
        header('Location: dashboard.php');
    } else {
        header('Location: login.php');
    }
} catch (Exception $e) {
    header('Location: setup.php');
}
exit;
