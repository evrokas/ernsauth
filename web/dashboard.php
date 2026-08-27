<?php

$baseDir = dirname(__DIR__);
require_once $baseDir . '/src/Config.php';
require_once $baseDir . '/src/Auth.php';

Auth::requireLogin();

$user = Auth::getCurrentUser();
$isAdmin = Auth::isAdmin();
$csrf = Auth::getCsrfToken();

$h = function($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); };
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="csrf-token" content="<?= $h($csrf) ?>">
<title>ErnsAuth Dashboard</title>
<link rel="stylesheet" href="css/dashboard.css">
</head>
<body>

<div class="header">
  <h1>Erns<span>Auth</span></h1>
  <div class="header-right">
    <span class="header-user"><?= $h($user['display_name'] ?: $user['username']) ?></span>
    <a href="login.php?logout" class="header-btn">Sign Out</a>
  </div>
</div>

<div class="tabs" id="tabs">
  <button class="tab active" data-tab="pending">Pending Logins</button>
  <button class="tab" data-tab="sessions">Active Sessions</button>
  <button class="tab" data-tab="security">Security</button>
  <?php if ($isAdmin): ?>
  <button class="tab" data-tab="admin">Admin</button>
  <?php endif; ?>
</div>

<div class="content">
  <!-- Pending Logins -->
  <div class="panel active" id="panel-pending">
    <div id="pending-logins">
      <div class="empty-state">Checking for pending logins...</div>
    </div>
  </div>

  <!-- Active Sessions -->
  <div class="panel" id="panel-sessions">
    <div class="card">
      <div class="card-title">Active Sessions</div>
      <div id="sessions-list">
        <div class="empty-state"><span class="spinner"></span> Loading...</div>
      </div>
      <div style="margin-top:12px">
        <button class="btn btn-ghost" id="btn-revoke-all">Revoke All Other Sessions</button>
      </div>
    </div>
  </div>

  <!-- Security -->
  <div class="panel" id="panel-security">
    <!-- TOTP -->
    <div class="card">
      <div class="card-title">Two-Factor Authentication (TOTP)</div>
      <div id="totp-section">
        <?php if ($user['totp_enabled']): ?>
        <p style="color:#86efac;margin-bottom:12px">2FA is enabled.</p>
        <div class="form-group">
          <label for="disable-totp-pass">Enter password to disable 2FA</label>
          <input type="password" id="disable-totp-pass">
        </div>
        <button class="btn btn-danger" id="btn-disable-totp">Disable 2FA</button>
        <?php else: ?>
        <p style="color:#94a3b8;margin-bottom:12px">2FA is not enabled. Secure your account with an authenticator app.</p>
        <button class="btn btn-primary" id="btn-setup-totp">Enable 2FA</button>
        <div id="totp-setup-area" style="display:none"></div>
        <?php endif; ?>
      </div>
    </div>

    <!-- Change Password -->
    <div class="card">
      <div class="card-title">Change Password</div>
      <div id="password-message"></div>
      <div class="form-group">
        <label for="current-pass">Current Password</label>
        <input type="password" id="current-pass">
      </div>
      <div class="form-group">
        <label for="new-pass">New Password</label>
        <input type="password" id="new-pass" minlength="12">
      </div>
      <div class="form-group">
        <label for="confirm-pass">Confirm New Password</label>
        <input type="password" id="confirm-pass" minlength="12">
      </div>
      <button class="btn btn-primary" id="btn-change-pass">Change Password</button>
    </div>
  </div>

  <?php if ($isAdmin): ?>
  <!-- Admin -->
  <div class="panel" id="panel-admin">
    <!-- Sub-tabs -->
    <div style="display:flex;gap:12px;margin-bottom:20px">
      <button class="btn btn-ghost admin-subtab active" data-subtab="apps">Client Apps</button>
      <button class="btn btn-ghost admin-subtab" data-subtab="users">Users</button>
      <button class="btn btn-ghost admin-subtab" data-subtab="audit">Audit Log</button>
    </div>

    <!-- Client Apps -->
    <div class="admin-panel active" id="admin-apps">
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
          <div class="card-title" style="margin-bottom:0">Client Apps</div>
          <button class="btn btn-primary btn-sm" id="btn-add-app">Add App</button>
        </div>
        <div class="table-wrap" id="apps-table">
          <div class="empty-state"><span class="spinner"></span> Loading...</div>
        </div>
      </div>
    </div>

    <!-- Users -->
    <div class="admin-panel" id="admin-users">
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
          <div class="card-title" style="margin-bottom:0">Users</div>
          <button class="btn btn-primary btn-sm" id="btn-add-user">Add User</button>
        </div>
        <div class="table-wrap" id="users-table">
          <div class="empty-state"><span class="spinner"></span> Loading...</div>
        </div>
      </div>
    </div>

    <!-- Audit Log -->
    <div class="admin-panel" id="admin-audit">
      <div class="card">
        <div class="card-title">Audit Log</div>
        <div class="filter-row">
          <div class="form-group">
            <label>Action</label>
            <select id="audit-action-filter">
              <option value="">All</option>
              <option value="login">Login</option>
              <option value="login_failed">Login Failed</option>
              <option value="logout">Logout</option>
              <option value="sso_approve">SSO Approve</option>
              <option value="sso_reject">SSO Reject</option>
              <option value="password_change">Password Change</option>
              <option value="totp_enable">TOTP Enable</option>
              <option value="totp_disable">TOTP Disable</option>
            </select>
          </div>
          <div class="form-group">
            <button class="btn btn-ghost btn-sm" id="btn-audit-search" style="margin-top:18px">Search</button>
          </div>
        </div>
        <div class="table-wrap" id="audit-table">
          <div class="empty-state"><span class="spinner"></span> Loading...</div>
        </div>
        <div class="pagination" id="audit-pagination"></div>
      </div>
    </div>
  </div>
  <?php endif; ?>
</div>

<!-- Modal -->
<div class="modal-overlay" id="modal-overlay">
  <div class="modal" id="modal"></div>
</div>

<script src="js/dashboard.js"></script>
</body>
</html>
