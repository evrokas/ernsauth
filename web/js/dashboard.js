// dashboard.js -- ErnsAuth dashboard
(function() {
    'use strict';

    var csrfToken = document.querySelector('meta[name="csrf-token"]').content;
    var pollTimer = null;

    // Bumped by any action that changes a challenge's state (approve/reject)
    // and captured by each loadPendingLogins() call. A pending_logins fetch
    // is only rendered if this still matches when it resolves -- otherwise
    // it's a stale response (issued before the action, but landing after)
    // and would just resurrect a card the user already dismissed by
    // overwriting the list with the pre-action data. Without this, a poll
    // in flight at the moment of a reject/approve click can win that race
    // and show the rejected card again a few seconds later.
    var pendingListVersion = 0;

    // ── API helpers ───────────────────────────────────────────────────────

    function api(action, opts) {
        opts = opts || {};
        var method = opts.method || 'GET';
        var body = opts.body || null;
        var params = opts.params || {};

        var url = 'api.php?action=' + encodeURIComponent(action);
        for (var k in params) {
            url += '&' + encodeURIComponent(k) + '=' + encodeURIComponent(params[k]);
        }

        var fetchOpts = {
            method: method,
            headers: { 'X-CSRF-Token': csrfToken },
            credentials: 'same-origin'
        };

        if (body && method === 'POST') {
            fetchOpts.headers['Content-Type'] = 'application/json';
            fetchOpts.body = JSON.stringify(body);
        }

        return fetch(url, fetchOpts).then(function(r) {
            if (r.status === 401) {
                window.location.href = 'login.php';
                throw new Error('Not authenticated');
            }
            return r.json();
        });
    }

    function h(s) {
        var d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    }

    // ── Tabs ──────────────────────────────────────────────────────────────

    var tabs = document.querySelectorAll('.tab');
    var panels = document.querySelectorAll('.panel');

    tabs.forEach(function(tab) {
        tab.addEventListener('click', function() {
            var target = this.dataset.tab;
            tabs.forEach(function(t) { t.classList.remove('active'); });
            panels.forEach(function(p) { p.classList.remove('active'); });
            this.classList.add('active');
            document.getElementById('panel-' + target).classList.add('active');

            if (target === 'sessions') loadSessions();
            if (target === 'admin') loadAdminTab();
            if (target === 'pending') startPolling();
            else stopPolling();
        });
    });

    // Admin sub-tabs
    document.querySelectorAll('.admin-subtab').forEach(function(btn) {
        btn.addEventListener('click', function() {
            document.querySelectorAll('.admin-subtab').forEach(function(b) { b.classList.remove('active'); });
            document.querySelectorAll('.admin-panel').forEach(function(p) { p.classList.remove('active'); });
            this.classList.add('active');
            document.getElementById('admin-' + this.dataset.subtab).classList.add('active');
            loadAdminTab();
        });
    });

    // ── Pending Logins ────────────────────────────────────────────────────

    function loadPendingLogins() {
        var version = ++pendingListVersion;
        api('pending_logins').then(function(data) {
            if (version !== pendingListVersion) return; // superseded by a newer poll or a reject/approve
            var container = document.getElementById('pending-logins');
            if (!data.challenges || data.challenges.length === 0) {
                container.innerHTML = '<div class="empty-state">No pending login requests</div>';
                return;
            }

            var html = '';
            data.challenges.forEach(function(ch) {
                html += '<div class="challenge-card" id="challenge-' + h(ch.id) + '">';
                html += '<div class="challenge-header">';
                html += '<span class="challenge-emoji">' + h(ch.app_emoji || '') + '</span>';
                html += '<span class="challenge-app">' + h(ch.app_label) + '</span>';
                html += '</div>';
                html += '<div class="challenge-meta">From ' + h(ch.client_ip) + ' &middot; ' + h(ch.time_ago) + '</div>';
                if (ch.requested_identity) {
                    // Whatever the calling app typed into its own login form
                    // -- an unverified claim, not something ErnsAuth checked.
                    // Shown so the approver can catch "that's not me" before
                    // tapping a number, not treated as a fact anywhere else.
                    html += '<div class="challenge-identity">Claiming to be <strong>' + h(ch.requested_identity) + '</strong></div>';
                }
                html += '<div class="challenge-numbers">';
                ch.numbers.forEach(function(n) {
                    html += '<button class="number-btn" data-challenge="' + h(ch.id) + '" data-number="' + n + '">' + n + '</button>';
                });
                html += '</div>';
                html += '<button class="btn btn-ghost btn-sm reject-btn" data-challenge="' + h(ch.id) + '">Reject</button>';
                html += '</div>';
            });
            container.innerHTML = html;

            // Bind number buttons
            container.querySelectorAll('.number-btn').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    approveLogin(this.dataset.challenge, parseInt(this.dataset.number), this);
                });
            });

            // Bind reject buttons
            container.querySelectorAll('.reject-btn').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    rejectLogin(this.dataset.challenge);
                });
            });
        });
    }

    function approveLogin(challengeId, number, btn) {
        api('approve_login', {
            method: 'POST',
            body: { challenge_id: challengeId, selected_number: number }
        }).then(function(data) {
            if (data.success) {
                pendingListVersion++; // invalidate in-flight polls so they can't resurrect this card
                btn.classList.add('correct');
                setTimeout(function() {
                    var card = document.getElementById('challenge-' + challengeId);
                    if (card) card.remove();
                    checkEmpty();
                }, 1000);
            } else {
                btn.classList.add('wrong');
                setTimeout(function() { btn.classList.remove('wrong'); }, 1500);
            }
        }).catch(function() {
            btn.classList.add('wrong');
            setTimeout(function() { btn.classList.remove('wrong'); }, 1500);
        });
    }

    function rejectLogin(challengeId) {
        api('reject_login', {
            method: 'POST',
            body: { challenge_id: challengeId }
        }).then(function() {
            pendingListVersion++; // invalidate in-flight polls so they can't resurrect this card
            var card = document.getElementById('challenge-' + challengeId);
            if (card) card.remove();
            checkEmpty();
        });
    }

    function checkEmpty() {
        var container = document.getElementById('pending-logins');
        if (!container.querySelector('.challenge-card')) {
            container.innerHTML = '<div class="empty-state">No pending login requests</div>';
        }
    }

    function startPolling() {
        loadPendingLogins();
        stopPolling();
        pollTimer = setInterval(loadPendingLogins, 5000);
    }

    function stopPolling() {
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    }

    // ── Sessions ──────────────────────────────────────────────────────────

    function loadSessions() {
        api('active_sessions').then(function(data) {
            var container = document.getElementById('sessions-list');
            if (!data.sessions || data.sessions.length === 0) {
                container.innerHTML = '<div class="empty-state">No active sessions</div>';
                return;
            }

            var html = '<table><thead><tr>';
            html += '<th>Device</th><th>IP Address</th><th>Last Active</th><th>Created</th><th></th>';
            html += '</tr></thead><tbody>';

            data.sessions.forEach(function(s) {
                var cls = s.is_current ? ' class="current"' : '';
                html += '<tr' + cls + '>';
                html += '<td>' + h(s.device_label || 'Unknown') + (s.is_current ? ' <span class="badge badge-blue">Current</span>' : '') + '</td>';
                html += '<td>' + h(s.ip_address || '') + '</td>';
                html += '<td>' + formatTime(s.last_active) + '</td>';
                html += '<td>' + formatTime(s.created_at) + '</td>';
                html += '<td>';
                if (!s.is_current) {
                    html += '<button class="btn btn-danger btn-sm revoke-btn" data-session="' + h(s.id) + '">Revoke</button>';
                }
                html += '</td></tr>';
            });

            html += '</tbody></table>';
            container.innerHTML = html;

            container.querySelectorAll('.revoke-btn').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    if (confirm('Revoke this session?')) {
                        api('revoke_session', { method: 'POST', body: { session_id: this.dataset.session } })
                            .then(function() { loadSessions(); });
                    }
                });
            });
        });
    }

    document.getElementById('btn-revoke-all').addEventListener('click', function() {
        if (confirm('Revoke all other sessions?')) {
            api('revoke_all_sessions', { method: 'POST' }).then(function(data) {
                loadSessions();
            });
        }
    });

    // ── Security: TOTP ────────────────────────────────────────────────────

    var setupTotpBtn = document.getElementById('btn-setup-totp');
    if (setupTotpBtn) {
        setupTotpBtn.addEventListener('click', function() {
            this.disabled = true;
            api('setup_totp', { method: 'POST' }).then(function(data) {
                var area = document.getElementById('totp-setup-area');
                area.style.display = 'block';

                var html = '<div class="totp-setup">';
                html += '<p style="margin-bottom:12px">Scan this QR code with your authenticator app:</p>';
                html += '<div class="totp-qr" id="totp-qr"></div>';
                html += '<p style="font-size:12px;color:#64748b;margin-bottom:4px">Or enter this secret manually:</p>';
                html += '<div class="totp-secret">' + h(data.secret) + '</div>';
                html += '<div class="form-group" style="max-width:200px;margin:0 auto">';
                html += '<label>Enter code from app to confirm</label>';
                html += '<input type="text" id="totp-confirm-code" inputmode="numeric" maxlength="6" placeholder="000000">';
                html += '</div>';
                html += '<button class="btn btn-primary" id="btn-confirm-totp" style="margin-top:12px">Confirm & Enable</button>';
                html += '<div style="margin-top:20px;text-align:left">';
                html += '<p style="font-size:13px;font-weight:600;margin-bottom:8px">Backup Codes (save these!):</p>';
                html += '<div class="backup-codes">';
                data.backup_codes.forEach(function(c) {
                    html += '<div class="backup-code">' + h(c) + '</div>';
                });
                html += '</div></div></div>';
                area.innerHTML = html;

                // Generate QR code
                if (typeof QRCode !== 'undefined') {
                    new QRCode(document.getElementById('totp-qr'), {
                        text: data.provisioning_uri,
                        width: 200,
                        height: 200,
                        colorDark: '#e2e8f0',
                        colorLight: '#1a1d27',
                    });
                } else {
                    document.getElementById('totp-qr').innerHTML =
                        '<p style="font-size:12px;color:#64748b">QR library not loaded. Use the manual secret above.</p>';
                }

                document.getElementById('btn-confirm-totp').addEventListener('click', function() {
                    var code = document.getElementById('totp-confirm-code').value.trim();
                    api('confirm_totp', { method: 'POST', body: { code: code } }).then(function(data) {
                        if (data.success) {
                            window.location.reload();
                        } else {
                            alert(data.error || 'Invalid code');
                        }
                    }).catch(function(e) {
                        alert('Error confirming TOTP');
                    });
                });
            });
        });
    }

    var disableTotpBtn = document.getElementById('btn-disable-totp');
    if (disableTotpBtn) {
        disableTotpBtn.addEventListener('click', function() {
            var pass = document.getElementById('disable-totp-pass').value;
            if (!pass) { alert('Enter your password'); return; }
            api('disable_totp', { method: 'POST', body: { password: pass } }).then(function(data) {
                if (data.success) window.location.reload();
                else alert(data.error || 'Failed');
            });
        });
    }

    // ── Security: Change Password ─────────────────────────────────────────

    document.getElementById('btn-change-pass').addEventListener('click', function() {
        var current = document.getElementById('current-pass').value;
        var newPass = document.getElementById('new-pass').value;
        var confirm = document.getElementById('confirm-pass').value;
        var msgEl = document.getElementById('password-message');

        api('change_password', {
            method: 'POST',
            body: { current: current, new_password: newPass, confirm: confirm }
        }).then(function(data) {
            if (data.success) {
                msgEl.innerHTML = '<div class="alert alert-success">Password changed successfully.</div>';
                document.getElementById('current-pass').value = '';
                document.getElementById('new-pass').value = '';
                document.getElementById('confirm-pass').value = '';
            } else {
                msgEl.innerHTML = '<div class="alert alert-error">' + h(data.error) + '</div>';
            }
        }).catch(function() {
            msgEl.innerHTML = '<div class="alert alert-error">Request failed.</div>';
        });
    });

    // ── Admin ─────────────────────────────────────────────────────────────

    function loadAdminTab() {
        var activePanel = document.querySelector('.admin-panel.active');
        if (!activePanel) return;
        var id = activePanel.id;
        if (id === 'admin-apps') loadClientApps();
        else if (id === 'admin-users') loadUsers();
        else if (id === 'admin-ratelimits') loadRateLimits();
        else if (id === 'admin-audit') loadAuditLog();
    }

    // Client Apps
    function loadClientApps() {
        api('get_client_apps').then(function(data) {
            var container = document.getElementById('apps-table');
            if (!data.apps || data.apps.length === 0) {
                container.innerHTML = '<div class="empty-state">No client apps registered</div>';
                return;
            }
            var html = '<table><thead><tr><th>ID</th><th>Label</th><th>Emoji</th><th>Active</th><th></th></tr></thead><tbody>';
            data.apps.forEach(function(app) {
                html += '<tr>';
                html += '<td>' + h(app.id) + '</td>';
                html += '<td>' + h(app.label) + '</td>';
                html += '<td>' + h(app.icon_emoji || '') + '</td>';
                html += '<td>' + (app.active ? '<span class="badge badge-green">Yes</span>' : '<span class="badge badge-red">No</span>') + '</td>';
                html += '<td>';
                html += '<button class="btn btn-ghost btn-sm edit-app" data-id="' + h(app.id) + '">Edit</button> ';
                html += '<button class="btn btn-danger btn-sm delete-app" data-id="' + h(app.id) + '">Delete</button>';
                html += '</td></tr>';
            });
            html += '</tbody></table>';
            container.innerHTML = html;

            container.querySelectorAll('.edit-app').forEach(function(btn) {
                btn.addEventListener('click', function() { showAppModal(this.dataset.id); });
            });
            container.querySelectorAll('.delete-app').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    if (confirm('Delete app "' + this.dataset.id + '"?')) {
                        api('delete_client_app', { method: 'POST', body: { id: this.dataset.id } })
                            .then(function() { loadClientApps(); });
                    }
                });
            });
        });
    }

    document.getElementById('btn-add-app') && document.getElementById('btn-add-app').addEventListener('click', function() {
        showAppModal();
    });

    function showAppModal(editId) {
        var app = null;
        var promise = editId
            ? api('get_client_apps').then(function(d) { app = d.apps.find(function(a) { return a.id === editId; }); })
            : Promise.resolve();

        promise.then(function() {
            var isEdit = !!app;
            var modal = document.getElementById('modal');
            modal.innerHTML = '<div class="modal-title">' + (isEdit ? 'Edit' : 'Add') + ' Client App</div>'
                + '<div class="form-group"><label>App ID</label><input type="text" id="modal-app-id" value="' + h(isEdit ? app.id : '') + '" ' + (isEdit ? 'readonly style="opacity:0.6"' : '') + '></div>'
                + '<div class="form-group"><label>Label</label><input type="text" id="modal-app-label" value="' + h(isEdit ? app.label : '') + '"></div>'
                + '<div class="form-group"><label>Callback URL</label><input type="text" id="modal-app-callback" value="' + h(isEdit ? app.callback_url : '') + '"></div>'
                + '<div class="form-group"><label>Icon Emoji</label><input type="text" id="modal-app-emoji" value="' + h(isEdit ? app.icon_emoji : '') + '" maxlength="10"></div>'
                + (isEdit ? '<div style="margin-top:12px"><button class="btn btn-ghost btn-sm" id="btn-regen-key">Regenerate API Key</button></div>' : '')
                + '<div id="modal-app-result"></div>'
                + '<div class="modal-actions">'
                + '<button class="btn btn-ghost" id="modal-cancel">Cancel</button>'
                + '<button class="btn btn-primary" id="modal-save">Save</button>'
                + '</div>';

            showModal();

            document.getElementById('modal-cancel').onclick = hideModal;
            document.getElementById('modal-save').onclick = function() {
                api('save_client_app', {
                    method: 'POST',
                    body: {
                        id: document.getElementById('modal-app-id').value.trim(),
                        label: document.getElementById('modal-app-label').value.trim(),
                        callback_url: document.getElementById('modal-app-callback').value.trim(),
                        icon_emoji: document.getElementById('modal-app-emoji').value.trim()
                    }
                }).then(function(data) {
                    if (data.api_key) {
                        document.getElementById('modal-app-result').innerHTML =
                            '<div class="alert alert-success" style="margin-top:12px">API Key (copy now, shown only once):<br><code style="font-size:12px;word-break:break-all">' + h(data.api_key) + '</code></div>';
                    } else {
                        hideModal();
                    }
                    loadClientApps();
                }).catch(function() {
                    document.getElementById('modal-app-result').innerHTML = '<div class="alert alert-error" style="margin-top:12px">Save failed</div>';
                });
            };

            var regenBtn = document.getElementById('btn-regen-key');
            if (regenBtn) {
                regenBtn.onclick = function() {
                    if (!confirm('Regenerate API key? The old key will stop working.')) return;
                    api('save_client_app', {
                        method: 'POST',
                        body: { id: editId, label: app.label, callback_url: app.callback_url, icon_emoji: app.icon_emoji, regenerate_key: true }
                    }).then(function(data) {
                        if (data.api_key) {
                            document.getElementById('modal-app-result').innerHTML =
                                '<div class="alert alert-success" style="margin-top:12px">New API Key:<br><code style="font-size:12px;word-break:break-all">' + h(data.api_key) + '</code></div>';
                        }
                    });
                };
            }
        });
    }

    // Rate Limits
    function loadRateLimits() {
        api('get_rate_limits').then(function(data) {
            var container = document.getElementById('ratelimits-table');
            if (!data.limits || data.limits.length === 0) {
                container.innerHTML = '<div class="empty-state">No rate limits defined</div>';
                return;
            }
            var html = '<table><thead><tr><th>Throttle</th><th>Max attempts</th><th>Window (seconds)</th><th></th><th></th></tr></thead><tbody>';
            data.limits.forEach(function(limit) {
                html += '<tr data-key="' + h(limit.key) + '">';
                html += '<td>' + h(limit.label) + '<br><span style="font-size:11px;color:#64748b">' + h(limit.key) + '</span></td>';
                html += '<td><input type="number" min="1" max="100000" class="rl-max" value="' + h(limit.max_attempts) + '" style="width:90px"></td>';
                html += '<td><input type="number" min="1" max="604800" class="rl-window" value="' + h(limit.window_seconds) + '" style="width:100px"></td>';
                html += '<td>' + (limit.is_customized
                    ? '<span class="badge badge-green">Customized</span>'
                    : '<span class="badge badge-blue">Default</span>') + '</td>';
                html += '<td>';
                html += '<button class="btn btn-primary btn-sm rl-save">Save</button> ';
                if (limit.is_customized) {
                    html += '<button class="btn btn-ghost btn-sm rl-reset">Reset</button>';
                }
                html += '</td></tr>';
            });
            html += '</tbody></table>';
            container.innerHTML = html;

            container.querySelectorAll('.rl-save').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    var row = this.closest('tr');
                    var key = row.dataset.key;
                    var maxAttempts = parseInt(row.querySelector('.rl-max').value, 10);
                    var windowSeconds = parseInt(row.querySelector('.rl-window').value, 10);
                    if (!maxAttempts || !windowSeconds || maxAttempts < 1 || windowSeconds < 1) {
                        alert('Max attempts and window must be positive numbers');
                        return;
                    }
                    api('save_rate_limit', {
                        method: 'POST',
                        body: { key: key, max_attempts: maxAttempts, window_seconds: windowSeconds }
                    }).then(function(data) {
                        if (data.error) { alert(data.error); return; }
                        loadRateLimits();
                    });
                });
            });
            container.querySelectorAll('.rl-reset').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    var row = this.closest('tr');
                    var key = row.dataset.key;
                    if (!confirm('Reset "' + key + '" to its default?')) return;
                    api('reset_rate_limit', { method: 'POST', body: { key: key } })
                        .then(function() { loadRateLimits(); });
                });
            });
        });
    }

    // Users
    function loadUsers() {
        api('get_users').then(function(data) {
            var container = document.getElementById('users-table');
            if (!data.users || data.users.length === 0) {
                container.innerHTML = '<div class="empty-state">No users</div>';
                return;
            }
            var html = '<table><thead><tr><th>Username</th><th>Email</th><th>Display Name</th><th>Admin</th><th>Active</th><th></th></tr></thead><tbody>';
            data.users.forEach(function(u) {
                html += '<tr>';
                html += '<td>' + h(u.username) + '</td>';
                html += '<td>' + h(u.email) + '</td>';
                html += '<td>' + h(u.display_name) + '</td>';
                html += '<td>' + (parseInt(u.is_admin) ? '<span class="badge badge-blue">Admin</span>' : '') + '</td>';
                html += '<td>' + (parseInt(u.active) ? '<span class="badge badge-green">Yes</span>' : '<span class="badge badge-red">No</span>') + '</td>';
                html += '<td>';
                html += '<button class="btn btn-ghost btn-sm edit-user" data-id="' + h(u.id) + '">Edit</button> ';
                var toggleLabel = parseInt(u.active) ? 'Deactivate' : 'Activate';
                html += '<button class="btn btn-ghost btn-sm toggle-user" data-id="' + h(u.id) + '" data-active="' + (parseInt(u.active) ? 0 : 1) + '">' + toggleLabel + '</button>';
                html += '</td></tr>';
            });
            html += '</tbody></table>';
            container.innerHTML = html;

            container.querySelectorAll('.edit-user').forEach(function(btn) {
                btn.addEventListener('click', function() { showUserModal(this.dataset.id); });
            });
            container.querySelectorAll('.toggle-user').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    api('toggle_user', { method: 'POST', body: { id: this.dataset.id, active: parseInt(this.dataset.active) } })
                        .then(function() { loadUsers(); });
                });
            });
        });
    }

    document.getElementById('btn-add-user') && document.getElementById('btn-add-user').addEventListener('click', function() {
        showUserModal();
    });

    function showUserModal(editId) {
        var user = null;
        var promise = editId
            ? api('get_users').then(function(d) { user = d.users.find(function(u) { return u.id === editId; }); })
            : Promise.resolve();

        promise.then(function() {
            var isEdit = !!user;
            var modal = document.getElementById('modal');
            modal.innerHTML = '<div class="modal-title">' + (isEdit ? 'Edit' : 'Add') + ' User</div>'
                + '<div class="form-group"><label>Username</label><input type="text" id="modal-user-username" value="' + h(isEdit ? user.username : '') + '"></div>'
                + '<div class="form-group"><label>Email</label><input type="email" id="modal-user-email" value="' + h(isEdit ? user.email : '') + '"></div>'
                + '<div class="form-group"><label>Display Name</label><input type="text" id="modal-user-display" value="' + h(isEdit ? user.display_name : '') + '"></div>'
                + '<div class="form-group"><label>Password' + (isEdit ? ' (leave blank to keep)' : '') + '</label><input type="password" id="modal-user-pass"></div>'
                + '<div class="form-group"><label><input type="checkbox" id="modal-user-admin" ' + (isEdit && parseInt(user.is_admin) ? 'checked' : '') + '> Admin</label></div>'
                + '<div id="modal-user-result"></div>'
                + '<div class="modal-actions">'
                + '<button class="btn btn-ghost" id="modal-cancel">Cancel</button>'
                + '<button class="btn btn-primary" id="modal-save">Save</button>'
                + '</div>';

            showModal();
            document.getElementById('modal-cancel').onclick = hideModal;
            document.getElementById('modal-save').onclick = function() {
                api('save_user', {
                    method: 'POST',
                    body: {
                        id: editId || '',
                        username: document.getElementById('modal-user-username').value.trim(),
                        email: document.getElementById('modal-user-email').value.trim(),
                        display_name: document.getElementById('modal-user-display').value.trim(),
                        password: document.getElementById('modal-user-pass').value,
                        is_admin: document.getElementById('modal-user-admin').checked ? 1 : 0
                    }
                }).then(function(data) {
                    if (data.success) { hideModal(); loadUsers(); }
                    else document.getElementById('modal-user-result').innerHTML = '<div class="alert alert-error" style="margin-top:12px">' + h(data.error) + '</div>';
                }).catch(function() {
                    document.getElementById('modal-user-result').innerHTML = '<div class="alert alert-error" style="margin-top:12px">Save failed</div>';
                });
            };
        });
    }

    // Audit Log
    var auditOffset = 0;
    function loadAuditLog(offset) {
        auditOffset = offset || 0;
        var actionFilter = document.getElementById('audit-action-filter') ? document.getElementById('audit-action-filter').value : '';
        api('audit_log', { params: { action_filter: actionFilter, limit: 50, offset: auditOffset } }).then(function(data) {
            var container = document.getElementById('audit-table');
            if (!data.entries || data.entries.length === 0) {
                container.innerHTML = '<div class="empty-state">No audit entries</div>';
                document.getElementById('audit-pagination').innerHTML = '';
                return;
            }
            var html = '<table><thead><tr><th>Time</th><th>Action</th><th>User</th><th>IP</th><th>Details</th></tr></thead><tbody>';
            data.entries.forEach(function(e) {
                html += '<tr>';
                html += '<td style="white-space:nowrap">' + formatTime(e.created_at) + '</td>';
                html += '<td><span class="badge badge-blue">' + h(e.action) + '</span></td>';
                html += '<td>' + h(e.username || '-') + '</td>';
                html += '<td>' + h(e.ip_address || '-') + '</td>';
                var details = e.details ? JSON.stringify(JSON.parse(e.details)) : '';
                html += '<td style="font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + h(details) + '">' + h(details) + '</td>';
                html += '</tr>';
            });
            html += '</tbody></table>';
            container.innerHTML = html;

            // Pagination
            var pag = document.getElementById('audit-pagination');
            var totalPages = Math.ceil(data.total / 50);
            var currentPage = Math.floor(auditOffset / 50) + 1;
            var pagHtml = '';
            if (currentPage > 1) pagHtml += '<button class="btn btn-ghost btn-sm" onclick="window._loadAudit(' + ((currentPage - 2) * 50) + ')">Prev</button>';
            pagHtml += '<span style="font-size:12px;color:#64748b">Page ' + currentPage + ' of ' + totalPages + '</span>';
            if (currentPage < totalPages) pagHtml += '<button class="btn btn-ghost btn-sm" onclick="window._loadAudit(' + (currentPage * 50) + ')">Next</button>';
            pag.innerHTML = pagHtml;
        });
    }
    window._loadAudit = loadAuditLog;

    var auditSearchBtn = document.getElementById('btn-audit-search');
    if (auditSearchBtn) {
        auditSearchBtn.addEventListener('click', function() { loadAuditLog(0); });
    }

    // ── Modal helpers ─────────────────────────────────────────────────────

    function showModal() {
        document.getElementById('modal-overlay').classList.add('active');
    }

    function hideModal() {
        document.getElementById('modal-overlay').classList.remove('active');
    }

    document.getElementById('modal-overlay').addEventListener('click', function(e) {
        if (e.target === this) hideModal();
    });

    // ── Time formatting ───────────────────────────────────────────────────

    function formatTime(ts) {
        if (!ts) return '-';
        var d = new Date(parseInt(ts) * 1000);
        var now = new Date();
        var diff = Math.floor((now - d) / 1000);
        if (diff < 60) return 'just now';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
        return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    // ── Init ──────────────────────────────────────────────────────────────

    startPolling();

})();
