<?php

class SSO
{
    // $requestedIdentity is the client app's own account name for the
    // person trying to log in (e.g. the username just typed into its
    // login form) -- shown on the approver's Pending Logins card ("Claiming
    // to be X") AND, since 2026-09-02, enforced server-side in
    // approveChallenge(): a logged-in ErnsAuth user can only approve a
    // challenge whose requested_identity matches their OWN ErnsAuth
    // username. There is deliberately no cross-app identity-mapping table
    // anywhere in this system (client apps' account namespaces are not
    // ErnsAuth's business to know about) -- the enforceable rule is
    // exactly "your ErnsAuth username must literally be the client app's
    // username", nothing more elaborate. Client apps that can't guarantee
    // that convention simply don't get the enforcement (see
    // approveChallenge()'s empty-requested_identity fallback). Still
    // truncated defensively even though the column itself already caps
    // length, and always rendered through the same h() escaping every
    // other user-supplied value on this dashboard already gets
    // (web/js/dashboard.js) -- treat this as attacker-controllable text,
    // because for a compromised or malicious client app, it is.
    public static function createChallenge(Config $config, string $clientAppId, string $clientIp, string $clientUa, string $requestedIdentity = ''): array
    {
        $requestedIdentity = $requestedIdentity !== '' ? mb_substr($requestedIdentity, 0, 128) : null;
        // A browser starting a new challenge -- whether a normal page load,
        // a tab it left open and reloaded, or an explicit "new request"
        // click after losing sync -- means any challenge it created earlier
        // is stale and will never be approved; the user has moved on. Left
        // alone, a stale-but-still-pending row sits in the approver's
        // Pending Logins list indistinguishable from the live one among the
        // decoy numbers until it naturally expires (challenge_ttl), which is
        // exactly the "lost sync" scenario this is fixing. Superseding here
        // -- unconditionally, on every create, not just a manual retry --
        // keeps at most one pending challenge per (app, IP, user agent).
        // Scoped to that triple rather than just client_app_id so a second
        // person on the same app from a different device isn't affected;
        // client_ip alone can occasionally collide (NAT/shared network) with
        // a different person's own still-pending attempt, but the worst case
        // is that unapproved attempt has to retry -- not a security issue.
        $superseded = 0;
        if ($clientIp !== '') {
            $st = $config->db()->prepare(
                "UPDATE sso_challenges
                    SET status = 'expired'
                  WHERE status = 'pending'
                    AND client_app_id = :app_id
                    AND client_ip = :ip
                    AND client_user_agent = :ua"
            );
            $st->execute([':app_id' => $clientAppId, ':ip' => $clientIp, ':ua' => $clientUa]);
            $superseded = $st->rowCount();
        }

        $id = bin2hex(random_bytes(16));
        $number = random_int(10, 99);
        $now = time();
        $expiresAt = $now + $config->get('challenge_ttl', 300);

        $st = $config->db()->prepare(
            "INSERT INTO sso_challenges (id, client_app_id, challenge_number, client_ip, client_user_agent, requested_identity, status, created_at, expires_at)
             VALUES (:id, :app_id, :number, :ip, :ua, :requested_identity, 'pending', :created_at, :expires_at)"
        );
        $st->execute([
            ':id'         => $id,
            ':app_id'     => $clientAppId,
            ':number'     => $number,
            ':ip'         => $clientIp,
            ':ua'         => $clientUa,
            ':requested_identity' => $requestedIdentity,
            ':created_at' => $now,
            ':expires_at' => $expiresAt,
        ]);

        return [
            'challenge_id'     => $id,
            'challenge_number' => $number,
            'expires_at'       => $expiresAt,
            'superseded_count' => $superseded,
        ];
    }

    public static function pollChallenge(Config $config, string $challengeId, string $clientAppId): array
    {
        // Scoped to the polling app's own challenges. Without client_app_id
        // in the WHERE clause, any app with a valid API key could poll --
        // and read back the auth_code of -- a challenge created by a
        // *different* app, if it ever learned the challenge_id through some
        // other channel (logs, a referrer leak, a compromised app). The ID
        // is 128-bit random and not practically guessable on its own, but
        // this shouldn't be the only thing enforcing the app boundary.
        $st = $config->db()->prepare("SELECT * FROM sso_challenges WHERE id = :id AND client_app_id = :app_id");
        $st->execute([':id' => $challengeId, ':app_id' => $clientAppId]);
        $row = $st->fetch();

        if (!$row) {
            return ['status' => 'not_found'];
        }

        // Auto-expire
        if ($row['status'] === 'pending' && $row['expires_at'] < time()) {
            $config->db()->prepare("UPDATE sso_challenges SET status = 'expired' WHERE id = :id AND status = 'pending'")
                ->execute([':id' => $challengeId]);
            return ['status' => 'expired'];
        }

        $result = ['status' => $row['status']];
        if ($row['status'] === 'approved' && $row['auth_code']) {
            $result['auth_code'] = $row['auth_code'];
        }
        return $result;
    }

    public static function getPendingChallenges(Config $config): array
    {
        $now = time();
        // First expire old ones
        $config->db()->prepare(
            "UPDATE sso_challenges SET status = 'expired' WHERE status = 'pending' AND expires_at < :now"
        )->execute([':now' => $now]);

        $st = $config->db()->prepare(
            "SELECT c.id, c.challenge_number, c.client_ip, c.client_user_agent, c.requested_identity, c.created_at, c.expires_at,
                    a.label AS app_label, a.icon_emoji AS app_emoji
             FROM sso_challenges c
             JOIN client_apps a ON c.client_app_id = a.id
             WHERE c.status = 'pending' AND c.expires_at > :now
             ORDER BY c.created_at DESC"
        );
        $st->execute([':now' => $now]);
        return $st->fetchAll();
    }

    public static function generateDecoys(int $correctNumber, int $count = 3): array
    {
        $numbers = [$correctNumber];
        while (count($numbers) < $count + 1) {
            $n = random_int(10, 99);
            if (!in_array($n, $numbers, true)) {
                $numbers[] = $n;
            }
        }
        shuffle($numbers);
        return $numbers;
    }

    // $approverUsername is the ErnsAuth username of whoever is clicking
    // approve (the session's own account -- never client-supplied). When
    // the challenge carries a requested_identity (see createChallenge()'s
    // docblock), this is the actual security check: only the ErnsAuth
    // account whose own username matches it may approve, checked here,
    // server-side, at the moment of approval -- not left to the approver
    // noticing the "Claiming to be X" text on their own, and not deferred
    // to the client app to catch after the fact. A challenge with no
    // requested_identity (an older/simpler client integration, or the
    // plain non-mandatory-username flow) skips this check entirely, same
    // as before this existed.
    public static function approveChallenge(Config $config, string $challengeId, int $selectedNumber, string $userId, string $approverUsername = ''): array
    {
        $st = $config->db()->prepare(
            "SELECT * FROM sso_challenges WHERE id = :id AND status = 'pending' AND expires_at > :now"
        );
        $st->execute([':id' => $challengeId, ':now' => time()]);
        $row = $st->fetch();

        if (!$row) {
            return ['error' => 'Challenge not found or expired'];
        }

        if ((int)$row['challenge_number'] !== $selectedNumber) {
            return ['error' => 'wrong_number'];
        }

        if (!empty($row['requested_identity']) && strcasecmp($row['requested_identity'], $approverUsername) !== 0) {
            return ['error' => 'identity_mismatch'];
        }

        $authCode = bin2hex(random_bytes(16));
        $config->db()->prepare(
            "UPDATE sso_challenges SET status = 'approved', approved_by = :uid, auth_code = :code WHERE id = :id"
        )->execute([':uid' => $userId, ':code' => $authCode, ':id' => $challengeId]);

        return ['success' => true];
    }

    public static function rejectChallenge(Config $config, string $challengeId, string $userId): void
    {
        $config->db()->prepare(
            "UPDATE sso_challenges SET status = 'rejected', approved_by = :uid WHERE id = :id AND status = 'pending'"
        )->execute([':uid' => $userId, ':id' => $challengeId]);
    }

    public static function exchangeCode(Config $config, string $authCode, string $clientAppId): array
    {
        // Scoped to the exchanging app's own challenges -- same reasoning
        // as pollChallenge() above: an auth_code is 128-bit random and not
        // practically guessable, but the app boundary shouldn't rest on
        // that alone.
        $st = $config->db()->prepare(
            "SELECT c.*, u.username, u.email, u.display_name
             FROM sso_challenges c
             JOIN users u ON c.approved_by = u.id
             WHERE c.auth_code = :code AND c.status = 'approved' AND c.client_app_id = :app_id"
        );
        $st->execute([':code' => $authCode, ':app_id' => $clientAppId]);
        $row = $st->fetch();

        if (!$row) {
            return ['error' => 'Invalid or expired auth code'];
        }

        // Check auth_code_ttl
        $ttl = $config->get('auth_code_ttl', 60);
        if ($row['created_at'] + $config->get('challenge_ttl', 300) + $ttl < time()) {
            return ['error' => 'Auth code expired'];
        }

        // Nullify auth_code (single-use) -- conditioned on the code still
        // matching, and checked via rowCount, not assumed. The plain
        // unconditional UPDATE this replaced left a gap between the SELECT
        // above and this write: two exchange_code calls racing on the same
        // valid code could both pass the SELECT before either nullified it,
        // both getting back a successful exchange for the same one-time
        // code. Re-matching auth_code here means only whichever request's
        // UPDATE lands first (they serialize on InnoDB's row lock) actually
        // clears it; the loser's WHERE no longer matches and rowCount is 0.
        $upd = $config->db()->prepare(
            "UPDATE sso_challenges SET auth_code = NULL WHERE id = :id AND auth_code = :code"
        );
        $upd->execute([':id' => $row['id'], ':code' => $authCode]);
        if ($upd->rowCount() === 0) {
            return ['error' => 'Invalid or expired auth code'];
        }

        return [
            'user_id'      => $row['approved_by'],
            'username'     => $row['username'],
            'email'        => $row['email'],
            'display_name' => $row['display_name'],
        ];
    }

    public static function cleanExpired(Config $config): int
    {
        $now = time();
        $st = $config->db()->prepare(
            "UPDATE sso_challenges SET status = 'expired' WHERE status = 'pending' AND expires_at < :now"
        );
        $st->execute([':now' => $now]);
        $expired = $st->rowCount();

        // Cleanup old records (> 24 hours)
        $config->db()->prepare("DELETE FROM sso_challenges WHERE created_at < :cutoff")
            ->execute([':cutoff' => $now - 86400]);

        return $expired;
    }
}
