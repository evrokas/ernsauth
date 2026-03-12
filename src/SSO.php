<?php

class SSO
{
    public static function createChallenge(Config $config, string $clientAppId, string $clientIp, string $clientUa): array
    {
        $id = bin2hex(random_bytes(16));
        $number = random_int(10, 99);
        $now = time();
        $expiresAt = $now + $config->get('challenge_ttl', 300);

        $st = $config->db()->prepare(
            "INSERT INTO sso_challenges (id, client_app_id, challenge_number, client_ip, client_user_agent, status, created_at, expires_at)
             VALUES (:id, :app_id, :number, :ip, :ua, 'pending', :created_at, :expires_at)"
        );
        $st->execute([
            ':id'         => $id,
            ':app_id'     => $clientAppId,
            ':number'     => $number,
            ':ip'         => $clientIp,
            ':ua'         => $clientUa,
            ':created_at' => $now,
            ':expires_at' => $expiresAt,
        ]);

        return [
            'challenge_id'     => $id,
            'challenge_number' => $number,
            'expires_at'       => $expiresAt,
        ];
    }

    public static function pollChallenge(Config $config, string $challengeId): array
    {
        $st = $config->db()->prepare("SELECT * FROM sso_challenges WHERE id = :id");
        $st->execute([':id' => $challengeId]);
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
            "SELECT c.id, c.challenge_number, c.client_ip, c.client_user_agent, c.created_at, c.expires_at,
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

    public static function approveChallenge(Config $config, string $challengeId, int $selectedNumber, string $userId): array
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

    public static function exchangeCode(Config $config, string $authCode): array
    {
        $st = $config->db()->prepare(
            "SELECT c.*, u.username, u.email, u.display_name
             FROM sso_challenges c
             JOIN users u ON c.approved_by = u.id
             WHERE c.auth_code = :code AND c.status = 'approved'"
        );
        $st->execute([':code' => $authCode]);
        $row = $st->fetch();

        if (!$row) {
            return ['error' => 'Invalid or expired auth code'];
        }

        // Check auth_code_ttl
        $ttl = $config->get('auth_code_ttl', 60);
        if ($row['created_at'] + $config->get('challenge_ttl', 300) + $ttl < time()) {
            return ['error' => 'Auth code expired'];
        }

        // Nullify auth_code (single-use)
        $config->db()->prepare("UPDATE sso_challenges SET auth_code = NULL WHERE id = :id")
            ->execute([':id' => $row['id']]);

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
