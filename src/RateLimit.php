<?php

class RateLimit
{
    public static function check(Config $config, string $key, int $maxAttempts, int $windowSeconds): bool
    {
        $st = $config->db()->prepare("SELECT attempts, window_start FROM rate_limits WHERE rate_key = :k");
        $st->execute([':k' => $key]);
        $row = $st->fetch();

        if (!$row) return true;

        // Window expired — reset
        if ($row['window_start'] + $windowSeconds < time()) {
            return true;
        }

        return $row['attempts'] < $maxAttempts;
    }

    public static function increment(Config $config, string $key, int $windowSeconds): void
    {
        $now = time();
        $st = $config->db()->prepare("SELECT attempts, window_start FROM rate_limits WHERE rate_key = :k");
        $st->execute([':k' => $key]);
        $row = $st->fetch();

        if (!$row || ($row['window_start'] + $windowSeconds < $now)) {
            // New window
            $config->db()->prepare(
                "INSERT INTO rate_limits (rate_key, attempts, window_start) VALUES (:k, 1, :now)
                 ON DUPLICATE KEY UPDATE attempts = 1, window_start = :now2"
            )->execute([':k' => $key, ':now' => $now, ':now2' => $now]);
        } else {
            $config->db()->prepare(
                "UPDATE rate_limits SET attempts = attempts + 1 WHERE rate_key = :k"
            )->execute([':k' => $key]);
        }
    }

    public static function reset(Config $config, string $key): void
    {
        $config->db()->prepare("DELETE FROM rate_limits WHERE rate_key = :k")->execute([':k' => $key]);
    }

    public static function cleanup(Config $config): int
    {
        $st = $config->db()->prepare("DELETE FROM rate_limits WHERE window_start < :cutoff");
        $st->execute([':cutoff' => time() - 7200]);
        return $st->rowCount();
    }

    public static function getRemainingSeconds(Config $config, string $key, int $windowSeconds): int
    {
        $st = $config->db()->prepare("SELECT window_start FROM rate_limits WHERE rate_key = :k");
        $st->execute([':k' => $key]);
        $row = $st->fetch();
        if (!$row) return 0;
        $remaining = ($row['window_start'] + $windowSeconds) - time();
        return max(0, $remaining);
    }
}
