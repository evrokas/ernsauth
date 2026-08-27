<?php

class RateLimit
{
    /**
     * Atomically records one attempt for $key and reports whether the
     * caller is still within $maxAttempts for the current $windowSeconds
     * window (creating or rolling the window as needed).
     *
     * This replaces the old check()-then-increment() pair. Those were two
     * separate, unlocked queries with application logic (a bcrypt verify,
     * sometimes an SMTP send) running between them -- so N requests that
     * arrived concurrently could all read the same pre-increment count
     * during their check() before any of them reached increment(), letting
     * a parallelized attacker slip more guesses through per window than
     * the configured limit. That mattered most for the 6-digit numeric
     * OTP flows, where the rate limit is the only thing standing between
     * the attempt budget and a 1-in-a-million secret.
     *
     * Fixed by making the record-an-attempt step itself the single
     * source of truth, done as one write before any sensitive work runs:
     * the INSERT/UPDATE below is a single statement, so concurrent callers
     * for the same key serialize on InnoDB's row lock rather than racing
     * on a read-then-write gap. Call this BEFORE doing the sensitive work
     * (matching how check() used to gate it), and call reset() after a
     * successful attempt exactly as before -- that part of the contract
     * is unchanged.
     */
    public static function attempt(Config $config, string $key, int $maxAttempts, int $windowSeconds): bool
    {
        $now = time();
        $db = $config->db();

        // ON DUPLICATE KEY UPDATE's IF() rolls an expired window over to a
        // fresh count of 1 in the same statement that increments a still-
        // current one, so there's no separate "reset the expired window"
        // step for another request to interleave with. PDO's real prepared
        // statements (Config sets ATTR_EMULATE_PREPARES => false) don't
        // allow reusing one named placeholder twice, hence the repeated
        // :now2/:now3/:win2 bindings for the same values below.
        $db->prepare(
            "INSERT INTO rate_limits (rate_key, attempts, window_start)
             VALUES (:k, 1, :now)
             ON DUPLICATE KEY UPDATE
               attempts = IF(window_start + :win < :now2, 1, attempts + 1),
               window_start = IF(window_start + :win2 < :now3, :now4, window_start)"
        )->execute([
            ':k'    => $key,
            ':now'  => $now,
            ':win'  => $windowSeconds,
            ':now2' => $now,
            ':win2' => $windowSeconds,
            ':now3' => $now,
            ':now4' => $now,
        ]);

        // Read back the count our own (now-committed, autocommit mode)
        // write just produced. Any other request whose increment for this
        // same key raced with ours already serialized against it above, so
        // this reflects every attempt recorded up to this point in the
        // database's actual commit order -- not a stale pre-write value.
        $st = $db->prepare("SELECT attempts FROM rate_limits WHERE rate_key = :k");
        $st->execute([':k' => $key]);
        $attempts = (int) ($st->fetchColumn() ?: 0);

        return $attempts <= $maxAttempts;
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
