<?php

/**
 * VersionCheck — compares a local ernsauth client checkout (e.g. a
 * lib/ernsauth clone in an integrating app) against the latest commit on
 * GitHub for the branch it was cloned from, so the app can prompt an
 * admin to update rather than silently drifting from upstream.
 *
 * Vendored alongside ErnsAuthClient.php -- ships in the same client/
 * directory, so any app cloning ernsauth's client library gets this too.
 * "Version" here is a git commit, not a semver number: this repo is
 * consumed as a git clone pinned to a branch (see README.md -- `stable`
 * carries the latest stable release), so a newer commit on that branch
 * *is* a newer version of the package.
 *
 * Usage:
 *   $result = VersionCheck::check(__DIR__ . '/..'); // path to the clone root
 *   if ($result['status'] === 'update_available') {
 *       // show an admin-facing notice: `cd lib/ernsauth && git pull`
 *   }
 */
class VersionCheck
{
    public static function check(
        string $localClonePath,
        string $repoUrl = 'https://github.com/evrokas/ernsauth.git',
        ?string $branch = null,
        int $timeoutSeconds = 3
    ): array {
        if (!is_dir($localClonePath . '/.git')) {
            return ['status' => 'unknown', 'reason' => 'not a git checkout'];
        }

        $local = self::run(['git', '-C', $localClonePath, 'rev-parse', 'HEAD'], $timeoutSeconds);
        if ($local === null) {
            return ['status' => 'unknown', 'reason' => 'could not read local commit'];
        }

        // No branch given -- use whichever branch the clone actually sits
        // on rather than assuming 'stable', so this still works correctly
        // if someone deliberately pinned the clone elsewhere. Only falls
        // back to 'stable' on detached HEAD (rev-parse would just return
        // the literal string "HEAD" in that case, not a branch name).
        if ($branch === null) {
            $detected = self::run(['git', '-C', $localClonePath, 'rev-parse', '--abbrev-ref', 'HEAD'], $timeoutSeconds);
            $branch = ($detected && $detected !== 'HEAD') ? $detected : 'stable';
        }

        // A reachable remote with no such branch still exits 0 with empty
        // output (not a failure) -- run() only returns null on an actual
        // process/network failure, so that case falls through to the
        // "branch not found" check below instead of being misreported as
        // unreachable.
        $remoteLine = self::run(['git', 'ls-remote', $repoUrl, $branch], $timeoutSeconds);
        if ($remoteLine === null) {
            return ['status' => 'unknown', 'reason' => 'could not reach GitHub', 'branch' => $branch];
        }
        $remote = trim(explode("\t", $remoteLine)[0] ?? '');
        if ($remote === '') {
            return ['status' => 'unknown', 'reason' => "branch '{$branch}' not found on remote", 'branch' => $branch];
        }

        return [
            'status'        => $local === $remote ? 'up_to_date' : 'update_available',
            'branch'        => $branch,
            'local_commit'  => $local,
            'remote_commit' => $remote,
        ];
    }

    /**
     * Runs $cmd (argv array, no shell involved) with a hard timeout. Null
     * means the process itself failed (couldn't start, timed out, non-zero
     * exit) -- a successful run with empty output (e.g. ls-remote against a
     * branch that doesn't exist) returns "" instead, so callers can tell
     * "couldn't check" apart from "checked, found nothing".
     */
    private static function run(array $cmd, int $timeoutSeconds): ?string
    {
        if (!function_exists('proc_open')) {
            return null;
        }

        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $fullCmd = array_merge(['timeout', (string)$timeoutSeconds], $cmd);
        $proc = @proc_open($fullCmd, $descriptors, $pipes);
        if (!is_resource($proc)) {
            return null;
        }

        $out = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($proc);

        if ($exitCode !== 0 || $out === false) {
            return null;
        }
        return trim($out);
    }
}
