<?php
/**
 * Pure helpers for deploy/health-handler.php's client-certificate checks.
 * Kept free of the zops classes so they can be exercised on their own.
 *
 * Each returns ['level' => 'ok'|'warn'|'fail', 'detail' => string].
 */
declare(strict_types=1);

/**
 * The dashboard must REFUSE a connection that presents no client
 * certificate. Ok = the TLS handshake was refused for want of a
 * certificate. Fail = any HTTP response came back (the requirement is off,
 * e.g. the emergency switch in ernsauth-mtls.conf was left on) or the host
 * could not be reached at all.
 *
 * $extraCurlOpts is for tests (CURLOPT_RESOLVE, CURLOPT_CAINFO).
 */
function ernsauth_mtls_gate_check(string $url, array $extraCurlOpts = []): array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_NOBODY         => true,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_NOPROXY        => '*',
        // Deliberately NO CURLOPT_SSLCERT: presenting none is the point.
    ] + $extraCurlOpts);
    curl_exec($ch);
    $errno = curl_errno($ch);
    $error = curl_error($ch);
    $code  = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($code > 0) {
        return ['level' => 'fail', 'detail' => "HTTP {$code} without a client certificate -- the requirement is OFF (emergency switch left on?)"];
    }
    // 35 = TLS connect error, 56 = receive failure (TLS 1.3 reports the
    // server's "certificate required" alert this way).
    if (in_array($errno, [35, 56], true) && preg_match('/certificate|handshake|alert/i', $error)) {
        return ['level' => 'ok', 'detail' => 'handshake refused without a certificate'];
    }
    return ['level' => 'fail', 'detail' => "could not verify the gate: curl error {$errno}" . ($error !== '' ? " ({$error})" : '')];
}

/**
 * An expired CRL makes Apache refuse EVERY client certificate, so its
 * nextUpdate date is the thing to watch. Warn inside $warnDays, fail once
 * expired or unreadable.
 */
function ernsauth_crl_check(string $file, int $now, int $warnDays = 14): array
{
    if (!is_file($file)) {
        return ['level' => 'fail', 'detail' => "CRL file {$file} not found"];
    }
    $out = [];
    $rc  = 1;
    exec('openssl crl -in ' . escapeshellarg($file) . ' -noout -nextupdate 2>&1', $out, $rc);
    $line = $out[0] ?? '';
    if ($rc !== 0 || strpos($line, 'nextUpdate=') !== 0) {
        return ['level' => 'fail', 'detail' => "could not read {$file}: " . trim(implode(' ', $out))];
    }
    $next = strtotime(substr($line, strlen('nextUpdate=')));
    if ($next === false) {
        return ['level' => 'fail', 'detail' => "unparseable nextUpdate: {$line}"];
    }
    $days = (int) floor(($next - $now) / 86400);
    if ($next <= $now) {
        return ['level' => 'fail', 'detail' => 'CRL EXPIRED ' . gmdate('Y-m-d', $next) . ' -- Apache is refusing every client certificate'];
    }
    if ($days <= $warnDays) {
        return ['level' => 'warn', 'detail' => "CRL expires in {$days} days (" . gmdate('Y-m-d', $next) . ") -- run refresh-crl.sh and server-install-crl.sh"];
    }
    return ['level' => 'ok', 'detail' => "CRL valid for {$days} more days"];
}
