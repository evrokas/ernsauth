<?php

class TOTP
{
    private const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function generateSecret(): string
    {
        return self::base32Encode(random_bytes(20));
    }

    public static function generateCode(string $base32Secret, ?int $timestamp = null): string
    {
        $timeStep = (int) floor(($timestamp ?? time()) / 30);
        $msg = pack('J', $timeStep);
        $key = self::base32Decode($base32Secret);
        $hmac = hash_hmac('sha1', $msg, $key, true);

        $offset = ord($hmac[19]) & 0x0F;
        $code = (
            (ord($hmac[$offset])     & 0x7F) << 24 |
            (ord($hmac[$offset + 1]) & 0xFF) << 16 |
            (ord($hmac[$offset + 2]) & 0xFF) << 8  |
            (ord($hmac[$offset + 3]) & 0xFF)
        ) % 1000000;

        return str_pad((string) $code, 6, '0', STR_PAD_LEFT);
    }

    public static function verify(string $base32Secret, string $code, int $window = 1): bool
    {
        $now = time();
        for ($i = -$window; $i <= $window; $i++) {
            $expected = self::generateCode($base32Secret, $now + ($i * 30));
            if (hash_equals($expected, $code)) {
                return true;
            }
        }
        return false;
    }

    public static function getProvisioningUri(string $secret, string $label, string $issuer = 'ErnsAuth'): string
    {
        return sprintf(
            'otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=6&period=30',
            rawurlencode($issuer),
            rawurlencode($label),
            $secret,
            rawurlencode($issuer)
        );
    }

    public static function generateBackupCodes(int $count = 10): array
    {
        $plaintexts = [];
        $hashes = [];
        for ($i = 0; $i < $count; $i++) {
            $code = str_pad((string) random_int(0, 99999999), 8, '0', STR_PAD_LEFT);
            $plaintexts[] = $code;
            $hashes[] = hash('sha256', $code);
        }
        return ['plaintexts' => $plaintexts, 'hashes' => $hashes];
    }

    public static function base32Encode(string $data): string
    {
        $binary = '';
        for ($i = 0; $i < strlen($data); $i++) {
            $binary .= str_pad(decbin(ord($data[$i])), 8, '0', STR_PAD_LEFT);
        }

        $result = '';
        for ($i = 0; $i < strlen($binary); $i += 5) {
            $chunk = substr($binary, $i, 5);
            if (strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            }
            $result .= self::BASE32_ALPHABET[bindec($chunk)];
        }

        return $result;
    }

    public static function base32Decode(string $base32): string
    {
        $base32 = strtoupper(rtrim($base32, '='));
        $binary = '';
        for ($i = 0; $i < strlen($base32); $i++) {
            $pos = strpos(self::BASE32_ALPHABET, $base32[$i]);
            if ($pos === false) continue;
            $binary .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }

        $result = '';
        for ($i = 0; $i + 8 <= strlen($binary); $i += 8) {
            $result .= chr(bindec(substr($binary, $i, 8)));
        }

        return $result;
    }
}
