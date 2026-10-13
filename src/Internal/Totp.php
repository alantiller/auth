<?php declare(strict_types=1);

namespace Alantiller\Auth\Internal;

use Alantiller\Auth\Exceptions\ValidationException;

/**
 * Generate and validate RFC 6238 authenticator codes.
 *
 * Uses SHA-1, six digits and 30-second time periods. Client is responsible for
 * persisting the accepted counter to prevent reuse across requests.
 *
 * @internal Applications should access authentication through Client.
 */
final class Totp
{
    /**
     * The Base32 alphabet used to encode and decode authenticator secrets.
     *
     * @var string
     */
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Generate a random Base32 secret for an authenticator.
     *
     * Twenty random bytes produce a 32-character, unpadded Base32 secret.
     *
     * @return string The raw authenticator secret.
     */
    public static function secret(): string
    {
        // Encode the random bytes in five-bit groups without Base32 padding.
        $bits = '';
        foreach (str_split(random_bytes(20)) as $character) {
            $byte = ord($character);
            $bits .= str_pad(decbin($byte), 8, '0', STR_PAD_LEFT);
        }
        $secret = '';
        foreach (str_split($bits, 5) as $chunk) {
            $secret .= self::ALPHABET[intval($chunk, 2) & 31];
        }
        return $secret;
    }

    /**
     * Generate a six-digit authenticator code for a given time counter.
     *
     * Uses the RFC 6238 SHA-1 algorithm with an eight-byte counter.
     * The returned string preserves any leading zeros.
     *
     * @param string $secret The raw, 32-character Base32 authenticator secret.
     * @param int $counter The nonnegative time counter, normally floor(Unix time / 30).
     * @return string The six-digit authenticator code.
     *
     * @throws ValidationException If the secret format or counter is invalid.
     */
    public static function code(string $secret, int $counter): string
    {
        if ($counter < 0 || !preg_match('/^[A-Z2-7]{32}$/D', $secret)) {
            throw new ValidationException('Invalid TOTP secret or counter.', field: $counter < 0 ? 'counter' : 'secret');
        }
        $bits = '';
        foreach (str_split($secret) as $character) {
            $index = strpos(self::ALPHABET, $character);
            if ($index === false) {
                throw new ValidationException('Invalid character in TOTP secret.', field: 'secret');
            }
            $bits .= str_pad(decbin($index), 5, '0', STR_PAD_LEFT);
        }
        $key = '';
        foreach (str_split($bits, 8) as $chunk) {
            $key .= chr(intval($chunk, 2) & 255);
        }
        // RFC 6238 signs an unsigned eight-byte counter in network byte order.
        $message = pack('N2', intdiv($counter, 4294967296), $counter % 4294967296);
        $hash = hash_hmac('sha1', $message, $key, true);
        // Dynamic truncation selects a positive 31-bit value from the HMAC.
        $offset = ord($hash[19]) & 15;
        $value = ((ord($hash[$offset]) & 127) << 24)
            | (ord($hash[$offset + 1]) << 16)
            | (ord($hash[$offset + 2]) << 8)
            | ord($hash[$offset + 3]);
        return str_pad((string) ($value % 1000000), 6, '0', STR_PAD_LEFT);
    }

    /**
     * Find an unused time counter matching an authenticator code.
     *
     * Checks the current 30-second period, then one period either side. Counters
     * at or below the last accepted counter are rejected to prevent replay.
     *
     * @param string $secret The raw, 32-character Base32 authenticator secret.
     * @param string $code The submitted six-digit code as a string.
     * @param int $now The current Unix time in seconds.
     * @param int|null $lastCounter The last accepted counter, or null if no code has been accepted.
     * @return int|null The matching counter, or null if the code is invalid, expired or already used.
     *
     * @throws ValidationException If the secret is invalid while generating a candidate code.
     */
    public static function match(string $secret, string $code, int $now, ?int $lastCounter): ?int
    {
        if (!preg_match('/^[0-9]{6}$/D', $code)) {
            return null;
        }
        $current = intdiv($now, 30);
        // Prefer the current period and tolerate one period of clock drift.
        foreach ([$current, $current - 1, $current + 1] as $counter) {
            if ($counter >= 0 && ($lastCounter === null || $counter > $lastCounter)
                && hash_equals(self::code($secret, $counter), $code)) {
                return $counter;
            }
        }
        return null;
    }
}
