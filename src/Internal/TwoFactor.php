<?php declare(strict_types=1);

namespace Alantiller\Auth\Internal;

use Alantiller\Auth\Exceptions\EncryptionException;
use Alantiller\Auth\Exceptions\StoredDataException;
use Alantiller\Auth\Exceptions\ConfigurationException;

/**
 * Handle authenticator-secret encryption and second-factor matching.
 *
 * The helper retains only encryption configuration. Client owns account locks
 * and persists accepted code counters or consumed recovery codes atomically.
 *
 * @internal Applications should access two-factor operations through Client.
 */
final class TwoFactor
{
    /**
     * The decoded Sodium encryption key, or null when not configured.
     *
     * @var string|null
     */
    private ?string $key = null;

    /**
     * Initialize the helper with an optional encoded encryption key.
     *
     * The key is configuration only; no current user or login state is retained.
     *
     * @param mixed $encodedKey A Base64-encoded 32-byte Sodium key, or null to leave it unconfigured.
     *
     * @throws ConfigurationException If the supplied encryption key is not valid Base64 for 32 bytes.
     */
    public function __construct(mixed $encodedKey)
    {
        if ($encodedKey !== null) {
            $key = is_string($encodedKey) ? base64_decode($encodedKey, true) : false;
            if ($key === false || strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
                throw new ConfigurationException('encryption_key must be a base64-encoded 32-byte key.', field: 'encryption_key');
            }
            $this->key = $key;
        }
    }

    /**
     * Get the configured encryption key or reject a missing configuration.
     *
     * @return string The decoded 32-byte Sodium encryption key.
     *
     * @throws ConfigurationException If no encryption key is configured.
     */
    public function requireKey(): string
    {
        if ($this->key === null) {
            throw new ConfigurationException('Configure encryption_key before using two-factor authentication.', field: 'encryption_key');
        }
        return $this->key;
    }

    /**
     * Encrypt an authenticator secret using a fresh random nonce.
     *
     * The nonce and authenticated ciphertext are stored together as Base64.
     *
     * @param string $secret The raw authenticator secret to encrypt.
     * @return string The Base64-encoded nonce and encrypted secret.
     *
     * @throws ConfigurationException If no encryption key is configured.
     */
    public function encrypt(string $secret): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return base64_encode($nonce . sodium_crypto_secretbox($secret, $nonce, $this->requireKey()));
    }

    /**
     * Decrypt and authenticate a stored authenticator secret.
     *
     * Malformed ciphertext or a mismatched encryption key is rejected.
     *
     * @param string $encrypted The Base64-encoded nonce and authenticated ciphertext.
     * @return string The decrypted authenticator secret.
     *
     * @throws ConfigurationException If no encryption key is configured.
     * @throws EncryptionException If the stored ciphertext is malformed or cannot be decrypted.
     */
    public function decrypt(string $encrypted): string
    {
        $data = base64_decode($encrypted, true);
        if ($data === false || strlen($data) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES) {
            throw new EncryptionException('Invalid stored two-factor secret.', field: 'two_factor_secret');
        }
        // Authenticate the ciphertext before returning the decrypted secret.
        $secret = sodium_crypto_secretbox_open(
            substr($data, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            substr($data, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            $this->requireKey()
        );
        if ($secret === false) {
            throw new EncryptionException('Cannot decrypt the two-factor secret. Check encryption_key.', field: 'two_factor_secret');
        }
        return $secret;
    }

    /**
     * Validate a second factor and return the account changes that consume it.
     *
     * No database write or login state is kept here. Client must save the changes
     * under its account lock before committing successful authentication.
     *
     * @param array<string, mixed> $user The stored account row, including internal authentication fields.
     * @param string $otp The authenticator code or an unused recovery code; preserve leading zeros.
     * @param int $now The current Unix time in seconds.
     * @return array<string, int|string>|null The new replay counter or recovery hashes, or null if the factor is invalid.
     *
     * @throws ConfigurationException If authenticator configuration or the secret format is invalid.
     * @throws EncryptionException If the authenticator secret cannot be decrypted.
     * @throws StoredDataException If the stored recovery-code JSON is invalid.
     */
    public function match(array $user, string $otp, int $now): ?array
    {
        if (preg_match('/^[0-9]{6}$/D', $otp)) {
            $counter = Totp::match(
                $this->decrypt($user['two_factor_secret']), $otp, $now,
                $user['two_factor_last_counter'] === null ? null : (int) $user['two_factor_last_counter']
            );
            return $counter === null ? null : ['two_factor_last_counter' => $counter];
        }
        // Recovery codes tolerate surrounding whitespace and letter case.
        $otp = strtolower(trim($otp));
        if (!preg_match('/^[a-f0-9]{10}-[a-f0-9]{10}$/D', $otp)) {
            return null;
        }
        try {
            $hashes = json_decode($user['two_factor_recovery_codes'] ?? '[]', false, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new StoredDataException('Stored recovery codes contain invalid JSON.', previous: $exception, field: 'two_factor_recovery_codes');
        }
        if (!is_array($hashes) || !array_is_list($hashes)) {
            throw new StoredDataException('Stored recovery codes must be a JSON list.', field: 'two_factor_recovery_codes');
        }
        foreach ($hashes as $hash) {
            if (!is_string($hash) || preg_match('/^[a-f0-9]{64}$/D', $hash) !== 1) {
                throw new StoredDataException('Stored recovery codes must contain SHA-256 hashes.', field: 'two_factor_recovery_codes');
            }
        }
        $candidate = hash('sha256', $otp);
        foreach ($hashes as $index => $hash) {
            if (hash_equals($hash, $candidate)) {
                // Return the remaining hashes; Client saves them in its transaction.
                unset($hashes[$index]);
                return ['two_factor_recovery_codes' => json_encode(array_values($hashes), JSON_THROW_ON_ERROR)];
            }
        }
        return null;
    }

    /**
     * Generate ten random recovery codes and their SHA-256 hashes.
     *
     * Raw codes are returned for one-time display; only hashes should be stored.
     *
     * @return array{0: list<string>, 1: list<string>} The raw recovery codes followed by their corresponding hashes.
     */
    public function recoveryCodes(): array
    {
        $codes = [];
        for ($i = 0; $i < 10; $i++) {
            $random = bin2hex(random_bytes(10));
            $codes[] = substr($random, 0, 10) . '-' . substr($random, 10);
        }
        return [$codes, array_map(fn (string $code): string => hash('sha256', $code), $codes)];
    }
}
