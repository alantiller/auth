<?php declare(strict_types=1);

namespace Alantiller;

use Alantiller\Auth\Exceptions\ConfigurationException;
use Alantiller\Auth\Exceptions\DatabaseException;
use Alantiller\Auth\Exceptions\TransactionException;
use Alantiller\Auth\Exceptions\UserNotFoundException;
use Alantiller\Auth\Exceptions\ValidationException;
use Alantiller\Auth\Exceptions\EncryptionException;
use Alantiller\Auth\Exceptions\StoredDataException;
use Alantiller\Auth\Internal\Preferences;
use Alantiller\Auth\Internal\Totp;
use Alantiller\Auth\Internal\TwoFactor;
use PDO;
use PDOException;
use Throwable;

/**
 * Manage users, authentication, two-factor enrollment and user preferences.
 *
 * Auth is the application entry point. Every authentication call receives all
 * required credentials, and no current user or pending login is kept in memory.
 * The application owns schema creation, authorization, token delivery and HTTP
 * handling; persistent account and token data are stored through PDO.
 */
class Auth
{
    /**
     * The PDO instance used for database interactions.
     *
     * @var PDO
     */
    protected PDO $pdo;

    /**
     * Validated authentication configuration, including default option values.
     *
     * @var array<string, mixed>
     */
    protected array $config;

    /**
     * The validated, driver-quoted name of the existing users table.
     *
     * @var string
     */
    private string $users;

    /**
     * The validated, driver-quoted name of the existing tokens table.
     *
     * @var string
     */
    private string $tokens;

    /**
     * The supported PDO driver name: mysql or sqlite.
     *
     * @var string
     */
    private string $driver;

    /**
     * Internal helper for encrypted secrets and second-factor matching.
     *
     * @var TwoFactor
     */
    private TwoFactor $twoFactor;

    /**
     * A fixed password hash used when checking credentials for an unknown email.
     *
     * Performing password verification in both cases reduces the timing
     * difference between existing and missing accounts.
     *
     * @var string
     */
    private const DUMMY_HASH = '$2y$12$xYdx.K8kam2MmK09wPZP/eCWaBMlDmXLoCGRGIXJ5fIHS7VtzGL0u';

    /**
     * Create an authentication client using an existing PDO connection.
     *
     * The application supplies the schema and configuration. No tables are created,
     * and no current user or pending login is kept on the client.
     *
     * @param PDO $pdo The existing PDO connection used for database interactions.
     * @param array<string, mixed> $config Optional authentication configuration settings.
     *
     * @throws ConfigurationException If required authentication configuration is missing or invalid.
     * @throws DatabaseException If a database operation fails.
     */
    public function __construct(PDO $pdo, array $config = [])
    {
        // Merge supported options with defaults before validating their values.
        $defaults = [
            'users_table' => 'users',
            'tokens_table' => 'tokens',
            'require_verified_email' => true,
            'auth_token_ttl' => 604800,
            'password_reset_token_ttl' => 3600,
            'magic_link_token_ttl' => 900,
            'email_verification_token_ttl' => 86400,
            'two_factor_setup_ttl' => 600,
            'issuer' => 'My App',
            'encryption_key' => null,
        ];
        if (array_diff_key($config, $defaults)) {
            throw new ConfigurationException('Unknown configuration option.', field: 'config', context: ['options' => array_keys(array_diff_key($config, $defaults))]);
        }
        $this->config = array_replace($defaults, $config);
        foreach ($this->config as $name => $value) {
            if (str_ends_with($name, '_ttl') && (!is_int($value) || $value < 1 || $value > 31536000)) {
                throw new ConfigurationException($name . ' must be an integer between 1 and 31536000 seconds.', field: $name);
            }
        }
        if (!is_bool($this->config['require_verified_email'])
            || !is_string($this->config['issuer']) || trim($this->config['issuer']) === ''
            || strlen($this->config['issuer']) > 100 || str_contains($this->config['issuer'], ':')) {
            throw new ConfigurationException('Invalid email verification policy or two-factor issuer.', field: 'config');
        }
        // Keep the supplied connection and quote identifiers for its SQL dialect.
        $this->pdo = $pdo;
        try {
            $this->driver = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $exception) {
            throw new DatabaseException('Cannot configure the PDO connection.', previous: $exception, context: ['operation' => 'configure']);
        }
        if (!in_array($this->driver, ['mysql', 'sqlite'], true)) {
            throw new ConfigurationException('Supported PDO drivers are mysql and sqlite.', field: 'pdo', context: ['driver' => $this->driver]);
        }
        $this->users = $this->identifier($this->config['users_table']);
        $this->tokens = $this->identifier($this->config['tokens_table']);
        if (strcasecmp($this->users, $this->tokens) === 0) {
            throw new ConfigurationException('Users and tokens must use different tables.', field: 'tokens_table');
        }
        // Validate the optional encryption key without starting an enrollment.
        $this->twoFactor = new TwoFactor($this->config['encryption_key']);
    }

    /**
     * Create a new, unverified user without issuing a verification token.
     *
     * The application must authorize account creation and arrange email verification
     * when required by its authentication policy.
     *
     * @param string $firstname The user's first name.
     * @param string $lastname The user's last name.
     * @param string $email The user's email address.
     * @param string $password The new plaintext password to hash and store.
     * @return array<string, mixed> The success status and public user, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    public function create_user(string $firstname, string $lastname, string $email, string $password): array
    {
        return $this->createAccount($firstname, $lastname, $email, $password, false);
    }

    /**
     * Register a new user and issue an email verification token.
     *
     * The returned raw token must be delivered to the user by the application.
     * Registration does not authenticate the new account.
     *
     * @param string $firstname The user's first name.
     * @param string $lastname The user's last name.
     * @param string $email The user's email address.
     * @param string $password The new plaintext password to hash and store.
     * @return array<string, mixed> The public user, verification token and expiry, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    public function register_user(string $firstname, string $lastname, string $email, string $password): array
    {
        return $this->createAccount($firstname, $lastname, $email, $password, true);
    }

    /**
     * Get the public user details for a user ID.
     *
     * Password hashes and internal two-factor fields are excluded.
     * The caller is responsible for authorizing access to this account.
     *
     * @param int $userId The positive ID of the user to access.
     * @return array<string, mixed>|null The public user details, or null if the user does not exist.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    public function get_user(int $userId): ?array
    {
        $user = $this->findUser($this->validId($userId));
        return $user === null ? null : $this->publicUser($user);
    }

    /**
     * Get the public user details for an email address.
     *
     * The email address is normalized before looking up the account.
     *
     * @param string $email The user's email address.
     * @return array<string, mixed>|null The public user details, or null if the user does not exist.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    public function get_user_by_email(string $email): ?array
    {
        $user = $this->findUserByEmail($this->email($email));
        return $user === null ? null : $this->publicUser($user);
    }

    /**
     * Update the supported account fields for an existing user.
     *
     * The caller must authorize access to the user ID. Password and email changes
     * revoke all account tokens and cancel pending two-factor enrollment.
     * Changing the email also clears verification and returns a new verification token.
     *
     * @param int $userId The positive ID of the user to access.
     * @param array<string, mixed> $fields The firstname, lastname, email and/or password fields to update.
     * @return array<string, mixed> The updated public user and any verification token, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    public function update_user(int $userId, array $fields): array
    {
        $this->validId($userId);
        if (!$fields || array_diff_key($fields, array_flip(['firstname', 'lastname', 'email', 'password']))) {
            throw new ValidationException('Provide firstname, lastname, email and/or password.', field: 'fields');
        }
        $changes = [];
        foreach ($fields as $name => $value) {
            if (!is_string($value)) {
                throw new ValidationException('User fields must be strings.', field: $name);
            }
            $changes[$name === 'password' ? 'password_hash' : $name] = match ($name) {
                'email' => $this->email($value),
                'password' => $this->hashPassword($value),
                default => $this->name($value, $name),
            };
        }
        try {
            return $this->transaction(function () use ($userId, $changes): array {
                $user = $this->findUser($userId, true);
                if ($user === null) {
                    return $this->failure('user_not_found');
                }
                $emailChanged = isset($changes['email']) && $changes['email'] !== $user['email'];
                if ($emailChanged) {
                    $changes['email_verified_at'] = null;
                }
                if ($emailChanged || isset($changes['password_hash'])) {
                    $changes['two_factor_pending_secret'] = null;
                    $changes['two_factor_pending_expires_at'] = null;
                }
                $this->saveUser($userId, $changes);
                if ($emailChanged || isset($changes['password_hash'])) {
                    $this->deleteUserTokens($userId);
                }
                $result = $this->success($this->requireUser($userId));
                return $emailChanged ? array_merge($result, $this->issueToken($userId, 'email_verification')) : $result;
            });
        } catch (DatabaseException $exception) {
            $cause = $exception->getPrevious();
            if ($cause instanceof PDOException && $this->emailConflict($cause)) {
                return $this->failure('email_exists');
            }
            throw $exception;
        }
    }

    /**
     * Permanently delete a user and all of their tokens.
     *
     * The caller must authorize deletion. Both the account and its token records
     * are deleted within the same transaction.
     *
     * @param int $userId The positive ID of the user to access.
     * @return array<string, mixed> The success status with an empty user array, or an error result.
     *
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     */
    public function delete_user(int $userId): array
    {
        $this->validId($userId);
        return $this->transaction(function () use ($userId): array {
            if ($this->findUser($userId, true) === null) {
                return $this->failure('user_not_found');
            }
            $this->deleteUserTokens($userId);
            $this->execute("DELETE FROM {$this->users} WHERE id = ?", [$userId]);
            return ['success' => true, 'user' => []];
        });
    }

    /**
     * Authenticate a user with their email, password and optional second factor.
     *
     * All required credentials are checked in one call. The OTP may be a TOTP code
     * or an unused recovery code. An enabled account requires a code; missing or
     * invalid codes return an error without creating a token or pending login.
     *
     * @param string $email The user's email address.
     * @param string $password The plaintext password to validate or hash.
     * @param string $otp The authenticator code or an unused recovery code; preserve leading zeros.
     * @return array<string, mixed> The public user, auth token and expiry on success, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws ConfigurationException If required authentication configuration is missing or invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws EncryptionException If a stored authenticator secret cannot be decrypted.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    public function authenticate(string $email, string $password, string $otp = ''): array
    {
        $email = $this->email($email);
        if (strlen($password) < 12 || strlen($password) > 72 || str_contains($password, "\0")) {
            return $this->failure('invalid_credentials');
        }
        return $this->transaction(function () use ($email, $password, $otp): array {
            $user = $this->findUserByEmail($email, true);
            if (!password_verify($password, $user['password_hash'] ?? self::DUMMY_HASH) || $user === null) {
                return $this->failure('invalid_credentials');
            }
            if ($this->config['require_verified_email'] && $user['email_verified_at'] === null) {
                return $this->failure('email_not_verified');
            }
            if ($user['two_factor_secret'] !== null) {
                if ($otp === '') {
                    return $this->failure('two_factor_required');
                }
                if (!$this->consumeFactor($user, $otp)) {
                    return $this->failure('invalid_two_factor_code');
                }
            }
            // Upgrade the hash only after every required credential has passed.
            if (password_needs_rehash($user['password_hash'], PASSWORD_DEFAULT)) {
                $this->saveUser((int) $user['id'], ['password_hash' => password_hash($password, PASSWORD_DEFAULT)]);
            }
            return $this->login($this->requireUser((int) $user['id']));
        });
    }

    /**
     * Authenticate an existing, unexpired auth token.
     *
     * Only tokens issued for authentication are accepted. Validation does not
     * issue a replacement token or extend the existing expiry.
     *
     * @param string $token The raw token returned by the library.
     * @return array<string, mixed> The public user and token expiry, or an invalid-token error result.
     */
    public function authenticate_token(string $token): array
    {
        return $this->transaction(function () use ($token): array {
            $context = $this->userForToken($token, 'auth');
            if ($context === null) {
                return $this->failure('invalid_token');
            }
            [$user, $row] = $context;
            if ($this->config['require_verified_email'] && $user['email_verified_at'] === null) {
                return $this->failure('invalid_token');
            }
            return array_merge($this->success($user), ['expires_at' => (int) $row['expires_at']]);
        });
    }

    /**
     * Revoke a single token using its raw value.
     *
     * This operation is idempotent and can revoke a token of any purpose.
     *
     * @param string $token The raw token returned by the library.
     * @return array{success: true, revoked: bool} Whether a matching token record was deleted.
     *
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     */
    public function revoke_token(string $token): array
    {
        return $this->transaction(function () use ($token): array {
            $revoked = $this->validToken($token)
                && $this->execute("DELETE FROM {$this->tokens} WHERE token_hash = ?", [hash('sha256', $token)])->rowCount() > 0;
            return ['success' => true, 'revoked' => $revoked];
        });
    }

    /**
     * Revoke all tokens belonging to an existing user.
     *
     * The caller must authorize access to the user ID. Auth sessions and pending
     * reset, magic-link and verification tokens are all revoked.
     *
     * @param int $userId The positive ID of the user to access.
     * @return array<string, mixed> The success status with an empty user array, or an error result.
     *
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     */
    public function revoke_user_tokens(int $userId): array
    {
        $this->validId($userId);
        return $this->transaction(function () use ($userId): array {
            if ($this->findUser($userId, true) === null) {
                return $this->failure('user_not_found');
            }
            $this->deleteUserTokens($userId);
            return ['success' => true, 'user' => []];
        });
    }

    /**
     * Issue a password reset token for an existing account.
     *
     * The application must deliver the raw token to the account owner. Issuing
     * a new reset token invalidates the previous reset token for that user.
     *
     * @param string $email The user's email address.
     * @return array<string, mixed> The raw reset token and expiry, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    public function request_password_reset(string $email): array
    {
        return $this->requestTokenByEmail($email, 'password_reset');
    }

    /**
     * Reset a password using a valid, single-use password reset token.
     *
     * Success revokes all account tokens and cancels pending two-factor enrollment.
     * Active two-factor authentication is preserved; no auth token is issued.
     *
     * @param string $token The raw token returned by the library.
     * @param string $password The new plaintext password to hash and store.
     * @return array<string, mixed> The updated public user, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    public function reset_password(string $token, string $password): array
    {
        $hash = $this->hashPassword($password);
        return $this->transaction(function () use ($token, $hash): array {
            $context = $this->userForToken($token, 'password_reset');
            if ($context === null) {
                return $this->failure('invalid_token');
            }
            [$user] = $context;
            $userId = (int) $user['id'];
            $this->saveUser($userId, [
                'password_hash' => $hash,
                'two_factor_pending_secret' => null,
                'two_factor_pending_expires_at' => null,
            ]);
            $this->deleteUserTokens($userId);
            return $this->success($this->requireUser($userId));
        });
    }

    /**
     * Issue an email verification token for an unverified user.
     *
     * The caller must authorize the request and deliver the token to the account
     * email address. A new token replaces the previous verification token.
     *
     * @param int $userId The positive ID of the user to access.
     * @return array<string, mixed> The raw verification token and expiry, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    public function request_email_verification(int $userId): array
    {
        $this->validId($userId);
        return $this->transaction(function () use ($userId): array {
            $user = $this->findUser($userId, true);
            if ($user === null) {
                return $this->failure('user_not_found');
            }
            if ($user['email_verified_at'] !== null) {
                return $this->failure('email_already_verified');
            }
            return array_merge(['success' => true, 'user' => []], $this->issueToken($userId, 'email_verification'));
        });
    }

    /**
     * Verify the current email address using a single-use verification token.
     *
     * Success records the verification time and removes the account
     * verification tokens. It does not issue an auth token.
     *
     * @param string $token The raw token returned by the library.
     * @return array<string, mixed> The verified public user, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    public function verify_email(string $token): array
    {
        return $this->transaction(function () use ($token): array {
            $context = $this->userForToken($token, 'email_verification');
            if ($context === null) {
                return $this->failure('invalid_token');
            }
            [$user] = $context;
            $userId = (int) $user['id'];
            $this->saveUser($userId, ['email_verified_at' => $user['email_verified_at'] ?? $this->now()]);
            $this->execute("DELETE FROM {$this->tokens} WHERE user_id = ? AND type = ?", [$userId, 'email_verification']);
            return $this->success($this->requireUser($userId));
        });
    }

    /**
     * Issue a magic-link token for an existing account.
     *
     * The application delivers the token to the account email address. A new
     * magic-link token replaces the previous magic-link token for that user.
     *
     * @param string $email The user's email address.
     * @return array<string, mixed> The raw magic-link token and expiry, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    public function request_magic_link(string $email): array
    {
        return $this->requestTokenByEmail($email, 'magic_link');
    }

    /**
     * Authenticate a magic-link token and any required second factor together.
     *
     * A missing or invalid required code leaves the link usable until expiry.
     * Success verifies the email address, consumes the link and issues an auth token.
     *
     * @param string $token The raw token returned by the library.
     * @param string $otp The authenticator code or an unused recovery code; preserve leading zeros.
     * @return array<string, mixed> The public user, auth token and expiry, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws ConfigurationException If required authentication configuration is missing or invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws EncryptionException If a stored authenticator secret cannot be decrypted.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    public function authenticate_magic_link(string $token, string $otp = ''): array
    {
        return $this->transaction(function () use ($token, $otp): array {
            $context = $this->userForToken($token, 'magic_link');
            if ($context === null) {
                return $this->failure('invalid_token');
            }
            [$user, $row] = $context;
            $userId = (int) $user['id'];
            if ($user['two_factor_secret'] !== null) {
                if ($otp === '') {
                    return $this->failure('two_factor_required');
                }
                if (!$this->consumeFactor($user, $otp)) {
                    return $this->failure('invalid_two_factor_code');
                }
            }
            // Possession of the emailed link proves access to the current email address.
            $this->saveUser($userId, ['email_verified_at' => $user['email_verified_at'] ?? $this->now()]);
            $this->execute("DELETE FROM {$this->tokens} WHERE id = ?", [(int) $row['id']]);
            return $this->login($this->requireUser($userId));
        });
    }

    /**
     * Begin authenticator enrollment for an existing user.
     *
     * The caller must authorize the user ID and require recent authentication.
     * A pending encrypted secret is stored, but two-factor authentication remains
     * disabled until a valid code confirms enrollment.
     *
     * @param int $userId The positive ID of the user to access.
     * @return array<string, mixed> The raw secret, otpauth URI and enrollment expiry, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    public function begin_two_factor_setup(int $userId): array
    {
        $this->validId($userId);
        $this->twoFactor->requireKey();
        return $this->transaction(function () use ($userId): array {
            $user = $this->findUser($userId, true);
            if ($user === null) {
                return $this->failure('user_not_found');
            }
            if ($user['two_factor_secret'] !== null) {
                return $this->failure('two_factor_already_enabled');
            }
            $secret = Totp::secret();
            $expiresAt = $this->now() + $this->config['two_factor_setup_ttl'];
            $this->saveUser($userId, [
                'two_factor_pending_secret' => $this->twoFactor->encrypt($secret),
                'two_factor_pending_expires_at' => $expiresAt,
            ]);
            $issuer = $this->config['issuer'];
            $uri = 'otpauth://totp/' . rawurlencode($issuer) . ':' . rawurlencode($user['email']) . '?'
                . http_build_query(['secret' => $secret, 'issuer' => $issuer, 'algorithm' => 'SHA1', 'digits' => 6, 'period' => 30], '', '&', PHP_QUERY_RFC3986);
            return ['success' => true, 'secret' => $secret, 'otpauth_uri' => $uri, 'expires_at' => $expiresAt];
        });
    }

    /**
     * Confirm authenticator enrollment using a code from the pending secret.
     *
     * Success enables two-factor authentication, consumes the code counter,
     * clears pending enrollment and revokes all account tokens.
     * Recovery codes are returned once for the application to display to the owner.
     *
     * @param int $userId The positive ID of the user to access.
     * @param string $otp The six-digit code from the pending authenticator secret.
     * @return array<string, mixed> The public user and ten raw recovery codes, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws ConfigurationException If required authentication configuration is missing or invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws EncryptionException If a stored authenticator secret cannot be decrypted.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    public function confirm_two_factor_setup(int $userId, string $otp): array
    {
        $this->validId($userId);
        return $this->transaction(function () use ($userId, $otp): array {
            $user = $this->findUser($userId, true);
            if ($user === null) {
                return $this->failure('user_not_found');
            }
            if ($user['two_factor_secret'] !== null) {
                return $this->failure('two_factor_already_enabled');
            }
            if ($user['two_factor_pending_secret'] === null || (int) $user['two_factor_pending_expires_at'] <= $this->now()) {
                return $this->failure('two_factor_setup_expired');
            }
            $counter = Totp::match($this->twoFactor->decrypt($user['two_factor_pending_secret']), $otp, $this->now(), null);
            if ($counter === null) {
                return $this->failure('invalid_two_factor_code');
            }
            [$codes, $hashes] = $this->twoFactor->recoveryCodes();
            $this->saveUser($userId, [
                'two_factor_secret' => $user['two_factor_pending_secret'],
                'two_factor_pending_secret' => null,
                'two_factor_pending_expires_at' => null,
                'two_factor_last_counter' => $counter,
                'two_factor_recovery_codes' => json_encode($hashes, JSON_THROW_ON_ERROR),
            ]);
            $this->deleteUserTokens($userId);
            return array_merge($this->success($this->requireUser($userId)), ['recovery_codes' => $codes]);
        });
    }

    /**
     * Disable two-factor authentication after checking the password and code.
     *
     * The caller must authorize the user ID. Success clears the active and pending
     * secrets, recovery codes and replay counter, and revokes all account tokens.
     *
     * @param int $userId The positive ID of the user to access.
     * @param string $password The plaintext password to validate or hash.
     * @param string $otp The authenticator code or an unused recovery code; preserve leading zeros.
     * @return array<string, mixed> The updated public user, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws ConfigurationException If required authentication configuration is missing or invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws EncryptionException If a stored authenticator secret cannot be decrypted.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    public function disable_two_factor(int $userId, string $password, string $otp): array
    {
        return $this->manageTwoFactor($userId, $password, $otp, false);
    }

    /**
     * Replace recovery codes after checking the password and second factor.
     *
     * The caller must authorize the user ID. Success invalidates the old recovery
     * codes and all account tokens. Display the new codes only to the account owner.
     *
     * @param int $userId The positive ID of the user to access.
     * @param string $password The plaintext password to validate or hash.
     * @param string $otp The authenticator code or an unused recovery code; preserve leading zeros.
     * @return array<string, mixed> The public user and ten new raw recovery codes, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws ConfigurationException If required authentication configuration is missing or invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws EncryptionException If a stored authenticator secret cannot be decrypted.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    public function regenerate_two_factor_recovery_codes(int $userId, string $password, string $otp): array
    {
        return $this->manageTwoFactor($userId, $password, $otp, true);
    }

    /**
     * Get all of the preferences stored for a user.
     *
     * The caller must authorize access to the user ID. Preferences are decoded
     * from a JSON object into a PHP array.
     *
     * @param int $userId The positive ID of the user to access.
     * @return array<array-key, mixed> The user preference key/value pairs.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     * @throws UserNotFoundException If the requested account does not exist.
     */
    public function get_preferences(int $userId): array
    {
        $user = $this->findUser($this->validId($userId));
        if ($user === null) {
            throw new UserNotFoundException('User does not exist.', field: 'userId', context: ['user_id' => $userId]);
        }
        return Preferences::decode($user['preferences']);
    }

    /**
     * Get a single preference value for a user.
     *
     * A missing key and a stored null value both return null. Use get_preferences()
     * with array_key_exists() when those cases need to be distinguished.
     *
     * @param int $userId The positive ID of the user to access.
     * @param string $field The case-sensitive preference key.
     * @return mixed The stored preference value, or null if the key is missing.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     * @throws UserNotFoundException If the requested account does not exist.
     */
    public function get_preference(int $userId, string $field): mixed
    {
        Preferences::validateField($field);
        return $this->get_preferences($userId)[$field] ?? null;
    }

    /**
     * Add a new preference key/value pair for a user.
     *
     * The caller must authorize the user ID. Existing keys return preference_exists
     * and are not overwritten. Values must be JSON-compatible.
     *
     * @param int $userId The positive ID of the user to access.
     * @param string $field The case-sensitive preference key.
     * @param mixed $value The JSON-compatible value to store.
     * @return array<string, mixed> The updated public user and preferences, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    public function add_preference(int $userId, string $field, mixed $value): array
    {
        return $this->changePreference($userId, $field, 'add', $value);
    }

    /**
     * Update an existing preference key/value pair for a user.
     *
     * The caller must authorize the user ID. Missing keys return preference_not_found.
     * Values must be JSON-compatible.
     *
     * @param int $userId The positive ID of the user to access.
     * @param string $field The case-sensitive preference key.
     * @param mixed $value The JSON-compatible value to store.
     * @return array<string, mixed> The updated public user and preferences, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    public function update_preference(int $userId, string $field, mixed $value): array
    {
        return $this->changePreference($userId, $field, 'update', $value);
    }

    /**
     * Remove an existing preference key for a user.
     *
     * The caller must authorize the user ID. Missing keys return preference_not_found.
     *
     * @param int $userId The positive ID of the user to access.
     * @param string $field The case-sensitive preference key.
     * @return array<string, mixed> The updated public user and preferences, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    public function remove_preference(int $userId, string $field): array
    {
        return $this->changePreference($userId, $field, 'remove');
    }

    /**
     * Delete all token records whose expiry has been reached.
     *
     * The application can call this method from its own scheduled cleanup job.
     * Expired tokens are rejected even before their records are removed.
     *
     * @return int The number of expired token records deleted.
     *
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     */
    public function prune_expired_tokens(): int
    {
        return $this->transaction(fn (): int => $this->execute("DELETE FROM {$this->tokens} WHERE expires_at <= ?", [$this->now()])->rowCount());
    }

    /**
     * Get the current time used for expiry and authenticator-code checks.
     *
     * This method can be overridden to provide a controlled clock in tests.
     *
     * @return int The current Unix time in seconds.
     */
    protected function now(): int
    {
        return time();
    }

    /**
     * Validate and create an account, optionally issuing a verification token.
     *
     * Account creation and optional token issuance are committed atomically.
     * A duplicate normalized email is returned as an email_exists error.
     *
     * @param string $firstname The user's first name.
     * @param string $lastname The user's last name.
     * @param string $email The user's email address.
     * @param string $password The new plaintext password to hash and store.
     * @param bool $register Whether to issue an email verification token after creation.
     * @return array<string, mixed> The public user and optional verification token, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    private function createAccount(string $firstname, string $lastname, string $email, string $password, bool $register): array
    {
        $firstname = $this->name($firstname, 'firstname');
        $lastname = $this->name($lastname, 'lastname');
        $email = $this->email($email);
        $hash = $this->hashPassword($password);
        try {
            return $this->transaction(function () use ($firstname, $lastname, $email, $hash, $register): array {
                $now = $this->now();
                $this->execute(
                    "INSERT INTO {$this->users} (firstname, lastname, email, password_hash, preferences, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    [$firstname, $lastname, $email, $hash, '{}', $now, $now]
                );
                $userId = (int) $this->pdo->lastInsertId();
                $result = $this->success($this->requireUser($userId));
                return $register ? array_merge($result, $this->issueToken($userId, 'email_verification')) : $result;
            });
        } catch (DatabaseException $exception) {
            $cause = $exception->getPrevious();
            if ($cause instanceof PDOException && $this->emailConflict($cause)) {
                return $this->failure('email_exists');
            }
            throw $exception;
        }
    }

    /**
     * Issue an action token for an existing account identified by email.
     *
     * The account is locked while replacing a previous token of the same purpose.
     *
     * @param string $email The user's email address.
     * @param string $type The token purpose: auth, password_reset, magic_link or email_verification.
     * @return array<string, mixed> The raw action token and expiry, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    private function requestTokenByEmail(string $email, string $type): array
    {
        $email = $this->email($email);
        return $this->transaction(function () use ($email, $type): array {
            $user = $this->findUserByEmail($email, true);
            if ($user === null) {
                return $this->failure('user_not_found');
            }
            return array_merge(['success' => true, 'user' => []], $this->issueToken((int) $user['id'], $type));
        });
    }

    /**
     * Generate a token and store only its SHA-256 hash.
     *
     * Call within an account transaction. Auth tokens can coexist; a new action
     * token removes previous tokens of the same purpose for this user.
     *
     * @param int $userId The positive ID of the user to access.
     * @param string $type The token purpose: auth, password_reset, magic_link or email_verification.
     * @return array{token: string, expires_at: int} The raw token and its Unix expiry time.
     *
     * @throws DatabaseException If a database operation fails.
     */
    private function issueToken(int $userId, string $type): array
    {
        // Multiple auth sessions are allowed; new action tokens invalidate their predecessors.
        if ($type !== 'auth') {
            $this->execute("DELETE FROM {$this->tokens} WHERE user_id = ? AND type = ?", [$userId, $type]);
        }
        // Return the raw token once; database records contain only its digest.
        $token = bin2hex(random_bytes(32));
        $now = $this->now();
        $expiresAt = $now + $this->config[$type === 'auth' ? 'auth_token_ttl' : $type . '_token_ttl'];
        $this->execute(
            "INSERT INTO {$this->tokens} (user_id, type, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
            [$userId, $type, hash('sha256', $token), $expiresAt, $now]
        );
        return ['token' => $token, 'expires_at' => $expiresAt];
    }

    /**
     * Build a successful authentication result and issue an auth token.
     *
     * Call only after all required credentials have been accepted.
     *
     * @param array<string, mixed> $user The stored account row, including internal authentication fields.
     * @return array<string, mixed> The public user, raw auth token and expiry.
     *
     * @throws DatabaseException If a database operation fails.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    private function login(array $user): array
    {
        return array_merge($this->success($user), $this->issueToken((int) $user['id'], 'auth'));
    }

    /**
     * Find and lock the account and token for the requested purpose.
     *
     * Lock the account before its token, then re-read the token under that lock.
     * This prevents concurrent token revocation or consumption from being missed.
     * Call within a transaction.
     *
     * @param string $token The raw token returned by the library.
     * @param string $type The token purpose: auth, password_reset, magic_link or email_verification.
     * @return array{0: array<string, mixed>, 1: array<string, mixed>}|null The stored user and token rows, or null for an invalid or expired token.
     *
     * @throws DatabaseException If a database operation fails.
     */
    private function userForToken(string $token, string $type): ?array
    {
        if (!$this->validToken($token)) {
            return null;
        }
        $hash = hash('sha256', $token);
        $row = $this->execute("SELECT * FROM {$this->tokens} WHERE token_hash = ? AND type = ?", [$hash, $type])->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            return null;
        }
        $user = $this->findUser((int) $row['user_id'], true);
        if ($user === null) {
            return null;
        }
        // Recheck under the lock in case another request consumed or revoked it.
        $row = $this->execute("SELECT * FROM {$this->tokens} WHERE token_hash = ? AND type = ?" . $this->lockClause(), [$hash, $type])->fetch(PDO::FETCH_ASSOC);
        return !$row || (int) $row['expires_at'] <= $this->now() ? null : [$user, $row];
    }

    /**
     * Disable two-factor authentication or replace its recovery codes.
     *
     * The password and second factor are checked before any account change.
     * All account tokens are revoked when the operation succeeds.
     *
     * @param int $userId The positive ID of the user to access.
     * @param string $password The plaintext password to validate or hash.
     * @param string $otp The authenticator code or an unused recovery code; preserve leading zeros.
     * @param bool $regenerate True to replace recovery codes; false to disable the second factor.
     * @return array<string, mixed> The public user and any newly generated recovery codes, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws ConfigurationException If required authentication configuration is missing or invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws EncryptionException If a stored authenticator secret cannot be decrypted.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    private function manageTwoFactor(int $userId, string $password, string $otp, bool $regenerate): array
    {
        $this->validId($userId);
        return $this->transaction(function () use ($userId, $password, $otp, $regenerate): array {
            $user = $this->findUser($userId, true);
            if ($user === null || strlen($password) < 12 || strlen($password) > 72
                || str_contains($password, "\0") || !password_verify($password, $user['password_hash'])) {
                return $this->failure('invalid_credentials');
            }
            if ($user['two_factor_secret'] === null) {
                return $this->failure('two_factor_not_enabled');
            }
            if (!$this->consumeFactor($user, $otp)) {
                return $this->failure('invalid_two_factor_code');
            }
            if ($regenerate) {
                [$codes, $hashes] = $this->twoFactor->recoveryCodes();
                $this->saveUser($userId, ['two_factor_recovery_codes' => json_encode($hashes, JSON_THROW_ON_ERROR)]);
            } else {
                $this->saveUser($userId, [
                    'two_factor_secret' => null,
                    'two_factor_pending_secret' => null,
                    'two_factor_pending_expires_at' => null,
                    'two_factor_last_counter' => null,
                    'two_factor_recovery_codes' => null,
                ]);
            }
            $this->deleteUserTokens($userId);
            $result = $this->success($this->requireUser($userId));
            return $regenerate ? array_merge($result, ['recovery_codes' => $codes]) : $result;
        });
    }

    /**
     * Validate and consume an authenticator code or recovery code.
     *
     * Call with a locked account inside a transaction. A successful match updates
     * the replay counter or removes the used recovery-code hash atomically.
     *
     * @param array<string, mixed> $user The stored account row, including internal authentication fields.
     * @param string $otp The authenticator code or an unused recovery code; preserve leading zeros.
     * @return bool Whether an unused, valid second factor was accepted.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws ConfigurationException If required authentication configuration is missing or invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws EncryptionException If a stored authenticator secret cannot be decrypted.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    private function consumeFactor(array $user, string $otp): bool
    {
        $changes = $this->twoFactor->match($user, $otp, $this->now());
        if ($changes === null) {
            return false;
        }
        $this->saveUser((int) $user['id'], $changes);
        return true;
    }

    /**
     * Add, update or remove a preference while holding the account lock.
     *
     * The complete JSON preference object is read and saved in one transaction
     * to avoid overwriting concurrent preference changes.
     *
     * @param int $userId The positive ID of the user to access.
     * @param string $field The case-sensitive preference key.
     * @param string $operation The preference operation: add, update or remove.
     * @param mixed $value The JSON-compatible value to store.
     * @return array<string, mixed> The updated public user, or an error result.
     *
     * @throws ValidationException If an input value is invalid.
     * @throws DatabaseException If a database operation fails.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    private function changePreference(int $userId, string $field, string $operation, mixed $value = null): array
    {
        $this->validId($userId);
        Preferences::validateField($field);
        if ($operation !== 'remove') {
            Preferences::validateValue($value, field: $field);
        }
        return $this->transaction(function () use ($userId, $field, $operation, $value): array {
            $user = $this->findUser($userId, true);
            if ($user === null) {
                return $this->failure('user_not_found');
            }
            $preferences = Preferences::decode($user['preferences']);
            $exists = array_key_exists($field, $preferences);
            if ($operation === 'add' && $exists) {
                return $this->failure('preference_exists');
            }
            if ($operation !== 'add' && !$exists) {
                return $this->failure('preference_not_found');
            }
            if ($operation === 'remove') {
                unset($preferences[$field]);
            } else {
                $preferences[$field] = $value;
            }
            $serialized = Preferences::encode($preferences);
            $this->saveUser($userId, ['preferences' => $serialized]);
            return $this->success($this->requireUser($userId));
        });
    }

    /**
     * Convert a stored account row into the public user representation.
     *
     * Internal password, secret, recovery-code and replay-counter fields are omitted.
     *
     * @param array<string, mixed> $user The stored account row, including internal authentication fields.
     * @return array<string, mixed> The public user details with deserialized preferences.
     *
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    private function publicUser(array $user): array
    {
        return [
            'id' => (int) $user['id'],
            'firstname' => $user['firstname'],
            'lastname' => $user['lastname'],
            'email' => $user['email'],
            'email_verified_at' => $user['email_verified_at'] === null ? null : (int) $user['email_verified_at'],
            'two_factor_enabled' => $user['two_factor_secret'] !== null,
            'preferences' => Preferences::decode($user['preferences']),
            'created_at' => (int) $user['created_at'],
            'updated_at' => (int) $user['updated_at'],
        ];
    }

    /**
     * Build a successful result containing public user details.
     *
     * @param array<string, mixed> $user The stored account row, including internal authentication fields.
     * @return array{success: true, user: array<string, mixed>} The successful operation result.
     *
     * @throws StoredDataException If a stored JSON field is corrupt or incompatible.
     */
    private function success(array $user): array
    {
        return ['success' => true, 'user' => $this->publicUser($user)];
    }

    /**
     * Build an expected operation failure without exposing account details.
     *
     * @param string $error The application-facing operation error code.
     * @return array{success: false, user: array{}, error: string} The failed operation result and its error code.
     */
    private function failure(string $error): array
    {
        return ['success' => false, 'user' => [], 'error' => $error];
    }

    /**
     * Find a stored account row by user ID, optionally locking it.
     *
     * Request a lock only from within a transaction.
     *
     * @param int $userId The positive ID of the user to access.
     * @param bool $lock Whether to request an account row lock inside a transaction.
     * @return array<string, mixed>|null The stored account row, or null if it does not exist.
     *
     * @throws DatabaseException If a database operation fails.
     */
    private function findUser(int $userId, bool $lock = false): ?array
    {
        $row = $this->execute("SELECT * FROM {$this->users} WHERE id = ?" . ($lock ? $this->lockClause() : ''), [$userId])->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    /**
     * Find a stored account row by normalized email, optionally locking it.
     *
     * Request a lock only from within a transaction.
     *
     * @param string $email The user's email address.
     * @param bool $lock Whether to request an account row lock inside a transaction.
     * @return array<string, mixed>|null The stored account row, or null if it does not exist.
     *
     * @throws DatabaseException If a database operation fails.
     */
    private function findUserByEmail(string $email, bool $lock = false): ?array
    {
        $row = $this->execute("SELECT * FROM {$this->users} WHERE email = ?" . ($lock ? $this->lockClause() : ''), [$email])->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    /**
     * Get a stored account that must still exist inside the current transaction.
     *
     * @param int $userId The account identifier to load.
     * @return array<string, mixed> The existing stored account row.
     *
     * @throws UserNotFoundException If the requested account does not exist.
     * @throws DatabaseException If a database operation fails.
     */
    private function requireUser(int $userId): array
    {
        $user = $this->findUser($userId);
        if ($user === null) {
            throw new UserNotFoundException('User does not exist.', field: 'userId', context: ['user_id' => $userId]);
        }
        return $user;
    }

    /**
     * Save internal account field changes and update the modification time.
     *
     * The caller provides validated column names and values.
     *
     * @param int $userId The positive ID of the user to access.
     * @param array<string, mixed> $changes The validated database columns and their replacement values.
     * @return void
     *
     * @throws DatabaseException If a database operation fails.
     */
    private function saveUser(int $userId, array $changes): void
    {
        $changes['updated_at'] = $this->now();
        $assignments = array_map(fn (string $column): string => $this->identifier($column) . ' = ?', array_keys($changes));
        $this->execute("UPDATE {$this->users} SET " . implode(', ', $assignments) . ' WHERE id = ?', [...array_values($changes), $userId]);
    }

    /**
     * Delete every token record belonging to a user.
     *
     * @param int $userId The positive ID of the user to access.
     * @return void
     *
     * @throws DatabaseException If a database operation fails.
     */
    private function deleteUserTokens(int $userId): void
    {
        $this->execute("DELETE FROM {$this->tokens} WHERE user_id = ?", [$userId]);
    }

    /**
     * Prepare and execute a database statement using bound parameters.
     *
     * @param string $sql The parameterized SQL statement to execute.
     * @param list<mixed> $parameters The positional values to bind to the SQL statement.
     * @return \PDOStatement The executed statement, ready for fetching or inspecting affected rows.
     *
     * @throws DatabaseException If a database operation fails.
     */
    private function execute(string $sql, array $parameters): \PDOStatement
    {
        try {
            $statement = $this->pdo->prepare($sql);
            if ($statement === false || !$statement->execute($parameters)) {
                throw new DatabaseException('A database statement could not be executed.', context: ['operation' => 'execute']);
            }
            return $statement;
        } catch (PDOException $exception) {
            throw new DatabaseException(
                'A database operation failed.',
                previous: $exception,
                context: ['operation' => 'execute', 'sql_state' => (string) $exception->getCode()]
            );
        }
    }

    /**
     * Run an operation in a transaction owned by the client.
     *
     * An existing application transaction is rejected. Exceptions roll back the
     * client transaction and are rethrown to the caller.
     *
     * @template T
     * @param callable():T $callback The operation to execute inside the transaction.
     * @return T The value returned by the callback.
     *
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     * @throws Throwable If the callback fails; its original exception is rethrown.
     */
    private function transaction(callable $callback): mixed
    {
        if ($this->pdo->inTransaction()) {
            throw new TransactionException('Use a PDO connection without an active transaction; Auth manages its own transactions.', context: ['operation' => 'begin']);
        }
        try {
            if (!$this->pdo->beginTransaction()) {
                throw new TransactionException('Cannot begin the database transaction.', context: ['operation' => 'begin']);
            }
            $result = $callback();
            if (!$this->pdo->commit()) {
                throw new TransactionException('Cannot commit the database transaction.', context: ['operation' => 'commit']);
            }
            return $result;
        } catch (Throwable $exception) {
            try {
                $this->rollbackTransaction();
            } catch (PDOException $rollbackException) {
                throw new TransactionException('Cannot roll back the database transaction.', previous: $exception,
                    context: ['operation' => 'rollback', 'sql_state' => (string) $rollbackException->getCode()]);
            }
            if ($exception instanceof PDOException) {
                throw new TransactionException('A database transaction failed.', previous: $exception,
                    context: ['operation' => 'transaction', 'sql_state' => (string) $exception->getCode()]);
            }
            throw $exception;
        }
    }

    /**
     * Roll back the client transaction if it is still active after a failure.
     *
     * @return void
     *
     * @throws PDOException If the callback fails; its original exception is rethrown.
     * @throws TransactionException If a client transaction cannot be started, committed or rolled back.
     */
    private function rollbackTransaction(): void
    {
        if ($this->pdo->inTransaction() && !$this->pdo->rollBack()) {
            throw new TransactionException('Cannot roll back the database transaction.', context: ['operation' => 'rollback']);
        }
    }

    /**
     * Get the locking clause supported by the configured database driver.
     *
     * MySQL uses row locks; SQLite coordinates writes through its transaction locks.
     *
     * @return string FOR UPDATE for MySQL, or an empty string for SQLite.
     */
    private function lockClause(): string
    {
        return $this->driver === 'mysql' ? ' FOR UPDATE' : '';
    }

    /**
     * Validate and quote a simple SQL table or column identifier.
     *
     * Identifiers must contain 1–64 ASCII letters, digits or underscores and
     * start with a letter or underscore. Qualified identifiers are not accepted.
     *
     * @param mixed $name The table or column identifier to validate.
     * @return string The validated identifier quoted for the current driver.
     *
     * @throws ConfigurationException If required authentication configuration is missing or invalid.
     */
    private function identifier(mixed $name): string
    {
        if (!is_string($name) || !preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}$/D', $name)) {
            throw new ConfigurationException('Table and column names must be simple SQL identifiers (1–64 characters).', field: 'table_name');
        }
        $quote = $this->driver === 'mysql' ? '`' : '"';
        return $quote . $name . $quote;
    }

    /**
     * Normalize and validate an email address.
     *
     * Email addresses are trimmed, lowercased and limited to 254 bytes.
     *
     * @param string $email The user's email address.
     * @return string The normalized, validated email address.
     *
     * @throws ValidationException If an input value is invalid.
     */
    private function email(string $email): string
    {
        $email = strtolower(trim($email));
        if (strlen($email) > 254 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new ValidationException('Provide a valid email address of at most 254 bytes.', field: 'email');
        }
        return $email;
    }

    /**
     * Trim and validate a required user name.
     *
     * Names must be valid UTF-8 and contain 1–100 bytes after trimming.
     *
     * @param string $name The name to validate.
     * @param string $field The account field associated with this name.
     * @return string The validated and trimmed name.
     *
     * @throws ValidationException If an input value is invalid.
     */
    private function name(string $name, string $field): string
    {
        $name = trim($name);
        if ($name === '' || strlen($name) > 100 || !preg_match('//u', $name)) {
            throw new ValidationException('Names must be valid UTF-8 and contain 1–100 bytes after trimming.', field: $field);
        }
        return $name;
    }

    /**
     * Validate a new password and hash it with PHP PASSWORD_DEFAULT.
     *
     * Passwords must contain 12–72 bytes and no null bytes. They are not trimmed.
     * The upper bound prevents bcrypt from silently truncating the password.
     *
     * @param string $password The new plaintext password to hash and store.
     * @return string The password hash to store in the database.
     *
     * @throws ValidationException If an input value is invalid.
     */
    private function hashPassword(string $password): string
    {
        if (strlen($password) < 12 || strlen($password) > 72 || str_contains($password, "\0")) {
            throw new ValidationException('Passwords must contain 12–72 bytes and no null bytes.', field: 'password', context: ['min_bytes' => 12, 'max_bytes' => 72]);
        }
        return password_hash($password, PASSWORD_DEFAULT);
    }

    /**
     * Validate a positive user identifier.
     *
     * @param int $userId The positive ID of the user to access.
     * @return int The validated user ID.
     *
     * @throws ValidationException If an input value is invalid.
     */
    private function validId(int $userId): int
    {
        if ($userId < 1) {
            throw new ValidationException('User IDs must be positive integers.', field: 'userId');
        }
        return $userId;
    }

    /**
     * Check the expected format of a raw library token.
     *
     * @param string $token The raw token returned by the library.
     * @return bool Whether the token is exactly 64 lowercase hexadecimal characters.
     */
    private function validToken(string $token): bool
    {
        return preg_match('/^[a-f0-9]{64}$/D', $token) === 1;
    }

    /**
     * Identify a duplicate-email constraint error from a supported database.
     *
     * @param PDOException $exception The database exception to inspect.
     * @return bool Whether the database exception represents an email uniqueness conflict.
     */
    private function emailConflict(PDOException $exception): bool
    {
        return ($this->driver === 'mysql' && ($exception->errorInfo[1] ?? null) === 1062
                && preg_match('/for key .*email/i', $exception->getMessage()) === 1)
            || ($this->driver === 'sqlite' && str_contains($exception->getMessage(), 'UNIQUE constraint failed:')
                && str_contains($exception->getMessage(), '.email'));
    }
}
