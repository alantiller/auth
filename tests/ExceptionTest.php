<?php declare(strict_types=1);

namespace Alantiller\Auth\Tests;

use Alantiller\Auth\Client;
use Alantiller\Auth\Exceptions\BaseException;
use Alantiller\Auth\Exceptions\ConfigurationException;
use Alantiller\Auth\Exceptions\DatabaseException;
use Alantiller\Auth\Exceptions\EncryptionException;
use Alantiller\Auth\Exceptions\InvalidArgumentException;
use Alantiller\Auth\Exceptions\StoredDataException;
use Alantiller\Auth\Exceptions\TransactionException;
use Alantiller\Auth\Exceptions\UserNotFoundException;
use Alantiller\Auth\Exceptions\ValidationException;
use Alantiller\Auth\Internal\Totp;
use PDO;
use PDOException;
use PHPUnit\Framework\TestCase;
use RuntimeException;

require_once __DIR__ . '/Support.php';

/** Verify structured failures, their causes, and transaction rollback behavior. */
final class ExceptionTest extends TestCase
{
    /** @var PDO The isolated in-memory test database. */
    private PDO $pdo;

    /** @var TestClient A client with encryption configured and a fixed clock. */
    private TestClient $auth;

    /** Create a database using the README's caller-managed SQLite schema. */
    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $readme = file_get_contents(dirname(__DIR__) . '/README.md');
        check(is_string($readme));
        preg_match_all('/```sql\n(.*?)\n```/s', $readme, $matches);
        equal(2, count($matches[1]));
        $this->pdo->exec($matches[1][1]);
        $this->auth = new TestClient($this->pdo, ['encryption_key' => base64_encode(random_bytes(32))]);
    }

    /** Verify exception metadata and PHP's standard constructor compatibility. */
    public function test_exception_fields_and_previous_cause(): void
    {
        $cause = new RuntimeException('Original cause');
        $exception = new ValidationException('Invalid email', 42, $cause, field: 'email', context: ['max_bytes' => 254]);
        self::assertInstanceOf(InvalidArgumentException::class, $exception);
        self::assertInstanceOf(BaseException::class, $exception);
        self::assertSame(42, $exception->getCode());
        self::assertSame($cause, $exception->getPrevious());
        self::assertSame('validation_error', $exception->errorCode);
        self::assertSame('email', $exception->field);
        self::assertSame(['max_bytes' => 254], $exception->context);
        self::assertSame([
            'error_code' => 'validation_error',
            'message' => 'Invalid email',
            'field' => 'email',
            'context' => ['max_bytes' => 254],
        ], $exception->toArray());
        self::assertArrayNotHasKey('trace', $exception->toArray());
        self::assertArrayNotHasKey('previous', $exception->toArray());
        self::assertSame('custom_error', (new BaseException(errorCode: 'custom_error'))->errorCode);
        self::assertSame('invalid_argument', (new InvalidArgumentException())->errorCode);
    }

    /** Verify validation names the input without including a submitted password. */
    public function test_validation_metadata_does_not_include_credentials(): void
    {
        $password = 'bad-secret';
        $exception = throws(ValidationException::class, fn () => $this->auth->register_user('Jane', 'Doe', 'jane@example.com', $password));
        self::assertSame('password', $exception->field);
        self::assertSame(['min_bytes' => 12, 'max_bytes' => 72], $exception->context);
        self::assertStringNotContainsString($password, json_encode($exception->toArray(), JSON_THROW_ON_ERROR));
        $exception = throws(ValidationException::class, fn () => $this->auth->create_user('', 'Doe', 'jane@example.com', 'a-long-unique-password'));
        self::assertSame('firstname', $exception->field);
        $exception = throws(ValidationException::class, fn () => $this->auth->get_user_by_email('invalid-email'));
        self::assertSame('email', $exception->field);
    }

    /** Verify configuration errors remain catchable as InvalidArgumentException. */
    public function test_configuration_errors_have_option_metadata(): void
    {
        $exception = throws(ConfigurationException::class, fn () => new Client($this->pdo, ['auth_token_ttl' => 0]));
        self::assertInstanceOf(InvalidArgumentException::class, $exception);
        self::assertSame('configuration_error', $exception->errorCode);
        self::assertSame('auth_token_ttl', $exception->field);
        $exception = throws(ConfigurationException::class, fn () => new Client($this->pdo, ['encryption_key' => 'bad-key']));
        self::assertSame('encryption_key', $exception->field);
        $exception = throws(ConfigurationException::class, fn () => (new Client($this->pdo))->begin_two_factor_setup(1));
        self::assertSame('encryption_key', $exception->field);
    }

    /** Verify missing account getters include the requested identifier. */
    public function test_missing_user_getters_have_a_specific_exception(): void
    {
        $exception = throws(UserNotFoundException::class, fn () => $this->auth->get_preferences(99));
        self::assertSame('user_not_found', $exception->errorCode);
        self::assertSame('userId', $exception->field);
        self::assertSame(['user_id' => 99], $exception->context);
        self::assertNull($this->auth->get_user(99));
        error('user_not_found', $this->auth->update_user(99, ['firstname' => 'Missing']));
    }

    /** Verify PDO failures are wrapped and do not leave a partially created user. */
    public function test_database_errors_preserve_causes_and_roll_back(): void
    {
        $this->pdo->exec('DROP TABLE tokens');
        $exception = throws(DatabaseException::class, fn () => $this->auth->register_user('Jane', 'Doe', 'jane@example.com', 'a-long-unique-password'));
        self::assertInstanceOf(PDOException::class, $exception->getPrevious());
        self::assertSame('database_error', $exception->errorCode);
        self::assertSame('execute', $exception->context['operation']);
        self::assertArrayHasKey('sql_state', $exception->context);
        self::assertStringNotContainsString('a-long-unique-password', json_encode($exception->toArray(), JSON_THROW_ON_ERROR));
        self::assertSame(0, (int) column($this->pdo, 'SELECT COUNT(*) FROM users'));
        self::assertFalse($this->pdo->inTransaction());
    }

    /** Verify outer transactions are rejected without taking ownership of them. */
    public function test_application_transaction_is_preserved(): void
    {
        $this->pdo->beginTransaction();
        try {
            $exception = throws(TransactionException::class, fn () => $this->auth->revoke_token('invalid'));
            self::assertSame('transaction_error', $exception->errorCode);
            self::assertSame(['operation' => 'begin'], $exception->context);
            self::assertTrue($this->pdo->inTransaction());
        } finally {
            $this->pdo->rollBack();
        }
    }

    /** Verify malformed preference JSON and incompatible roots are classified. */
    public function test_corrupt_preferences_are_stored_data_errors(): void
    {
        $result = ok($this->auth->create_user('Jane', 'Doe', 'jane@example.com', 'a-long-unique-password'));
        $id = $result['user']['id'];
        foreach (['{broken', '[]', 'null', '"scalar"'] as $json) {
            $statement = $this->pdo->prepare('UPDATE users SET preferences = ? WHERE id = ?');
            check($statement !== false);
            $statement->execute([$json, $id]);
            $exception = throws(StoredDataException::class, fn () => $this->auth->get_preferences($id));
            self::assertSame('stored_data_error', $exception->errorCode);
            self::assertSame('preferences', $exception->field);
            if ($json === '{broken') {
                self::assertInstanceOf(\JsonException::class, $exception->getPrevious());
            }
        }
    }

    /** Verify failed decryption does not issue tokens or consume a TOTP counter. */
    public function test_corrupt_encrypted_secret_is_an_encryption_error(): void
    {
        $user = ok($this->auth->register_user('Jane', 'Doe', 'jane@example.com', 'a-long-unique-password'));
        ok($this->auth->verify_email($user['token']));
        $setup = ok($this->auth->begin_two_factor_setup($user['user']['id']));
        $counter = intdiv($this->auth->clock, 30);
        ok($this->auth->confirm_two_factor_setup($user['user']['id'], Totp::code($setup['secret'], $counter)));
        $this->pdo->exec("UPDATE users SET two_factor_secret = 'invalid-ciphertext'");
        $this->auth->clock += 30;
        $exception = throws(EncryptionException::class, fn () => $this->auth->authenticate('jane@example.com', 'a-long-unique-password', Totp::code($setup['secret'], $counter + 1)));
        self::assertSame('encryption_error', $exception->errorCode);
        self::assertSame('two_factor_secret', $exception->field);
        self::assertSame($counter, (int) column($this->pdo, 'SELECT two_factor_last_counter FROM users'));
        self::assertSame(0, (int) column($this->pdo, 'SELECT COUNT(*) FROM tokens'));
        self::assertFalse($this->pdo->inTransaction());
    }

    /** Verify invalid recovery-code records never produce authentication success. */
    public function test_corrupt_recovery_codes_are_stored_data_errors(): void
    {
        $user = ok($this->auth->register_user('Jane', 'Doe', 'jane@example.com', 'a-long-unique-password'));
        ok($this->auth->verify_email($user['token']));
        $setup = ok($this->auth->begin_two_factor_setup($user['user']['id']));
        $codes = ok($this->auth->confirm_two_factor_setup($user['user']['id'], Totp::code($setup['secret'], intdiv($this->auth->clock, 30))));
        foreach (['{broken', '{}', '["invalid-hash"]', '[42]', 'null'] as $json) {
            $statement = $this->pdo->prepare('UPDATE users SET two_factor_recovery_codes = ?');
            check($statement !== false);
            $statement->execute([$json]);
            $exception = throws(StoredDataException::class, fn () => $this->auth->authenticate('jane@example.com', 'a-long-unique-password', $codes['recovery_codes'][0]));
            self::assertSame('two_factor_recovery_codes', $exception->field);
            self::assertSame(0, (int) column($this->pdo, 'SELECT COUNT(*) FROM tokens'));
        }
    }
}
