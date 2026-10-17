<?php declare(strict_types=1);

namespace Alantiller\Auth\Tests;

use Alantiller\Auth;
use Alantiller\Auth\Internal\Totp;
use Alantiller\Auth\Exceptions\BaseException;
use Alantiller\Auth\Exceptions\InvalidArgumentException;
use PDO;
use stdClass;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/Support.php';

/** Integration tests using the exact application migration schema in README.md. */
final class AuthTest extends TestCase
{
    /** @var PDO The isolated test database connection. */
    private PDO $pdo;

    /** @var TestAuth The client with a deterministic test clock. */
    private TestAuth $auth;

    /** @var array<string, mixed> The configuration shared by fresh client instances. */
    private array $config;

    /** @var list<string> The MySQL and SQLite schemas from the README. */
    private array $schemas;

    /** @var string The unique test account table name. */
    private string $usersTable;

    /** @var string The unique test token table name. */
    private string $tokensTable;

    /** @var bool Whether the optional MySQL test database is in use. */
    private bool $mysql = false;

    /** @var string A valid test password with no production credentials. */
    private string $password = 'a-long-unique-password';

    /** @var int The fixture email sequence within one isolated test. */
    private int $fixtureNumber = 0;

    /** Create a fresh database from the documented schema for each test. */
    protected function setUp(): void
    {
        $readme = file_get_contents(dirname(__DIR__) . '/README.md');
        check(is_string($readme), 'Cannot read the documented migration schema.');
        preg_match_all('/```sql\n(.*?)\n```/s', $readme, $matches);
        equal(2, count($matches[1]));
        $this->schemas = $matches[1];
        $mysqlDsn = getenv('AUTH_TEST_MYSQL_DSN');
        $this->mysql = is_string($mysqlDsn) && $mysqlDsn !== '';
        if (is_string($mysqlDsn) && $mysqlDsn !== '') {
            $this->pdo = new PDO($mysqlDsn, getenv('AUTH_TEST_MYSQL_USER') ?: '', getenv('AUTH_TEST_MYSQL_PASSWORD') ?: '', [PDO::ATTR_EMULATE_PREPARES => false]);
        } else {
            $this->pdo = new PDO('sqlite::memory:');
        }
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $suffix = $this->mysql ? '_test_' . bin2hex(random_bytes(6)) : '';
        $this->usersTable = 'users' . $suffix;
        $this->tokensTable = 'tokens' . $suffix;
        $schema = str_replace(['users', 'tokens'], [$this->usersTable, $this->tokensTable], $this->schemas[$this->mysql ? 0 : 1]);
        foreach (explode(';', $schema) as $statement) {
            if (trim($statement) !== '') {
                $this->pdo->exec($statement);
            }
        }
        $this->config = [
            'users_table' => $this->usersTable,
            'tokens_table' => $this->tokensTable,
            'encryption_key' => base64_encode(random_bytes(32)),
            'issuer' => 'Test App',
        ];
        $this->auth = new TestAuth($this->pdo, $this->config);
    }

    /** Remove only the uniquely named MySQL tables created by this test. */
    protected function tearDown(): void
    {
        if ($this->mysql) {
            $this->pdo->exec("DROP TABLE IF EXISTS `{$this->tokensTable}`");
            $this->pdo->exec("DROP TABLE IF EXISTS `{$this->usersTable}`");
        }
    }

    /**
     * Create a verified account for one integration scenario.
     *
     * @param TestAuth $auth The deterministic authentication client.
     * @return array{0: int, 1: string} The user identifier and unique email address.
     */
    private function fixture(TestAuth $auth): array
    {
        $email = 'fixture' . ++$this->fixtureNumber . '@example.com';
        $registration = ok($auth->register_user('Jane', 'Doe', $email, $this->password));
        ok($auth->verify_email($registration['token']));
        return [$registration['user']['id'], $email];
    }

    /**
     * Read a user expected to exist and assert the nullable getter result.
     *
     * @param Auth $auth The client to read from.
     * @param int $id The existing user identifier.
     * @return array<string, mixed> The public account fields.
     */
    private function user(Auth $auth, int $id): array
    {
        $user = $auth->get_user($id);
        check($user !== null, 'Expected account to exist.');
        return $user;
    }

    /** Verify rfc 6238 sha-1 reference vectors and drift/replay. */
    public function test_rfc_6238_sha_1_reference_vectors_and_drift_replay(): void
    {
        $secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
        foreach ([59 => '287082', 1111111109 => '081804', 1111111111 => '050471', 1234567890 => '005924', 2000000000 => '279037', 20000000000 => '353130'] as $time => $code) {
            equal($code, Totp::code($secret, intdiv($time, 30)));
        }
        equal(1, Totp::match($secret, '287082', 59, null));
        equal(null, Totp::match($secret, '287082', 59, 1));
        equal(1, Totp::match($secret, '287082', 89, null));
        equal(null, Totp::match($secret, '287082', 90, null));
        equal(null, Totp::match($secret, '28708x', 59, null));
        check(strlen(Totp::secret()) === 32);
    }

    /** Verify constructor does not create tables; custom table names and validation. */
    public function test_constructor_does_not_create_tables_custom_table_names_and_validation(): void
    {
        $pdo = $this->pdo;
        $config = $this->config;
        $matches = [1 => $this->schemas];
        $password = $this->password;
        $empty = new PDO('sqlite::memory:');
        new Auth($empty);
        equal(0, (int) column($empty, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'"));
        throws(InvalidArgumentException::class, fn () => new Auth($pdo, $config + ['typo' => true]));
        foreach ([['auth_token_ttl' => 0], ['auth_token_ttl' => '300'], ['users_table' => 'users; DROP TABLE users'], ['tokens_table' => $config['users_table']], ['tokens_table' => strtoupper($config['users_table'])], ['require_verified_email' => 1], ['encryption_key' => 'bad'], ['issuer' => 'bad:issuer']] as $bad) {
            throws(InvalidArgumentException::class, fn () => new Auth($pdo, array_replace($config, $bad)));
        }
        $empty->exec(str_replace(['users', 'tokens'], ['app_users', 'app_tokens'], $matches[1][1]));
        $custom = new Auth($empty, ['users_table' => 'app_users', 'tokens_table' => 'app_tokens']);
        $registered = ok($custom->register_user('Custom', 'Tables', 'custom@example.com', $password));
        ok($custom->verify_email($registered['token']));
        ok($custom->authenticate('custom@example.com', $password));
    }

    /** Verify registration, canonical emails, duplicate email, verification and safe user data. */
    public function test_registration_canonical_emails_duplicate_email_verification_and_safe_user_data(): void
    {
        $auth = $this->auth;
        $pdo = $this->pdo;
        $usersTable = $this->usersTable;
        $tokensTable = $this->tokensTable;
        $password = $this->password;
        $result = ok($auth->register_user(' Jane ', ' Doe ', ' JANE@EXAMPLE.COM ', $password));
        $id = $result['user']['id'];
        equal('jane@example.com', $result['user']['email']);
        equal('Jane', $result['user']['firstname']);
        equal(['id', 'firstname', 'lastname', 'email', 'email_verified_at', 'two_factor_enabled', 'preferences', 'created_at', 'updated_at'], array_keys($result['user']));
        $hash = stringColumn($pdo, "SELECT password_hash FROM $usersTable WHERE id = $id");
        check($hash !== $password && password_verify($password, $hash));
        $stored = stringColumn($pdo, "SELECT token_hash FROM $tokensTable WHERE user_id = $id");
        equal(hash('sha256', $result['token']), $stored);
        check($stored !== $result['token']);
        error('email_exists', $auth->create_user('Jane', 'Doe', 'JANE@EXAMPLE.COM', $password));
        error('email_not_verified', $auth->authenticate('jane@example.com', $password));
        error('invalid_token', $auth->authenticate_token($result['token']));
        ok($auth->verify_email($result['token']));
        error('invalid_token', $auth->verify_email($result['token']));
        error('email_already_verified', $auth->request_email_verification($id));
        check($this->user($auth, $id)['email_verified_at'] !== null);
        $byEmail = $auth->get_user_by_email(' JANE@EXAMPLE.COM ');
        check($byEmail !== null);
        equal($id, $byEmail['id']);
        $created = ok($auth->create_user('New', 'User', 'created@example.com', $password));
        check(!isset($created['token']));
        error('email_not_verified', $auth->authenticate('created@example.com', $password));
        $first = ok($auth->request_email_verification($created['user']['id']));
        $second = ok($auth->request_email_verification($created['user']['id']));
        error('invalid_token', $auth->verify_email($first['token']));
        ok($auth->verify_email($second['token']));
    }

    /** Verify password sessions, explicit expiry, purpose isolation and revocation. */
    public function test_password_sessions_explicit_expiry_purpose_isolation_and_revocation(): void
    {
        $auth = $this->auth;
        $password = $this->password;
        [$id, $email] = $this->fixture($auth);
        error('invalid_credentials', $auth->authenticate($email, 'wrong-long-password'));
        error('invalid_credentials', $auth->authenticate('missing@example.com', $password));
        error('invalid_credentials', $auth->authenticate($email, $password . str_repeat('x', 72)));
        $first = ok($auth->authenticate($email, $password));
        $second = ok($auth->authenticate($email, $password));
        equal($id, ok($auth->authenticate_token($first['token']))['user']['id']);
        equal($first['expires_at'], ok($auth->authenticate_token($first['token']))['expires_at']);
        error('invalid_token', $auth->reset_password($first['token'], 'new-unique-password'));
        equal(true, $auth->revoke_token($first['token'])['revoked']);
        equal(false, $auth->revoke_token($first['token'])['revoked']);
        error('invalid_token', $auth->authenticate_token($first['token']));
        ok($auth->authenticate_token($second['token']));
        $auth->clock = $second['expires_at'];
        error('invalid_token', $auth->authenticate_token($second['token']));
        check($auth->prune_expired_tokens() > 0);
        $auth->clock = 1700000010;
        $session = ok($auth->authenticate($email, $password));
        ok($auth->revoke_user_tokens($id));
        error('invalid_token', $auth->authenticate_token($session['token']));
        error('invalid_token', $auth->authenticate_token('malformed'));
    }

    /** Verify updates, duplicate rollback, security revocation and deletion. */
    public function test_updates_duplicate_rollback_security_revocation_and_deletion(): void
    {
        $auth = $this->auth;
        $password = $this->password;
        [$id, $email] = $this->fixture($auth);
        [$otherId, $otherEmail] = $this->fixture($auth);
        $session = ok($auth->authenticate($email, $password));
        ok($auth->update_user($id, ['firstname' => 'Updated']));
        ok($auth->authenticate_token($session['token']));
        error('email_exists', $auth->update_user($id, ['firstname' => 'Rolled back', 'email' => $otherEmail]));
        equal('Updated', $this->user($auth, $id)['firstname']);
        equal($email, $this->user($auth, $id)['email']);
        $reset = ok($auth->request_password_reset($email));
        $changed = ok($auth->update_user($id, ['email' => 'changed@example.com']));
        equal(null, $changed['user']['email_verified_at']);
        error('invalid_token', $auth->authenticate_token($session['token']));
        error('invalid_token', $auth->reset_password($reset['token'], 'new-unique-password'));
        ok($auth->verify_email($changed['token']));
        $session = ok($auth->authenticate('changed@example.com', $password));
        ok($auth->update_user($id, ['password' => 'new-unique-password']));
        error('invalid_token', $auth->authenticate_token($session['token']));
        error('invalid_credentials', $auth->authenticate('changed@example.com', $password));
        $session = ok($auth->authenticate('changed@example.com', 'new-unique-password'));
        ok($auth->delete_user($id));
        equal(null, $auth->get_user($id));
        error('invalid_token', $auth->authenticate_token($session['token']));
        error('user_not_found', $auth->delete_user($id));
        error('user_not_found', $auth->update_user($id, ['firstname' => 'Missing']));
        error('user_not_found', $auth->revoke_user_tokens($id));
        error('user_not_found', $auth->request_email_verification($id));
        check($auth->get_user($otherId) !== null);
    }

    /** Verify password reset replacement, single use and all-purpose revocation. */
    public function test_password_reset_replacement_single_use_and_all_purpose_revocation(): void
    {
        $auth = $this->auth;
        $password = $this->password;
        [$id, $email] = $this->fixture($auth);
        $session = ok($auth->authenticate($email, $password));
        $magic = ok($auth->request_magic_link($email));
        $first = ok($auth->request_password_reset($email));
        $second = ok($auth->request_password_reset($email));
        error('invalid_token', $auth->reset_password($first['token'], 'new-unique-password'));
        error('invalid_token', $auth->authenticate_token($second['token']));
        ok($auth->reset_password($second['token'], 'new-unique-password'));
        error('invalid_token', $auth->reset_password($second['token'], 'other-unique-password'));
        error('invalid_token', $auth->authenticate_token($session['token']));
        error('invalid_token', $auth->authenticate_magic_link($magic['token']));
        error('invalid_credentials', $auth->authenticate($email, $password));
        ok($auth->authenticate($email, 'new-unique-password'));
        error('user_not_found', $auth->request_password_reset('missing@example.com'));
    }

    /** Verify magic links verify existing email and cannot be reused. */
    public function test_magic_links_verify_existing_email_and_cannot_be_reused(): void
    {
        $auth = $this->auth;
        $password = $this->password;
        $created = ok($auth->create_user('Magic', 'User', 'magic@example.com', $password));
        $first = ok($auth->request_magic_link('magic@example.com'));
        $second = ok($auth->request_magic_link('magic@example.com'));
        error('invalid_token', $auth->authenticate_magic_link($first['token']));
        error('invalid_token', $auth->authenticate_token($second['token']));
        $login = ok($auth->authenticate_magic_link($second['token']));
        equal($created['user']['id'], $login['user']['id']);
        check($login['user']['email_verified_at'] !== null);
        ok($auth->authenticate_token($login['token']));
        error('invalid_token', $auth->authenticate_magic_link($second['token']));
        error('user_not_found', $auth->request_magic_link('missing@example.com'));
    }

    /** Verify preferences preserve nested values and implement strict add/update/remove semantics. */
    public function test_preferences_preserve_nested_values_and_implement_strict_add_update_remove_semantics(): void
    {
        $auth = $this->auth;
        $pdo = $this->pdo;
        $usersTable = $this->usersTable;
        [$id] = $this->fixture($auth);
        equal([], $auth->get_preferences($id));
        equal(null, $auth->get_preference($id, 'absent'));
        ok($auth->add_preference($id, 'theme', 'dark'));
        error('preference_exists', $auth->add_preference($id, 'theme', 'light'));
        equal('dark', $auth->get_preference($id, 'theme'));
        ok($auth->update_preference($id, 'theme', 'light'));
        error('preference_not_found', $auth->update_preference($id, 'absent', true));
        $nested = ['email' => true, 'sms' => false, 'options' => [1, 'two', null]];
        ok($auth->add_preference($id, 'notifications', $nested));
        equal($nested, $auth->get_preference($id, 'notifications'));
        ok($auth->add_preference($id, 'nullable', null));
        error('preference_exists', $auth->add_preference($id, 'nullable', 1));
        ok($auth->update_preference($id, 'nullable', false));
        equal(false, $auth->get_preference($id, 'nullable'));
        ok($auth->add_preference($id, '0', 'numeric-key'));
        equal('numeric-key', $auth->get_preference($id, '0'));
        ok($auth->remove_preference($id, 'theme'));
        error('preference_not_found', $auth->remove_preference($id, 'theme'));
        equal($nested, $auth->get_preference($id, 'notifications'));
        $stored = stringColumn($pdo, "SELECT preferences FROM $usersTable WHERE id = $id");
        check(json_decode($stored) instanceof stdClass);
        throws(InvalidArgumentException::class, fn () => $auth->add_preference($id, '', 1));
        throws(InvalidArgumentException::class, fn () => $auth->add_preference($id, 'object', new stdClass()));
        throws(InvalidArgumentException::class, fn () => $auth->add_preference($id, 'float', INF));
        throws(InvalidArgumentException::class, fn () => $auth->add_preference($id, 'utf8', "\xff"));
        throws(InvalidArgumentException::class, fn () => $auth->add_preference($id, 'oversize', str_repeat('x', 65536)));
        equal(null, $auth->get_preference($id, 'oversize'));
        $nestedTooDeep = [];
        for ($i = 0; $i < 34; $i++) { $nestedTooDeep = [$nestedTooDeep]; }
        throws(InvalidArgumentException::class, fn () => $auth->add_preference($id, 'depth', $nestedTooDeep));
        throws(InvalidArgumentException::class, fn () => $auth->get_preferences(PHP_INT_MAX));
        error('user_not_found', $auth->add_preference(PHP_INT_MAX, 'missing', 1));
        $alone = ok($auth->create_user('Empty', 'Prefs', 'empty-prefs@example.com', 'a-long-unique-password'))['user']['id'];
        ok($auth->add_preference($alone, '0', null));
        ok($auth->remove_preference($alone, '0'));
        equal('{}', column($pdo, "SELECT preferences FROM $usersTable WHERE id = $alone"));
    }

    /** Verify single-call two-factor authentication, encryption and replay protection. */
    public function test_single_call_two_factor_authentication_encryption_and_replay_protection(): void
    {
        $auth = $this->auth;
        $pdo = $this->pdo;
        $usersTable = $this->usersTable;
        $tokensTable = $this->tokensTable;
        $config = $this->config;
        $password = $this->password;
        [$id, $email] = $this->fixture($auth);
        $session = ok($auth->authenticate($email, $password));
        $setup = ok($auth->begin_two_factor_setup($id));
        check(str_starts_with($setup['otpauth_uri'], 'otpauth://totp/Test%20App:'));
        equal(false, $this->user($auth, $id)['two_factor_enabled']);
        $stored = stringColumn($pdo, "SELECT two_factor_pending_secret FROM $usersTable WHERE id = $id");
        check($stored !== $setup['secret'] && !str_contains($stored, $setup['secret']));
        $code = Totp::code($setup['secret'], intdiv($auth->clock, 30));
        error('invalid_two_factor_code', $auth->confirm_two_factor_setup($id, 'bad'));
        $confirmed = ok($auth->confirm_two_factor_setup($id, $code));
        equal(true, $confirmed['user']['two_factor_enabled']);
        equal(10, count($confirmed['recovery_codes']));
        $recovery = stringColumn($pdo, "SELECT two_factor_recovery_codes FROM $usersTable WHERE id = $id");
        check(!str_contains($recovery, $confirmed['recovery_codes'][0]));
        error('invalid_token', $auth->authenticate_token($session['token']));
        error('invalid_two_factor_code', $auth->authenticate($email, $password, $code));
        error('two_factor_already_enabled', $auth->begin_two_factor_setup($id));
        error('two_factor_already_enabled', $auth->confirm_two_factor_setup($id, $code));
        $missingCode = $auth->authenticate($email, $password);
        equal(['success' => false, 'user' => [], 'error' => 'two_factor_required'], $missingCode);
        error('invalid_two_factor_code', $auth->authenticate($email, $password, 'bad'));
        equal(0, (int) column($pdo, "SELECT COUNT(*) FROM $tokensTable WHERE user_id = $id"));
        $auth->clock += 30;
        $code = Totp::code($setup['secret'], intdiv($auth->clock, 30));
        error('invalid_credentials', $auth->authenticate($email, 'wrong-long-password', $code));
        // A fresh instance can authenticate directly, without any earlier login request.
        $fresh = new TestAuth($pdo, $config);
        $fresh->clock = $auth->clock;
        $login = ok($fresh->authenticate($email, $password, $code));
        ok($auth->authenticate_token($login['token']));
        error('invalid_two_factor_code', $auth->authenticate($email, $password, $code));
        ok($auth->authenticate($email, $password, strtoupper(' ' . $confirmed['recovery_codes'][0] . ' ')));
        error('invalid_two_factor_code', $auth->authenticate($email, $password, $confirmed['recovery_codes'][0]));
        $auth->clock = 1700000010;
    }

    /** Verify magic links require all factors in one call; reset preserves active two-factor. */
    public function test_magic_links_require_all_factors_in_one_call_reset_preserves_active_two_factor(): void
    {
        $auth = $this->auth;
        $pdo = $this->pdo;
        $tokensTable = $this->tokensTable;
        $config = $this->config;
        $password = $this->password;
        [$id, $email] = $this->fixture($auth);
        $setup = ok($auth->begin_two_factor_setup($id));
        $confirmed = ok($auth->confirm_two_factor_setup($id, Totp::code($setup['secret'], intdiv($auth->clock, 30))));
        $magic = ok($auth->request_magic_link($email));
        error('invalid_two_factor_code', $auth->authenticate_magic_link($magic['token'], 'bad'));
        $missingCode = $auth->authenticate_magic_link($magic['token']);
        equal(['success' => false, 'user' => [], 'error' => 'two_factor_required'], $missingCode);
        error('two_factor_required', $auth->authenticate_magic_link($magic['token']));
        equal(1, (int) column($pdo, "SELECT COUNT(*) FROM $tokensTable WHERE user_id = $id"));
        $fresh = new TestAuth($pdo, $config);
        ok($fresh->authenticate_magic_link($magic['token'], $confirmed['recovery_codes'][0]));
        error('invalid_token', $auth->authenticate_magic_link($magic['token'], $confirmed['recovery_codes'][1]));
        $magic = ok($auth->request_magic_link($email));
        ok($auth->authenticate_magic_link($magic['token'], $confirmed['recovery_codes'][1]));
        error('invalid_token', $auth->authenticate_magic_link($magic['token'], $confirmed['recovery_codes'][2]));
        $session = ok($auth->authenticate($email, $password, $confirmed['recovery_codes'][2]));
        $reset = ok($auth->request_password_reset($email));
        ok($auth->reset_password($reset['token'], 'new-unique-password'));
        check($this->user($auth, $id)['two_factor_enabled']);
        error('invalid_token', $auth->authenticate_token($session['token']));
        error('invalid_credentials', $auth->authenticate($email, $password, $confirmed['recovery_codes'][3]));
        error('two_factor_required', $auth->authenticate($email, 'new-unique-password'));
        ok($auth->authenticate($email, 'new-unique-password', $confirmed['recovery_codes'][3]));
    }

    /** Verify recovery-code regeneration and disabling revoke sessions and require both factors. */
    public function test_recovery_code_regeneration_and_disabling_revoke_sessions_and_require_both_factors(): void
    {
        $auth = $this->auth;
        $password = $this->password;
        [$id, $email] = $this->fixture($auth);
        $setup = ok($auth->begin_two_factor_setup($id));
        $confirmed = ok($auth->confirm_two_factor_setup($id, Totp::code($setup['secret'], intdiv($auth->clock, 30))));
        $session = ok($auth->authenticate($email, $password, $confirmed['recovery_codes'][0]));
        error('invalid_credentials', $auth->disable_two_factor($id, 'wrong-long-password', $confirmed['recovery_codes'][1]));
        error('invalid_credentials', $auth->disable_two_factor($id, $password . str_repeat('x', 72), $confirmed['recovery_codes'][1]));
        error('invalid_two_factor_code', $auth->disable_two_factor($id, $password, 'bad'));
        $new = ok($auth->regenerate_two_factor_recovery_codes($id, $password, $confirmed['recovery_codes'][1]));
        equal(10, count($new['recovery_codes']));
        error('invalid_token', $auth->authenticate_token($session['token']));
        error('invalid_two_factor_code', $auth->authenticate($email, $password, $confirmed['recovery_codes'][2]));
        $session = ok($auth->authenticate($email, $password, $new['recovery_codes'][0]));
        $disabled = ok($auth->disable_two_factor($id, $password, $new['recovery_codes'][1]));
        equal(false, $disabled['user']['two_factor_enabled']);
        error('invalid_token', $auth->authenticate_token($session['token']));
        ok($auth->authenticate($email, $password));
        error('two_factor_not_enabled', $auth->disable_two_factor($id, $password, 'bad'));
    }

    /** Verify enrollment replacement/expiry/cancellation and token expiry boundaries. */
    public function test_enrollment_replacement_expiry_cancellation_and_token_expiry_boundaries(): void
    {
        $auth = $this->auth;
        $password = $this->password;
        [$id, $email] = $this->fixture($auth);
        $first = ok($auth->begin_two_factor_setup($id));
        $second = ok($auth->begin_two_factor_setup($id));
        check($first['secret'] !== $second['secret']);
        $auth->clock = $second['expires_at'];
        error('two_factor_setup_expired', $auth->confirm_two_factor_setup($id, Totp::code($second['secret'], intdiv($auth->clock, 30))));
        $auth->clock = 1700000010;
        $setup = ok($auth->begin_two_factor_setup($id));
        ok($auth->update_user($id, ['password' => 'new-unique-password']));
        error('two_factor_setup_expired', $auth->confirm_two_factor_setup($id, Totp::code($setup['secret'], intdiv($auth->clock, 30))));
        $reset = ok($auth->request_password_reset($email));
        $auth->clock = $reset['expires_at'];
        error('invalid_token', $auth->reset_password($reset['token'], 'other-unique-password'));
        $auth->clock = 1700000010;
        $magic = ok($auth->request_magic_link($email));
        $auth->clock = $magic['expires_at'];
        error('invalid_token', $auth->authenticate_magic_link($magic['token']));
        $auth->clock = 1700000010;
        $created = ok($auth->register_user('Expiry', 'User', 'expiry@example.com', $password));
        $auth->clock = $created['expires_at'];
        error('invalid_token', $auth->verify_email($created['token']));
        $auth->clock = 1700000010;
        $setup = ok($auth->begin_two_factor_setup($id));
        ok($auth->confirm_two_factor_setup($id, Totp::code($setup['secret'], intdiv($auth->clock, 30))));
        error('two_factor_required', $auth->authenticate($email, 'new-unique-password'));
        $auth->clock += 30;
        ok($auth->authenticate($email, 'new-unique-password', Totp::code($setup['secret'], intdiv($auth->clock, 30))));
        $auth->clock = 1700000010;
    }

    /** Verify input validation, optional verification policy and transaction rollback. */
    public function test_input_validation_optional_verification_policy_and_transaction_rollback(): void
    {
        $auth = $this->auth;
        $pdo = $this->pdo;
        $config = $this->config;
        $password = $this->password;
        throws(InvalidArgumentException::class, fn () => $auth->register_user('', 'Doe', 'valid@example.com', $password));
        throws(InvalidArgumentException::class, fn () => $auth->register_user('Jane', 'Doe', 'bad-email', $password));
        throws(InvalidArgumentException::class, fn () => $auth->register_user('Jane', 'Doe', 'valid@example.com', 'short'));
        throws(InvalidArgumentException::class, fn () => $auth->register_user('Jane', 'Doe', 'valid@example.com', str_repeat('a', 73)));
        throws(InvalidArgumentException::class, fn () => $auth->register_user('Jane', 'Doe', 'valid@example.com', "long-password\0"));
        throws(InvalidArgumentException::class, fn () => $auth->get_user(0));
        [$id] = $this->fixture($auth);
        throws(InvalidArgumentException::class, fn () => $auth->update_user($id, ['email_verified_at' => 1]));
        throws(InvalidArgumentException::class, fn () => $auth->update_user($id, []));
        $unverified = ok($auth->create_user('No', 'Verification', 'no-verification@example.com', $password));
        $optional = new TestAuth($pdo, array_replace($config, ['require_verified_email' => false]));
        ok($optional->authenticate('no-verification@example.com', $password));
        $noKey = new Auth($pdo, array_replace($config, ['encryption_key' => null]));
        throws(InvalidArgumentException::class, fn () => $noKey->begin_two_factor_setup($id));
        $pdo->beginTransaction();
        try {
            throws(BaseException::class, fn () => $auth->delete_user($id));
            check($pdo->inTransaction(), 'The client must not roll back an application transaction.');
        } finally {
            $pdo->rollBack();
        }
        check($auth->get_user($id) !== null);
    }

}
