# alantiller/auth

A small PHP authentication library built around a PDO connection. Manage accounts, register users, authenticate with passwords or magic links, enable authenticator-app two-factor authentication, and store extensible user preferences.

**Your application owns the database schema and token delivery.** The library never creates tables, runs migrations, sends email or SMS, builds HTTP responses, or sets cookies. It returns tokens so you can distribute them using your own services.

**`Client` is the single entry point.** Each authentication call takes all required credentials together. The client keeps no current user, pending login, or PHP session state, so you can create a fresh instance for every request. Accounts, enrollment data, token records and TOTP replay protection are stored in your database. Classes under `src/Internal` are implementation details; applications only need to use `Alantiller\Auth\Client` and catch its exceptions.

```php
$result = $auth->authenticate($email, $password, $totpCode);
```

## Contents

- [Installation and setup](#installation-and-setup)
- [Database schema](#database-schema)
- [Results and user data](#results-and-user-data)
- [Registration and email verification](#registration-and-email-verification)
- [Password authentication and sessions](#password-authentication-and-sessions)
- [Password resets](#password-resets)
- [Magic-link authentication](#magic-link-authentication)
- [Two-factor authentication](#two-factor-authentication)
- [User management](#user-management)
- [User preferences](#user-preferences)
- [Token lifecycle](#token-lifecycle)
- [Configuration](#configuration)
- [API reference](#api-reference)
- [Errors](#errors)
- [Application responsibilities](#application-responsibilities)
- [Development](#development)

## Installation and setup

Requires 64-bit PHP 8.1+, PDO with `pdo_mysql` or `pdo_sqlite`, and the Sodium extension. Supported databases are MySQL 8+ using InnoDB and SQLite 3. PostgreSQL and other PDO drivers are not supported.

When the package is available through your Composer repository:

```sh
composer require alantiller/auth
```

For a local checkout, run `composer install` and load its `vendor/autoload.php`. There are no third-party runtime packages.

PHPStan and PHPUnit are development dependencies. For a production installation, use `composer install --no-dev`.

Create the tables through your application's migrations before constructing the client (see [Database schema](#database-schema)).

```php
<?php
require __DIR__ . '/vendor/autoload.php';

use Alantiller\Auth\Client;

$pdo = new PDO(
    'mysql:host=localhost;dbname=my_app;charset=utf8mb4',
    getenv('DB_USERNAME'),
    getenv('DB_PASSWORD'),
    [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]
);

$auth = new Client($pdo, [
    'issuer' => 'My App',
    // Optional until you use two-factor authentication:
    'encryption_key' => getenv('AUTH_ENCRYPTION_KEY') ?: null,
]);
```

Generate the encryption key **once**, keep it in your application's secret configuration, and reuse it across requests and servers:

```sh
php -r 'echo base64_encode(random_bytes(32)), PHP_EOL;'
```

Do not generate a new key in the constructor or on every request. Losing or replacing it makes existing authenticator secrets unreadable. Key rotation requires your own migration that decrypts with the old key and encrypts with the new one.

For SQLite, enable foreign keys on each connection:

```php
$pdo = new PDO('sqlite:' . __DIR__ . '/app.sqlite');
$pdo->exec('PRAGMA foreign_keys = ON');
$pdo->exec('PRAGMA busy_timeout = 5000');
$auth = new Client($pdo);
```

`Client` sets PDO's error mode to exceptions. Account changes and token validation manage their own transactions; use a connection with no active transaction. Do not wrap these calls in an outer transaction. InnoDB locks account rows during authentication and changes; concurrent SQLite writes may produce a database-busy exception. Handle transient database errors in your application's retry policy.

## Database schema

Two tables are required: `users` and `tokens`. Use these definitions in your migration tool, or translate them into its schema builder. **No schema SQL is executed by the library.** All timestamps are integer Unix seconds in UTC, not SQL datetime strings. Keep these column names; only the table names are configurable.

### `users`

| Field | MySQL type | Null/default | Purpose |
| --- | --- | --- | --- |
| `id` | `BIGINT UNSIGNED` | Primary key, auto increment | User identifier; must fit a positive PHP integer. |
| `firstname` | `VARCHAR(100)` | Required | First name, trimmed; 1–100 UTF-8 bytes. |
| `lastname` | `VARCHAR(100)` | Required | Last name, trimmed; 1–100 UTF-8 bytes. |
| `email` | `VARCHAR(254)` | Required, unique | Trimmed, lowercased email address. |
| `password_hash` | `VARCHAR(255)` | Required | PHP `password_hash()` result; never plaintext. |
| `email_verified_at` | `BIGINT` | `NULL` | Verification time; `NULL` means unverified. |
| `preferences` | `TEXT` | Required | JSON-serialized key/value object; library inserts `{}`. |
| `two_factor_secret` | `TEXT` | `NULL` | Base64 Sodium-encrypted active TOTP secret; present means enabled. |
| `two_factor_pending_secret` | `TEXT` | `NULL` | Encrypted secret awaiting enrollment confirmation. |
| `two_factor_pending_expires_at` | `BIGINT` | `NULL` | Pending enrollment expiry. |
| `two_factor_last_counter` | `BIGINT` | `NULL` | Last accepted TOTP counter, preventing code replay. |
| `two_factor_recovery_codes` | `TEXT` | `NULL` | JSON array of SHA-256 hashes of unused recovery codes. |
| `created_at` | `BIGINT` | Required | Creation time, set by the library. |
| `updated_at` | `BIGINT` | Required | Last account/preference/factor update, set by the library. |

### `tokens`

| Field | MySQL type | Null/default | Purpose |
| --- | --- | --- | --- |
| `id` | `BIGINT UNSIGNED` | Primary key, auto increment | Internal row identifier. |
| `user_id` | `BIGINT UNSIGNED` | Required, foreign key | References `users.id`, with `ON DELETE CASCADE`. |
| `type` | `VARCHAR(32)` | Required | `auth`, `password_reset`, `magic_link`, or `email_verification`. |
| `token_hash` | `CHAR(64)` | Required, unique | SHA-256 hash of the returned token. |
| `expires_at` | `BIGINT` | Required | Exclusive expiry boundary; expired when `now >= expires_at`. |
| `created_at` | `BIGINT` | Required | Token issue time. |

Create a unique index on `users.email`, a unique index on `tokens.token_hash`, an index on `tokens(user_id, type)`, and an index on `tokens.expires_at`. Tokens are deleted when consumed or revoked; there is no plaintext token or consumed flag in the database.

### MySQL migration SQL

Use InnoDB, matching foreign-key types, and a binary email/token collation. Normalize existing emails before adding the unique constraint if adapting an existing database.

```sql
CREATE TABLE users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    firstname VARCHAR(100) NOT NULL,
    lastname VARCHAR(100) NOT NULL,
    email VARCHAR(254) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email_verified_at BIGINT NULL DEFAULT NULL,
    preferences TEXT NOT NULL,
    two_factor_secret TEXT NULL DEFAULT NULL,
    two_factor_pending_secret TEXT NULL DEFAULT NULL,
    two_factor_pending_expires_at BIGINT NULL DEFAULT NULL,
    two_factor_last_counter BIGINT NULL DEFAULT NULL,
    two_factor_recovery_codes TEXT NULL DEFAULT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY users_email_unique (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    type VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY tokens_hash_unique (token_hash),
    KEY tokens_user_type_index (user_id, type),
    KEY tokens_expiry_index (expires_at),
    CONSTRAINT tokens_user_foreign FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### SQLite migration SQL

SQLite uses `INTEGER PRIMARY KEY AUTOINCREMENT` for IDs and `TEXT` for string/JSON fields. These definitions are also used by the integration tests.

```sql
PRAGMA foreign_keys = ON;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firstname TEXT NOT NULL,
    lastname TEXT NOT NULL,
    email TEXT NOT NULL COLLATE BINARY UNIQUE,
    password_hash TEXT NOT NULL,
    email_verified_at INTEGER DEFAULT NULL,
    preferences TEXT NOT NULL,
    two_factor_secret TEXT DEFAULT NULL,
    two_factor_pending_secret TEXT DEFAULT NULL,
    two_factor_pending_expires_at INTEGER DEFAULT NULL,
    two_factor_last_counter INTEGER DEFAULT NULL,
    two_factor_recovery_codes TEXT DEFAULT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX tokens_user_type_index ON tokens (user_id, type);
CREATE INDEX tokens_expiry_index ON tokens (expires_at);
```

With custom table names, update your migration's table names, foreign-key reference, and index/constraint names accordingly:

```php
$auth = new Client($pdo, [
    'users_table' => 'app_users',
    'tokens_table' => 'app_tokens',
]);
```

Table names must contain 1–64 ASCII letters, digits or underscores and start with a letter or underscore. Qualified names such as `schema.users` are not supported. Extra application columns are permitted if they are nullable or have defaults; `update_user()` only changes the documented fields. Use preferences for arbitrary profile fields.

## Results and user data

Most operations return an array containing `success`. When an account is returned, `user` contains only:

```php
[
    'id' => 1,
    'firstname' => 'Jane',
    'lastname' => 'Doe',
    'email' => 'jane@example.com',
    'email_verified_at' => null, // Unix seconds after verification
    'two_factor_enabled' => false,
    'preferences' => [],        // Deserialized PHP array
    'created_at' => 1700000000,
    'updated_at' => 1700000000,
];
```

Password hashes, encrypted secrets, replay counters and recovery-code hashes are never included in a public user result. Enrollment explicitly returns the secret and recovery codes to display to the account owner.

A typical successful login is:

```php
[
    'success' => true,
    'user' => [/* public fields above */],
    'token' => '...',       // Raw auth token: 64 lowercase hex characters
    'expires_at' => 1700604800,
];
```

An expected failure is:

```php
['success' => false, 'user' => [], 'error' => 'invalid_credentials'];
```

Token requests return `success`, an empty `user`, `token`, and `expires_at`. Registration and email changes include the updated public user along with the verification token. A missing required second-factor code returns `two_factor_required`; it issues no token and creates no pending login. Getter methods and maintenance methods have their own documented return types.

Always check `success` before using a result. Successful registration, verification, reset, enrollment or account update does **not** log the user in. Only successful `authenticate()` or `authenticate_magic_link()` calls issue auth tokens.

## Registration and email verification

```php
$result = $auth->register_user(
    'Jane',
    'Doe',
    'jane@example.com',
    'a-long-unique-password'
);

if ($result['success']) {
    $userId = $result['user']['id'];
    $verificationToken = $result['token'];
    $verificationUrl = 'https://app.example.com/verify-email?token='
        . rawurlencode($verificationToken);
    // Your application emails $verificationUrl to $result['user']['email'].
}
```

Registration creates an unverified user and returns a single-use email verification token. Password login is blocked until verification by default.

In your verification handler, pass the token received by your application:

```php
$result = $auth->verify_email($submittedToken);
```

To resend verification, first identify and authorize the intended account in your application:

```php
$result = $auth->request_email_verification($userId);
if ($result['success']) {
    $verificationToken = $result['token'];
    // Deliver this new token to the user's current email address.
}
```

Resending invalidates the previous verification token. A verified account returns `email_already_verified`.

Use `create_user()` for account creation without issuing a verification token:

```php
$result = $auth->create_user('Jane', 'Doe', 'jane@example.com', 'a-long-unique-password');
```

This also creates an **unverified** account. Call `request_email_verification()` afterwards, or explicitly choose `require_verified_email => false` in application configuration. The library does not silently mark administrator-created accounts verified.

Email addresses are trimmed, lowercased, validated with PHP's `FILTER_VALIDATE_EMAIL`, and limited to 254 bytes. Internationalized addresses must be converted to a supported ASCII form by your application. Both names are required. Passwords must contain 12–72 bytes without null bytes; the upper bound prevents bcrypt truncation. Passwords are neither trimmed nor lowercased.

## Password authentication and sessions

```php
$result = $auth->authenticate('jane@example.com', 'a-long-unique-password', $submittedCode);

if ($result['success']) {
    $authToken = $result['token'];
    $user = $result['user'];
    // Your application delivers/stores the token in its chosen session mechanism.
}
```

Supply the email, password and authenticator code together when two-factor authentication is enabled. If it is disabled, omit the code:

```php
$result = $auth->authenticate('jane@example.com', 'a-long-unique-password');
```

`$submittedCode` must be a string so leading zeros are preserved. It can be an authenticator code or an unused recovery code. An enabled account with no supplied code returns `two_factor_required`; a wrong or used code returns `invalid_two_factor_code`. Neither failure issues a token. Submit all credentials in a new call to try again. No earlier login request or shared client instance is needed.

For a later request, obtain the raw token from your application's cookie, session or `Authorization: Bearer ...` handling:

```php
$result = $auth->authenticate_token($authToken);
if ($result['success']) {
    $currentUser = $result['user'];
}
```

Auth tokens are opaque database-backed tokens, not JWTs. Validation returns the current public user and the existing expiry; it does not issue a new token or extend expiry. Multiple sessions can coexist. There is no refresh-token mechanism; authenticate again when the token expires.

Log out the current token or every token for an authorized account:

```php
$auth->revoke_token($authToken);        // Idempotent: success=true, revoked=true/false
$auth->revoke_user_tokens($userId);     // Revokes ALL purposes, including pending links
```

## Password resets

```php
$result = $auth->request_password_reset('jane@example.com');
if ($result['success']) {
    $resetUrl = 'https://app.example.com/reset-password?token='
        . rawurlencode($result['token']);
    // Your application emails $resetUrl to the requested account.
}
```

The token is returned to your trusted server code. Do not return it to the browser that requested a reset; deliver it only to the account's email address. Show the same outward response for existing and missing accounts.

In your reset form handler:

```php
$result = $auth->reset_password($submittedToken, $newPassword);
```

A successful reset consumes the reset token, replaces the password hash, clears pending two-factor enrollment, and revokes **all** account tokens. It does not verify the email address, disable active two-factor authentication, or create a session. Ask the user to log in again with the new password and their second factor if enabled.

## Magic-link authentication

```php
$result = $auth->request_magic_link('jane@example.com');
if ($result['success']) {
    $loginUrl = 'https://app.example.com/magic-login?token='
        . rawurlencode($result['token']);
    // Your application emails $loginUrl to the requested account.
}
```

In your login handler:

```php
$result = $auth->authenticate_magic_link($submittedToken, $submittedCode);
if ($result['success']) {
    $authToken = $result['token'];
}
```

A magic link proves possession of the email address and marks it verified after successful authentication. It authenticates only existing accounts; it never creates a user. An enabled second factor is still required and must be supplied in the same call as the link token.

For accounts without two-factor authentication, omit the code:

```php
$result = $auth->authenticate_magic_link($submittedToken);
```

A missing or invalid required second-factor code leaves the link usable until expiry and does not verify the email or issue an auth token. Retry by supplying the same link token and a valid code together. A successful login consumes the link. Email scanners can follow links, so have your application present a confirmation page and consume the token only on an intentional POST action.

## Two-factor authentication

Uses authenticator-app TOTP: SHA-1, six digits, 30-second periods, with one period of drift on either side. Codes follow [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238). Accepted counters cannot be reused for that account, including the code that confirms enrollment.

### Enroll an authenticator

Use a client configured with `encryption_key`. Derive the account ID from your authenticated session and require recent authentication before these operations.

```php
$setup = $auth->begin_two_factor_setup($userId);
if ($setup['success']) {
    $secret = $setup['secret'];
    $otpauthUri = $setup['otpauth_uri'];
    // Display the secret or render the URI as a QR code in your application.
}
```

Beginning setup does not enable two-factor authentication. The pending secret is encrypted in the database and expires after ten minutes by default. Starting again replaces the pending secret. An already-enabled account cannot start another enrollment.

Once the user enters a code from their authenticator:

```php
$result = $auth->confirm_two_factor_setup($userId, $submittedCode);
if ($result['success']) {
    $recoveryCodes = $result['recovery_codes'];
    // Display these ten codes once and ask the user to store them safely.
}
```

Confirmation enables two-factor authentication, clears pending setup and revokes all existing account tokens. The confirmation code has been consumed; use the next authenticator code or a recovery code for the next login.

The library returns an `otpauth://` URI and secret, but does not generate QR images, send codes, or support SMS/email second-factor delivery.

### Recovery codes

Ten random recovery codes are returned only on enrollment or regeneration. Each has the form `0123456789-abcdef0123`. Only their hashes are stored. A recovery code can replace the authenticator code in every second-factor input and is consumed after successful use. Surrounding whitespace and letter case are ignored for recovery codes.

```php
$result = $auth->authenticate($email, $password, $recoveryCode);
```

Generate a fresh set using the account's password and a current code or unused recovery code:

```php
$result = $auth->regenerate_two_factor_recovery_codes($userId, $password, $submittedCode);
if ($result['success']) {
    $newRecoveryCodes = $result['recovery_codes'];
}
```

Regeneration invalidates all old recovery codes and all account tokens. If the user loses both the authenticator and recovery codes, account recovery requires your own identity-verification/support process. A password reset does not bypass the second factor.

### Disable two-factor authentication

```php
$result = $auth->disable_two_factor($userId, $password, $submittedCode);
```

Requires the password and an unused second factor. Success clears the active/pending secrets, replay counter and recovery hashes and revokes all account tokens. Your application should require login again.

## User management

These are **trusted server-side methods**. A user ID is a lookup key, not proof of permission. Derive it from an authenticated session or perform your own administrator authorization before using it.

```php
$user = $auth->get_user($userId);                   // Public user array or null
$user = $auth->get_user_by_email('jane@example.com');

$result = $auth->update_user($userId, [
    'firstname' => 'Janet',
    'lastname' => 'Doe',
]);

$result = $auth->update_user($userId, ['email' => 'janet@example.com']);
if ($result['success'] && isset($result['token'])) {
    $verificationToken = $result['token'];
    // Deliver to $result['user']['email'], which is the new address.
}

$result = $auth->update_user($userId, ['password' => 'another-unique-password']);
$result = $auth->delete_user($userId);
```

`update_user()` accepts a nonempty array containing only `firstname`, `lastname`, `email` and/or `password`. It rejects arbitrary columns and returns the updated public user. Changing email clears verification, cancels pending two-factor enrollment, revokes all existing tokens and returns a new verification token. Changing password cancels pending enrollment and revokes all existing tokens. Name-only changes preserve tokens. Active two-factor authentication is preserved by email/password changes.

`update_user()` does not check the old password or the acting user's permissions; apply your own recent-authentication policy before calling it. For a forgotten password, use `reset_password()` instead.

`delete_user()` permanently deletes the account and its tokens in a transaction. It returns `success=true` and an empty `user`. Deleting an unknown ID returns `user_not_found`. References from your other tables remain your application's migration/deletion-policy responsibility.

## User preferences

Preferences provide extra fields without adding columns. Each operation takes a user ID and field name; add/update also take the value. They are stored together as a **JSON-serialized object** in `users.preferences`, and returned as PHP arrays/values. No PHP `unserialize()` is used.

```php
$auth->add_preference($userId, 'theme', 'dark');
$theme = $auth->get_preference($userId, 'theme'); // 'dark'
$auth->update_preference($userId, 'theme', 'light');
$auth->remove_preference($userId, 'theme');

$auth->add_preference($userId, 'notifications', [
    'email' => true,
    'sms' => false,
]);
$auth->add_preference($userId, 'timezone', 'Europe/London');
$preferences = $auth->get_preferences($userId);
```

Stored example:

```json
{"notifications":{"email":true,"sms":false},"timezone":"Europe/London"}
```

- `add_preference()` creates a new key; existing keys return `preference_exists`.
- `update_preference()` changes an existing key; missing keys return `preference_not_found`.
- `remove_preference()` deletes an existing key; missing keys return `preference_not_found`.
- Mutation results contain `success` and the updated public `user`, including `preferences`.
- `get_preference()` returns the value, or `null` for a missing key. Stored `null` also returns `null`; use `array_key_exists()` on `get_preferences()` to distinguish them.
- Preference getters throw `UserNotFoundException` (a subclass of `InvalidArgumentException`) for an unknown user; mutations return `user_not_found`.

Keys are case-sensitive, valid UTF-8, 1–100 bytes, and cannot be entirely whitespace. Values may be strings, booleans, integers, finite floats, `null`, or nested PHP arrays of those values. Objects and resources are rejected. Values must contain valid UTF-8, may nest up to 32 levels, and the complete serialized object must fit 65,535 bytes. JSON round-tripping can normalize numeric keys and number types; treat preferences as JSON data.

Preference changes lock the account inside a transaction to avoid overwriting another request's changes. The library does not reserve preference names or use them for authorization. Do not store passwords, TOTP secrets, roles that grant access, or tokens in preferences; manage security-sensitive data through dedicated application logic.

## Token lifecycle

| Purpose (`tokens.type`) | Issued by | Used by | Default lifetime | Single use? |
| --- | --- | --- | --- | --- |
| `auth` | Successful password or magic-link login, including any required second factor | `authenticate_token()` | 7 days | No; valid until expiry/revocation. |
| `password_reset` | `request_password_reset()` | `reset_password()` | 1 hour | Yes. |
| `magic_link` | `request_magic_link()` | `authenticate_magic_link()` | 15 minutes | Yes, on successful authentication. |
| `email_verification` | `register_user()`, email change, `request_email_verification()` | `verify_email()` | 24 hours | Yes. |

Raw tokens contain 32 cryptographically random bytes represented as 64 lowercase hex characters. The database stores only their SHA-256 hashes. Tokens are checked against their purpose: a reset or verification token cannot be used as an auth token. There is no method to retrieve a raw token later. If delivery fails, request a replacement.

Issuing a new non-auth token invalidates the previous token of the **same purpose** for that user. It does not remove other purposes or existing sessions. Failed authentication attempts create no tokens. Your application must enforce attempt limits, including for second-factor codes.

All token types are revoked by password changes/resets, email changes, two-factor confirmation/disabling/recovery-code regeneration, `revoke_user_tokens()`, and user deletion. Verification alone does not revoke auth sessions. `revoke_token()` can revoke any one token for which your application has the raw value.

Expired tokens are rejected even if the row still exists. Schedule cleanup using your own cron/job system:

```php
$deletedRows = $auth->prune_expired_tokens();
```

Your server owns delivery of verification/reset/magic-link tokens to the email account. It also owns secure delivery/storage of auth tokens for the requesting client. Enrollment secrets and recovery codes should only be displayed to the authenticated account owner. Keep these values out of logs and analytics.

## Configuration

All options are optional. Unknown options and invalid values throw `InvalidArgumentException`. TTL values must be integers from 1 to 31,536,000 seconds.

| Option | Default | Meaning |
| --- | --- | --- |
| `users_table` | `'users'` | Existing account table. |
| `tokens_table` | `'tokens'` | Existing token table; must differ from users table. |
| `require_verified_email` | `true` | Require verification before password/session authentication. Magic links prove email access themselves. |
| `auth_token_ttl` | `604800` | Auth token lifetime, seven days. |
| `password_reset_token_ttl` | `3600` | Reset token lifetime, one hour. |
| `magic_link_token_ttl` | `900` | Magic-link lifetime, fifteen minutes. |
| `email_verification_token_ttl` | `86400` | Verification lifetime, one day. |
| `two_factor_setup_ttl` | `600` | Pending enrollment lifetime, ten minutes. |
| `issuer` | `'My App'` | Authenticator display name; nonblank string, max 100 bytes, no colon. |
| `encryption_key` | `null` | Base64-encoded 32-byte Sodium key, required for authenticator enrollment/code verification. |

Example:

```php
$auth = new Client($pdo, [
    'auth_token_ttl' => 3600,
    'magic_link_token_ttl' => 600,
    'issuer' => 'Example App',
    'encryption_key' => getenv('AUTH_ENCRYPTION_KEY'),
]);
```

## API reference

All listed methods are on `Alantiller\Auth\Client`. Mutations and authentication operations return result arrays; explicit getter/maintenance exceptions are shown below. Parameter names are shown for clarity; examples use positional arguments.

| Method | Return / behavior |
| --- | --- |
| `__construct(PDO $pdo, array $config = [])` | Uses an existing connection and tables. |
| `create_user(string $firstname, string $lastname, string $email, string $password): array` | Creates an unverified user; no token. |
| `register_user(string $firstname, string $lastname, string $email, string $password): array` | Creates a user and returns a verification token. |
| `get_user(int $userId): ?array` | Public user or `null`. |
| `get_user_by_email(string $email): ?array` | Public user or `null`. |
| `update_user(int $userId, array $fields): array` | Updates supported fields; email change returns a verification token. |
| `delete_user(int $userId): array` | Permanently deletes user and tokens. |
| `authenticate(string $email, string $password, string $otp = ''): array` | Checks all credentials in one call; returns auth token or failure. |
| `authenticate_token(string $token): array` | Validates an auth token; returns user and expiry. |
| `revoke_token(string $token): array` | Returns `success=true` and boolean `revoked`; safe to repeat. |
| `revoke_user_tokens(int $userId): array` | Revokes all purposes for an authorized user. |
| `request_password_reset(string $email): array` | Returns a reset token for an existing account. |
| `reset_password(string $token, string $password): array` | Resets password and revokes all tokens. |
| `request_email_verification(int $userId): array` | Returns a verification token for an unverified account. |
| `verify_email(string $token): array` | Marks email verified and consumes verification tokens. |
| `request_magic_link(string $email): array` | Returns a login link token for an existing account. |
| `authenticate_magic_link(string $token, string $otp = ''): array` | Checks link and required code together; consumes link and returns auth token on success. |
| `begin_two_factor_setup(int $userId): array` | Returns `secret`, `otpauth_uri` and `expires_at` on success. |
| `confirm_two_factor_setup(int $userId, string $otp): array` | Enables second factor; returns user and ten `recovery_codes`. |
| `disable_two_factor(int $userId, string $password, string $otp): array` | Removes factor after password and factor checks. |
| `regenerate_two_factor_recovery_codes(int $userId, string $password, string $otp): array` | Replaces codes; returns user and ten new `recovery_codes`. |
| `get_preferences(int $userId): array` | Deserialized preferences; throws for missing user. |
| `get_preference(int $userId, string $field): mixed` | Value or `null`; throws for missing user. |
| `add_preference(int $userId, string $field, mixed $value): array` | Adds a key that must not already exist. |
| `update_preference(int $userId, string $field, mixed $value): array` | Updates a key that must already exist. |
| `remove_preference(int $userId, string $field): array` | Removes an existing key. |
| `prune_expired_tokens(): int` | Deletes expired token rows and returns their count. |

## Errors

Expected operational failures use `success=false` with one of these `error` values:

| Error | Meaning |
| --- | --- |
| `invalid_credentials` | Wrong email/password, or failed password check for factor management. |
| `email_exists` | Another user already has the normalized email. |
| `user_not_found` | The account does not exist. |
| `email_not_verified` | Verification is required before authentication. |
| `email_already_verified` | A verification request was made for a verified account. |
| `invalid_token` | Token is malformed, missing, expired, revoked, consumed, or for another purpose. |
| `two_factor_required` | Supply a code with the email/password or magic-link token in the same authentication call. |
| `invalid_two_factor_code` | Incorrect, previously used, or out-of-window authenticator/recovery code. |
| `two_factor_already_enabled` | Enrollment requested for an enabled account. |
| `two_factor_not_enabled` | Disabling/regenerating codes requested without an active factor. |
| `two_factor_setup_expired` | Pending enrollment missing or expired; begin again. |
| `preference_exists` | Adding an existing key. |
| `preference_not_found` | Updating/removing a missing key. |

Invalid credentials, tokens and factor codes are expected failures returned as result arrays. Malformed input and operational problems use specific exceptions in `Alantiller\Auth\Exceptions`. All library exceptions extend `BaseException`.

| Exception | `errorCode` | When it is raised |
| --- | --- | --- |
| `InvalidArgumentException` | `invalid_argument` | Compatibility parent for invalid arguments. |
| `ValidationException` | `validation_error` | Malformed email, names, new passwords, IDs or preference input. |
| `ConfigurationException` | `configuration_error` | Invalid options, table names or a missing/invalid encryption key. |
| `UserNotFoundException` | `user_not_found` | A preference getter requests an account that does not exist. |
| `DatabaseException` | `database_error` | A database operation fails, including a missing/incompatible schema. |
| `TransactionException` | `transaction_error` | An outer transaction is active or a client transaction fails. Extends `DatabaseException`. |
| `EncryptionException` | `encryption_error` | A stored authenticator secret is malformed or cannot be decrypted. |
| `StoredDataException` | `stored_data_error` | Stored preferences or recovery-code JSON is invalid or has the wrong structure. |

`ValidationException`, `ConfigurationException` and `UserNotFoundException` extend `InvalidArgumentException`, so existing catches for that class continue to work. A malformed email passed to `authenticate()` throws `ValidationException`; a well-formed email with the wrong password returns `invalid_credentials`. PHP argument type errors remain `TypeError`.

### Custom exception fields

Exceptions carry immutable, public metadata:

- `errorCode`: a stable string identifier, separate from PHP's numeric `getCode()`.
- `field`: the related input/configuration/database field, or `null` when no single field applies.
- `context`: additional details such as password length limits, a user ID, operation name or SQLSTATE. Library-generated context excludes passwords, tokens, encryption keys and SQL parameter values.

`getMessage()`, `getCode()` and `getPrevious()` work as standard PHP exception methods. Database and JSON errors retain the original exception as the previous cause. `toArray()` returns `error_code`, `message`, `field` and `context`, omitting the trace and previous exception.

```php
use Alantiller\Auth\Exceptions\DatabaseException;
use Alantiller\Auth\Exceptions\ValidationException;

try {
    $result = $auth->register_user($firstname, $lastname, $email, $password);
    if (!$result['success']) {
        // Map $result['error'] to a suitable application response.
    }
} catch (ValidationException $exception) {
    $field = $exception->field; // e.g. 'email' or 'password'
    $details = $exception->toArray();
    // Map these validation details to your form/API errors.
} catch (DatabaseException $exception) {
    $cause = $exception->getPrevious();
    // Log the cause in your trusted server diagnostics and return a generic error.
}
```

You can add your own metadata or subclass the base exception:

```php
use Alantiller\Auth\Exceptions\ValidationException;

throw new ValidationException(
    'The chosen username is unavailable.',
    errorCode: 'username_unavailable',
    field: 'username',
    context: ['rule' => 'unique']
);
```

The constructor keeps PHP's standard first three arguments (`message`, numeric `code`, `previous`). Additional named arguments are `errorCode`, `field` and `context`. Custom subclasses can override the protected `ERROR_CODE` constant to choose their default identifier. Keep sensitive values out of application-supplied context. Extra user/profile fields continue to use the [preference key/value API](#user-preferences); exception metadata does not add database columns.

Review messages and context before using `toArray()` in a public response. Do not expose database causes, encryption configuration, traces or internal account-existence errors directly to unauthenticated clients.

## Application responsibilities

The library handles password hashing, parameterized database queries, random token generation, purpose/expiry validation, token consumption/revocation, encrypted TOTP secrets, recovery-code consumption, and preference serialization. Passwords use PHP's [`password_hash()`](https://www.php.net/manual/en/function.password-hash.php) with `PASSWORD_DEFAULT` and are rehashed after successful password login when necessary.

Your application must provide:

- Migrations, database credentials, backups, and a consistent encryption key.
- Registration/login/reset/verification forms or routes and token delivery to the correct account.
- Authorization for **every** user-ID operation, including preference reads/writes and factor enrollment. Derive IDs from the authenticated account; never trust a submitted ID alone.
- Recent-authentication checks before sensitive profile, password, email, deletion or enrollment changes.
- Rate limits and attempt limits for login, token requests, enrollment and second-factor validation. The library has no built-in throttling or failed-attempt counter.
- Generic outward responses and suitable timing controls for public registration/reset/magic-link endpoints to limit account enumeration.
- HTTPS, secure cookie/session handling, CSRF protection for state changes, and input/output handling for your framework. Never consume action tokens solely because a scanner follows a GET link.
- Safe logs and token URLs: avoid leaking query tokens into analytics, referrer headers or third-party page assets. Do not send reset, magic-link or verification tokens back to the requesting browser.
- An explicit support/recovery policy for users who lose all second factors, and scheduled expired-token cleanup.

There are no roles/permissions, account suspension, social login, WebAuthn/passkeys, SMS factors, automatic delivery, or refresh tokens in this API.

## Development

```sh
composer install
composer validate --no-check-publish
composer analyse  # PHPStan static analysis
composer test     # PHPUnit behavior tests
composer check    # Both checks
```

PHPStan checks `src` and `tests` at **level 8**, targeting PHP 8.1. Its shared configuration is `phpstan.neon.dist`; no error baseline or ignored errors are used. PHPDoc documents parameters, array types, return values and custom exceptions for both IDE tooling and static analysis.

PHPUnit uses `phpunit.xml.dist` and `pdo_sqlite`. Tests create a fresh in-memory database for each case from the README's SQLite SQL, and exercise account management, token purpose/expiry/reuse, verification, password resets, magic links, TOTP reference vectors/replay protection, recovery codes, and preferences. Additional tests verify structured exception fields, original causes, corrupt stored data and database rollback. They do not create or modify your application's database. `php tests/run.php` remains an alternate PHPUnit entry point.

To run account integration tests against MySQL, provide `AUTH_TEST_MYSQL_DSN`, `AUTH_TEST_MYSQL_USER`, and `AUTH_TEST_MYSQL_PASSWORD`. Use a **dedicated empty test database**: each test creates uniquely named test tables and drops those tables afterwards. Exception-isolation tests always use SQLite.

The package declares the MIT license in `composer.json`.
