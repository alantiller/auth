<?php declare(strict_types=1);

namespace Alantiller\Auth\Tests;

use Alantiller\Auth;
use PHPUnit\Framework\Assert;
use Throwable;

/** Authentication client using a predictable clock for expiry and replay tests. */
final class TestAuth extends Auth
{
    /** @var int The current test time in Unix seconds. */
    public int $clock = 1700000010;

    /** @return int The current deterministic test time. */
    protected function now(): int
    {
        return $this->clock;
    }
}

/**
 * Assert a condition and communicate its narrowing to PHPStan.
 *
 * @param bool $condition The condition to check.
 * @param string $message The diagnostic message on failure.
 * @return void
 * @phpstan-assert true $condition
 */
function check(bool $condition, string $message = 'Assertion failed'): void
{
    Assert::assertTrue($condition, $message);
}

/**
 * Assert strict equality through PHPUnit's assertion counter.
 *
 * @param mixed $expected The expected value.
 * @param mixed $actual The actual value.
 * @return void
 */
function equal(mixed $expected, mixed $actual): void
{
    Assert::assertSame($expected, $actual);
}

/**
 * Check and return a successful library result.
 *
 * @param array<string, mixed> $result The operation result.
 * @return array<string, mixed> The successful result for further assertions.
 */
function ok(array $result): array
{
    equal(true, $result['success']);
    return $result;
}

/**
 * Check the expected authentication or account-operation failure.
 *
 * @param string $expected The expected error identifier.
 * @param array<string, mixed> $result The operation result.
 * @return void
 */
function error(string $expected, array $result): void
{
    equal(false, $result['success']);
    equal($expected, $result['error']);
    equal([], $result['user']);
}

/**
 * Assert an exception type and return the original instance for metadata checks.
 *
 * @template T of Throwable
 * @param class-string<T> $class The expected exception class.
 * @param callable():mixed $callback The operation that must fail.
 * @return T The exception raised by the operation.
 */
function throws(string $class, callable $callback): Throwable
{
    try {
        $callback();
    } catch (Throwable $exception) {
        if (!$exception instanceof $class) {
            Assert::fail('Expected ' . $class . ', got ' . get_class($exception));
        }
        Assert::assertInstanceOf($class, $exception);
        return $exception;
    }
    Assert::fail('Expected exception ' . $class);
}

/**
 * Read a single SQL value after verifying the statement was prepared.
 *
 * @param \PDO $pdo The test database connection.
 * @param string $sql The test-only query.
 * @return mixed The first column, or false when no row exists.
 */
function column(\PDO $pdo, string $sql): mixed
{
    $statement = $pdo->query($sql);
    check($statement !== false, 'Test query failed.');
    return $statement->fetchColumn();
}

/**
 * Read a database value that the test expects to be a string.
 *
 * @param \PDO $pdo The test database connection.
 * @param string $sql The test-only query.
 * @return string The verified string value.
 */
function stringColumn(\PDO $pdo, string $sql): string
{
    $value = column($pdo, $sql);
    check(is_string($value), 'Expected a string database value.');
    return $value;
}
