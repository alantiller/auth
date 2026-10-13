<?php declare(strict_types=1);

namespace Alantiller\Auth\Exceptions;

use Exception;
use Throwable;

/**
 * Base exception for library validation, transaction and stored-data failures.
 *
 * Expected authentication failures are returned as result arrays instead.
 */
class BaseException extends Exception
{
    /**
     * Default machine-readable error code, overridden by specific exceptions.
     *
     * @var string
     */
    protected const ERROR_CODE = 'library_error';

    /**
     * Stable error identifier for application handling.
     *
     * @var string
     */
    public readonly string $errorCode;

    /**
     * The input or stored field associated with the failure, when known.
     *
     * @var string|null
     */
    public readonly ?string $field;

    /**
     * Additional diagnostic metadata. Library context never contains credentials.
     *
     * @var array<string, mixed>
     */
    public readonly array $context;

    /**
     * Create an exception with structured details and an optional underlying cause.
     *
     * The first three arguments preserve PHP's standard exception constructor.
     * Use named arguments for field, context and errorCode when adding metadata.
     *
     * @param string $message A description suitable for trusted application code.
     * @param int $code The numeric exception code.
     * @param Throwable|null $previous The original exception, if any.
     * @param string|null $errorCode An optional override of the class error identifier.
     * @param string|null $field The field associated with the failure.
     * @param array<string, mixed> $context Additional application-defined metadata.
     */
    public function __construct(
        string $message = '',
        int $code = 0,
        ?Throwable $previous = null,
        ?string $errorCode = null,
        ?string $field = null,
        array $context = []
    ) {
        parent::__construct($message, $code, $previous);
        $this->errorCode = $errorCode ?? static::ERROR_CODE;
        $this->field = $field;
        $this->context = $context;
    }

    /**
     * Return structured exception details without the trace or underlying exception.
     *
     * Review the message and context before exposing them in a public response.
     *
     * @return array{error_code: string, message: string, field: string|null, context: array<string, mixed>}
     */
    public function toArray(): array
    {
        return [
            'error_code' => $this->errorCode,
            'message' => $this->getMessage(),
            'field' => $this->field,
            'context' => $this->context,
        ];
    }
}
