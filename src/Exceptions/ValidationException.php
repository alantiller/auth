<?php declare(strict_types=1);

namespace Alantiller\Auth\Exceptions;

/**
 * Indicate malformed account or preference input.
 *
 * Structured field and context metadata are inherited from BaseException.
 */
class ValidationException extends InvalidArgumentException
{
    /**
     * Machine-readable identifier for this exception category.
     *
     * @var string
     */
    protected const ERROR_CODE = 'validation_error';
}
