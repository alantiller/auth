<?php declare(strict_types=1);

namespace Alantiller\Auth\Exceptions;

/**
 * Indicate an invalid argument or missing required authentication configuration.
 */
class InvalidArgumentException extends BaseException
{
    /**
     * Error identifier for invalid library arguments.
     *
     * @var string
     */
    protected const ERROR_CODE = 'invalid_argument';
}
