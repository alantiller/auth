<?php declare(strict_types=1);

namespace Alantiller\Auth\Exceptions;

/**
 * Indicate that a getter was called for an account that does not exist.
 *
 * Structured field and context metadata are inherited from BaseException.
 */
class UserNotFoundException extends InvalidArgumentException
{
    /**
     * Machine-readable identifier for this exception category.
     *
     * @var string
     */
    protected const ERROR_CODE = 'user_not_found';
}
