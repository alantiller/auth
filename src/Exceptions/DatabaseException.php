<?php declare(strict_types=1);

namespace Alantiller\Auth\Exceptions;

/**
 * Indicate a failed database operation, retaining its original cause.
 *
 * Structured field and context metadata are inherited from BaseException.
 */
class DatabaseException extends BaseException
{
    /**
     * Machine-readable identifier for this exception category.
     *
     * @var string
     */
    protected const ERROR_CODE = 'database_error';
}
