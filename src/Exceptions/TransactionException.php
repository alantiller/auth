<?php declare(strict_types=1);

namespace Alantiller\Auth\Exceptions;

/**
 * Indicate an incompatible transaction state or a failed transaction operation.
 *
 * Structured field and context metadata are inherited from BaseException.
 */
class TransactionException extends DatabaseException
{
    /**
     * Machine-readable identifier for this exception category.
     *
     * @var string
     */
    protected const ERROR_CODE = 'transaction_error';
}
