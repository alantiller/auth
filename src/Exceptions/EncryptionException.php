<?php declare(strict_types=1);

namespace Alantiller\Auth\Exceptions;

/**
 * Indicate that a stored authenticator secret cannot be authenticated or decrypted.
 *
 * Structured field and context metadata are inherited from BaseException.
 */
class EncryptionException extends BaseException
{
    /**
     * Machine-readable identifier for this exception category.
     *
     * @var string
     */
    protected const ERROR_CODE = 'encryption_error';
}
