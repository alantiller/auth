<?php declare(strict_types=1);

namespace Alantiller\Auth\Exceptions;

/**
 * Indicate corrupt or incompatible data in an application-managed database field.
 *
 * Structured field and context metadata are inherited from BaseException.
 */
class StoredDataException extends BaseException
{
    /**
     * Machine-readable identifier for this exception category.
     *
     * @var string
     */
    protected const ERROR_CODE = 'stored_data_error';
}
