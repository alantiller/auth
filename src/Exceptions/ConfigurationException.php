<?php declare(strict_types=1);

namespace Alantiller\Auth\Exceptions;

/**
 * Indicate an unsupported or missing library configuration option.
 *
 * Structured field and context metadata are inherited from BaseException.
 */
class ConfigurationException extends InvalidArgumentException
{
    /**
     * Machine-readable identifier for this exception category.
     *
     * @var string
     */
    protected const ERROR_CODE = 'configuration_error';
}
