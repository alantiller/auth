<?php declare(strict_types=1);

namespace Alantiller\Auth\Internal;

use Alantiller\Auth\Exceptions\StoredDataException;
use Alantiller\Auth\Exceptions\ValidationException;

/**
 * Validate and serialize extensible user preference key/value pairs.
 *
 * Preferences are stored as a JSON object and decoded into PHP arrays.
 * This helper does not access the database or retain user-specific state.
 *
 * @internal Applications should manage preferences through Auth.
 */
final class Preferences
{
    /**
     * Validate the name of a preference key.
     *
     * Keys must be nonblank, valid UTF-8 strings containing 1–100 bytes.
     *
     * @param string $field The case-sensitive preference key.
     * @return void
     *
     * @throws ValidationException If the key is blank, too long or invalid UTF-8.
     */
    public static function validateField(string $field): void
    {
        if (trim($field) === '' || strlen($field) > 100 || !preg_match('//u', $field)) {
            throw new ValidationException('Preference names must be valid UTF-8 and contain 1–100 bytes.', field: 'field');
        }
    }

    /**
     * Validate a JSON-compatible preference value and its nested values.
     *
     * Objects, resources, non-finite floats, invalid UTF-8 and nesting beyond
     * 32 levels are rejected.
     *
     * @param mixed $value The JSON-compatible value to store.
     * @param int $depth The current nesting depth; callers start at zero.
     * @param string $field The preference field to include in validation errors.
     * @return void
     *
     * @throws ValidationException If the value is not supported or exceeds the nesting limit.
     */
    public static function validateValue(mixed $value, int $depth = 0, string $field = 'preferences'): void
    {
        if ($depth > 32 || is_object($value) || is_resource($value)
            || (is_float($value) && !is_finite($value))) {
            throw new ValidationException('Preferences must contain JSON-compatible values with at most 32 levels.', field: $field, context: ['max_depth' => 32]);
        }
        if (is_array($value)) {
            foreach ($value as $child) {
                self::validateValue($child, $depth + 1, $field);
            }
        }
        try {
            json_encode($value, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new ValidationException('Preference values must be valid JSON.', previous: $exception, field: $field);
        }
    }

    /**
     * Serialize preference key/value pairs as a JSON object.
     *
     * Casting to an object preserves the object representation for an empty map
     * or a map containing only numeric keys. The result is limited to 65,535 bytes.
     *
     * @param array<array-key, mixed> $preferences The preference key/value pairs to serialize.
     * @return string The serialized JSON preference object.
     *
     * @throws ValidationException If serialized preferences exceed 65,535 bytes.
     * @throws \JsonException If a value cannot be encoded as JSON.
     */
    public static function encode(array $preferences): string
    {
        $serialized = json_encode((object) $preferences, JSON_THROW_ON_ERROR);
        if (strlen($serialized) > 65535) {
            throw new ValidationException('Serialized preferences cannot exceed 65535 bytes.', field: 'preferences', context: ['max_bytes' => 65535]);
        }
        return $serialized;
    }

    /**
     * Deserialize a stored JSON preference object into a PHP array.
     *
     * Stored JSON arrays and scalar values are rejected.
     *
     * @param string $serialized The stored JSON preference object.
     * @return array<array-key, mixed> The deserialized preference key/value pairs.
     *
     * @throws StoredDataException If the stored JSON is not an object.
     * @throws StoredDataException If the stored JSON cannot be decoded.
     */
    public static function decode(string $serialized): array
    {
        try {
            $decoded = json_decode($serialized, false, 512, JSON_THROW_ON_ERROR);
            if (!$decoded instanceof \stdClass) {
                throw new StoredDataException('Stored preferences must be a JSON object.', field: 'preferences');
            }
            $preferences = json_decode($serialized, true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($preferences)) {
                throw new StoredDataException('Stored preferences must decode to key/value pairs.', field: 'preferences');
            }
            return $preferences;
        } catch (\JsonException $exception) {
            throw new StoredDataException('Stored preferences contain invalid JSON.', previous: $exception, field: 'preferences');
        }
    }
}
