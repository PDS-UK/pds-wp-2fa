<?php

declare(strict_types=1);

namespace PDS\WP2FA\Identity;

final class EnvironmentType
{
    public const LOCAL = 'local';
    public const DEVELOPMENT = 'development';
    public const STAGING = 'staging';
    public const PRODUCTION = 'production';

    private string $value;

    private function __construct(string $value)
    {
        $this->value = $value;
    }

    /**
     * Mirrors wp_get_environment_type(): invalid or absent input is production.
     *
     * @param mixed $value
     */
    public static function classify($value): self
    {
        if (is_string($value) && in_array($value, self::values(), true)) {
            return new self($value);
        }

        return self::production();
    }

    public static function fromStoredValue(string $value): self
    {
        if (!in_array($value, self::values(), true)) {
            throw new \InvalidArgumentException('The persisted environment type is invalid.');
        }

        return new self($value);
    }

    public static function local(): self
    {
        return new self(self::LOCAL);
    }

    public static function development(): self
    {
        return new self(self::DEVELOPMENT);
    }

    public static function staging(): self
    {
        return new self(self::STAGING);
    }

    public static function production(): self
    {
        return new self(self::PRODUCTION);
    }

    /** @return list<string> */
    public static function values(): array
    {
        return [self::LOCAL, self::DEVELOPMENT, self::STAGING, self::PRODUCTION];
    }

    public function value(): string
    {
        return $this->value;
    }

    public function isProduction(): bool
    {
        return $this->value === self::PRODUCTION;
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
