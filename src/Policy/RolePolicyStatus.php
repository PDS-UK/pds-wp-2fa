<?php

declare(strict_types=1);

namespace PDS\WP2FA\Policy;

final class RolePolicyStatus
{
    public const DISABLED = 'disabled';
    public const ACTIVE = 'active';
    public const ORPHANED = 'orphaned';

    /** @var string */
    private $value;

    public function __construct(string $value)
    {
        if (!in_array($value, [self::DISABLED, self::ACTIVE, self::ORPHANED], true)) {
            throw new \InvalidArgumentException('Invalid role-policy status.');
        }

        $this->value = $value;
    }

    public function value(): string
    {
        return $this->value;
    }

    public function isDisabled(): bool
    {
        return $this->value === self::DISABLED;
    }

    public function isActive(): bool
    {
        return $this->value === self::ACTIVE;
    }

    public function isOrphaned(): bool
    {
        return $this->value === self::ORPHANED;
    }
}
