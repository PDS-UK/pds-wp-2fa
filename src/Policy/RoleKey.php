<?php

declare(strict_types=1);

namespace PDS\WP2FA\Policy;

final class RoleKey
{
    /** @var string */
    private $value;

    public function __construct(string $value)
    {
        if ($value === '') {
            throw new \InvalidArgumentException('A role key cannot be empty.');
        }

        $this->value = $value;
    }

    public function value(): string
    {
        return $this->value;
    }

    public function equals(RoleKey $other): bool
    {
        return $this->value === $other->value;
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
