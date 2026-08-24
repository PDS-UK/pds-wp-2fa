<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class RetainedMethodCount
{
    public function __construct(private int $value)
    {
        if ($value < 0) {
            throw new \InvalidArgumentException('A retained method count cannot be negative.');
        }
    }

    public function value(): int
    {
        return $this->value;
    }

    public function hasAny(): bool
    {
        return $this->value > 0;
    }
}
