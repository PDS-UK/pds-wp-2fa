<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class UserId
{
    private int $value;

    private function __construct(int $value)
    {
        $this->value = $value;
    }

    public static function fromInt(int $value): self
    {
        if ($value < 1) {
            throw new \InvalidArgumentException('A WordPress user ID must be positive.');
        }

        return new self($value);
    }

    public function value(): int
    {
        return $this->value;
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }
}
