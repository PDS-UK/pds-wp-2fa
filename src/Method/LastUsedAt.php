<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

use DateTimeImmutable;

final class LastUsedAt
{
    private ?DateTimeImmutable $value;

    private function __construct(?DateTimeImmutable $value)
    {
        $this->value = $value;
    }

    public static function never(): self
    {
        return new self(null);
    }

    public static function at(DateTimeImmutable $value): self
    {
        return new self($value);
    }

    public function value(): ?DateTimeImmutable
    {
        return $this->value;
    }

    public function hasValue(): bool
    {
        return $this->value !== null;
    }
}
