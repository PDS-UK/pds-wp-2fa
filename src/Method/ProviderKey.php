<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class ProviderKey
{
    private string $value;

    private function __construct(string $value)
    {
        $this->value = $value;
    }

    public static function fromString(string $value): self
    {
        $value = strtolower(trim($value));
        if ($value === '' || preg_match('/^[a-z][a-z0-9_-]{0,31}$/', $value) !== 1) {
            throw new \InvalidArgumentException('Provider keys must be stable lowercase identifiers.');
        }

        return new self($value);
    }

    public function value(): string
    {
        return $this->value;
    }

    public function equals(self $other): bool
    {
        return hash_equals($this->value, $other->value);
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
