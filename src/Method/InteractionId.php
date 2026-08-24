<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class InteractionId
{
    private string $value;

    private function __construct(string $value)
    {
        $this->value = $value;
    }

    public static function fromHash(string $value): self
    {
        if (preg_match('/^[a-f0-9]{64}$/', $value) !== 1) {
            throw new \InvalidArgumentException('Interaction IDs must be SHA-256 hexadecimal digests.');
        }

        return new self($value);
    }

    public static function random(): self
    {
        return self::fromHash(hash('sha256', random_bytes(32)));
    }

    public function value(): string
    {
        return $this->value;
    }

    public function equals(self $other): bool
    {
        return hash_equals($this->value, $other->value);
    }
}
