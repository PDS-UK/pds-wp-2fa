<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class MethodId
{
    private string $value;

    private function __construct(string $value)
    {
        $this->value = $value;
    }

    public static function fromString(string $value): self
    {
        $value = trim($value);
        if ($value === '' || strlen($value) > 128 || preg_match('/^[A-Za-z0-9_-]+$/', $value) !== 1) {
            throw new \InvalidArgumentException('Method IDs must be opaque URL-safe identifiers.');
        }

        return new self($value);
    }

    public static function random(): self
    {
        // Method IDs are stored as binary(16) by the WordPress repository.
        // Keep the external opaque identifier exactly round-trippable.
        return new self(rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '='));
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
