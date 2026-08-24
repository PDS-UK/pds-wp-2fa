<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class RecoveryCodeId
{
    private string $value;

    public function __construct(string $value)
    {
        $value = trim($value);
        if ($value === '' || strlen($value) > 128 || preg_match('/^[A-Za-z0-9_-]+$/', $value) !== 1) {
            throw new \InvalidArgumentException('Recovery code IDs must be opaque identifiers.');
        }

        $this->value = $value;
    }

    public static function random(): self
    {
        return new self(rtrim(strtr(base64_encode(random_bytes(18)), '+/', '-_'), '='));
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
