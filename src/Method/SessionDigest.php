<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class SessionDigest
{
    private string $value;

    public function __construct(string $value)
    {
        $value = trim($value);
        if ($value === '' || strlen($value) > 128 || preg_match('/^[A-Za-z0-9_-]+$/', $value) !== 1) {
            throw new \InvalidArgumentException('Session bindings require a canonical digest.');
        }

        $this->value = $value;
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
