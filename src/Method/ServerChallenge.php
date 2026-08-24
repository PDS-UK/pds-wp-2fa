<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class ServerChallenge
{
    private string $value;

    private function __construct(string $value)
    {
        $this->value = $value;
    }

    public static function fromString(string $value): self
    {
        $value = trim($value);
        if ($value === '' || strlen($value) > 512 || preg_match('/^[A-Za-z0-9_-]+$/', $value) !== 1) {
            throw new \InvalidArgumentException('Challenges must be opaque server-created values.');
        }

        return new self($value);
    }

    public static function random(): self
    {
        return new self(rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='));
    }

    public function value(): string
    {
        return $this->value;
    }
}
