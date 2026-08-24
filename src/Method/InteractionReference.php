<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class InteractionReference
{
    private string $value;

    private function __construct(string $value)
    {
        $this->value = $value;
    }

    public static function fromString(string $value): self
    {
        $value = trim($value);
        if ($value === '' || strlen($value) > 256 || preg_match('/^[A-Za-z0-9_-]+$/', $value) !== 1) {
            throw new \InvalidArgumentException('Interaction references must be opaque URL-safe values.');
        }

        return new self($value);
    }

    public static function random(): self
    {
        return new self(rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='));
    }

    public function id(): InteractionId
    {
        return InteractionId::fromHash(hash('sha256', $this->value));
    }

    public function value(): string
    {
        return $this->value;
    }
}
