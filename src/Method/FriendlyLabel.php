<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class FriendlyLabel
{
    private string $value;

    private function __construct(string $value)
    {
        $this->value = $value;
    }

    public static function fromString(string $value): self
    {
        $value = trim($value);
        if ($value === '' || strlen($value) > 240 || preg_match('//u', $value) !== 1) {
            throw new \InvalidArgumentException('Method labels must be valid, bounded UTF-8 text.');
        }
        if (preg_match('/[\x00-\x1F\x7F-\x9F]/u', $value) === 1) {
            throw new \InvalidArgumentException('Method labels cannot contain control characters.');
        }

        return new self($value);
    }

    public function value(): string
    {
        return $this->value;
    }
}
