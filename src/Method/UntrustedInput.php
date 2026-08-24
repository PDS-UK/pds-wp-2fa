<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class UntrustedInput
{
    public function __construct(private mixed $value)
    {
    }

    public function value(): mixed
    {
        return $this->value;
    }

    /** @return array<string, mixed> */
    public function asArray(): array
    {
        if (!is_array($this->value)) {
            throw new \InvalidArgumentException('Provider input must be an array after transport decoding.');
        }

        return $this->value;
    }
}
