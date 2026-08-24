<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class ProviderServerState
{
    /** @var array<string, mixed> */
    private array $values;

    /** @param array<string, mixed> $values */
    public function __construct(array $values)
    {
        $this->values = $values;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return $this->values;
    }
}
