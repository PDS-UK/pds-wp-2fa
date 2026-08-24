<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class ProviderData
{
    private int $schemaVersion;

    /** @var array<string, mixed> */
    private array $values;

    /** @param array<string, mixed> $values */
    public function __construct(int $schemaVersion, array $values)
    {
        if ($schemaVersion < 1) {
            throw new \InvalidArgumentException('Provider schema versions must be positive.');
        }

        $this->schemaVersion = $schemaVersion;
        $this->values = $values;
    }

    public function schemaVersion(): int
    {
        return $this->schemaVersion;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return $this->values;
    }
}
