<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

final class RecoveryCodeRecord
{
    public function __construct(private readonly string $id, private readonly string $hash)
    {
        if ($this->id === '' || strlen($this->id) > 256 || $this->hash === '') {
            throw new \InvalidArgumentException('Invalid recovery-code record.');
        }
    }

    public function id(): string
    {
        return $this->id;
    }

    public function hash(): string
    {
        return $this->hash;
    }

    public function __debugInfo(): array
    {
        return ['id' => $this->id];
    }
}
