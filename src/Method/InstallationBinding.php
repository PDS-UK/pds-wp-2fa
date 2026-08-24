<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class InstallationBinding
{
    private string $hash;
    private int $epoch;

    public function __construct(string $hash, int $epoch)
    {
        $hash = trim($hash);
        if ($hash === '' || strlen($hash) > 128 || preg_match('/^[A-Za-z0-9_-]+$/', $hash) !== 1) {
            throw new \InvalidArgumentException('Installation bindings require a canonical identity hash.');
        }
        if ($epoch < 1) {
            throw new \InvalidArgumentException('Installation epochs must be positive.');
        }

        $this->hash = $hash;
        $this->epoch = $epoch;
    }

    public function hash(): string
    {
        return $this->hash;
    }

    public function epoch(): int
    {
        return $this->epoch;
    }

    public function equals(self $other): bool
    {
        return hash_equals($this->hash, $other->hash) && $this->epoch === $other->epoch;
    }
}
