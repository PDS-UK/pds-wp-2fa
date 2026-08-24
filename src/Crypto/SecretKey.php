<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

final class SecretKey
{
    private function __construct(private string $bytes)
    {
    }

    public static function fromRaw(string $bytes): self
    {
        if (strlen($bytes) !== 32) {
            throw new \InvalidArgumentException('Invalid encryption key.');
        }

        return new self($bytes);
    }

    public static function fromBase64(string $encoded): self
    {
        if ($encoded === '' || preg_match('/\A[A-Za-z0-9+\/]+={0,2}\z/D', $encoded) !== 1) {
            throw new \InvalidArgumentException('Invalid base64 encryption key.');
        }

        $decoded = base64_decode($encoded, true);

        if (!is_string($decoded) || base64_encode($decoded) !== $encoded) {
            throw new \InvalidArgumentException('Invalid base64 encryption key.');
        }

        return self::fromRaw($decoded);
    }

    public function raw(): string
    {
        return $this->bytes;
    }

    public function __debugInfo(): array
    {
        return ['length' => strlen($this->bytes)];
    }
}
