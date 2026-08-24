<?php

declare(strict_types=1);

namespace PDS\WP2FA\Identity;

final class IdentityFingerprint
{
    private string $bytes;

    private function __construct(string $bytes)
    {
        if (strlen($bytes) !== 32) {
            throw new \InvalidArgumentException('An identity fingerprint must contain exactly 32 bytes.');
        }

        $this->bytes = $bytes;
    }

    public static function fromBytes(string $bytes): self
    {
        return new self($bytes);
    }

    public static function fromHex(string $hex): self
    {
        if (preg_match('/\A[0-9a-f]{64}\z/D', $hex) !== 1) {
            throw new \InvalidArgumentException('An identity fingerprint must be 64 lowercase hexadecimal characters.');
        }

        return self::fromBytes(hex2bin($hex));
    }

    public function binary(): string
    {
        return $this->bytes;
    }

    public function hex(): string
    {
        return bin2hex($this->bytes);
    }

    public function redacted(): string
    {
        return 'sha256:' . substr($this->hex(), 0, 12) . '...';
    }

    public function equals(self $other): bool
    {
        return hash_equals($this->bytes, $other->bytes);
    }

    public function __toString(): string
    {
        return $this->redacted();
    }

    public function __debugInfo(): array
    {
        return ['fingerprint' => $this->redacted()];
    }
}
