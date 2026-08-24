<?php

declare(strict_types=1);

namespace PDS\WP2FA\Identity;

/**
 * A validated identity that intentionally retains only its fingerprint.
 *
 * The deployment value is accepted at the configuration boundary and is
 * discarded after hashing. This prevents a normal domain object dump from
 * becoming a secret disclosure path.
 */
final class InstallationIdentity
{
    private IdentityFingerprint $fingerprint;

    private function __construct(IdentityFingerprint $fingerprint)
    {
        $this->fingerprint = $fingerprint;
    }

    public static function fromCanonicalHex(string $canonicalHex): self
    {
        if (!self::isCanonicalHex($canonicalHex)) {
            throw new \InvalidArgumentException('Installation identity must be 64 lowercase hexadecimal characters.');
        }

        return self::fromBytes(hex2bin($canonicalHex));
    }

    public static function fromBytes(string $bytes): self
    {
        if (strlen($bytes) !== 32) {
            throw new \InvalidArgumentException('Installation identity must contain exactly 32 bytes.');
        }

        return new self(IdentityFingerprint::fromBytes(hash('sha256', $bytes, true)));
    }

    public static function isCanonicalHex(string $value): bool
    {
        return preg_match('/\A[0-9a-f]{64}\z/D', $value) === 1;
    }

    public function fingerprint(): IdentityFingerprint
    {
        return $this->fingerprint;
    }

    public function equals(self $other): bool
    {
        return $this->fingerprint->equals($other->fingerprint);
    }

    public function __toString(): string
    {
        return '[redacted]';
    }

    public function __debugInfo(): array
    {
        return ['identity' => '[redacted]'];
    }
}
