<?php

declare(strict_types=1);

namespace PDS\WP2FA\Persistence;

use PDS\WP2FA\Identity\InstallationBinding as IdentityBinding;
use PDS\WP2FA\Method\InstallationBinding as MethodBinding;

/** Exact binary identity/epoch predicate shared by every security repository. */
final class InstallationScope
{
    public function __construct(private string $identityHash, private int $epoch)
    {
        if (strlen($identityHash) !== 32 || $epoch < 1) {
            throw new \InvalidArgumentException('A persistence scope requires a 32-byte identity and positive epoch.');
        }
    }

    public static function fromIdentity(IdentityBinding $binding): self
    {
        return new self($binding->identityHash(), $binding->epoch());
    }

    public static function fromMethod(MethodBinding $binding): self
    {
        return new self(self::decodeDigest($binding->hash()), $binding->epoch());
    }

    public static function fromValues(string $identityHash, int $epoch): self
    {
        return new self(self::decodeDigest($identityHash), $epoch);
    }

    public static function decodeDigest(string $value): string
    {
        if (strlen($value) === 32) {
            return $value;
        }
        if (preg_match('/\A[0-9a-f]{64}\z/', $value) === 1) {
            return hex2bin($value);
        }

        $decoded = base64_decode(strtr($value, '-_', '+/') . str_repeat('=', (4 - strlen($value) % 4) % 4), true);
        if (is_string($decoded) && strlen($decoded) === 32) {
            return $decoded;
        }

        throw new \InvalidArgumentException('Installation identity hashes must be 32 raw bytes or their canonical digest encoding.');
    }

    public function identityHash(): string { return $this->identityHash; }
    public function epoch(): int { return $this->epoch; }

    /** @return array{hash:string,epoch:int} */
    public function parameters(): array
    {
        return ['hash' => $this->identityHash, 'epoch' => $this->epoch];
    }
}
