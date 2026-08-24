<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

final class RecoveryCodeHasher
{
    private readonly RecoveryCodeNormalizer $normalizer;
    private readonly string|int $algorithm;

    public function __construct(?RecoveryCodeNormalizer $normalizer = null)
    {
        $this->normalizer = $normalizer ?? new RecoveryCodeNormalizer();
        $this->algorithm = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
    }

    public function hash(string $code): string
    {
        $normalized = $this->normalizer->normalize($code);

        try {
            $hash = password_hash($normalized, $this->algorithm);
        } catch (\Throwable) {
            throw new CryptoException('Recovery-code hashing failed.');
        }

        if (!is_string($hash) || $hash === '') {
            throw new CryptoException('Recovery-code hashing failed.');
        }

        return $hash;
    }

    public function verify(string $code, string $hash): bool
    {
        try {
            $normalized = $this->normalizer->normalize($code);
            return password_verify($normalized, $hash);
        } catch (\Throwable) {
            return false;
        }
    }
}
