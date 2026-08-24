<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

final class RecoveryCodeNormalizer
{
    public function normalize(string $value): string
    {
        $normalized = preg_replace('/[\x09-\x0D\x20\x2D]/', '', $value);

        if (!is_string($normalized)) {
            throw new \InvalidArgumentException('Invalid recovery code.');
        }

        $normalized = strtoupper($normalized);

        if (preg_match('/\A[0-9A-F]{32}\z/D', $normalized) !== 1) {
            throw new \InvalidArgumentException('Invalid recovery code.');
        }

        return $normalized;
    }
}
