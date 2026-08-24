<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

final class RecoveryCodeVerifier
{
    public function __construct(
        private readonly RecoveryCodeHasher $hasher,
        private readonly RecoveryCodeNormalizer $normalizer = new RecoveryCodeNormalizer(),
    ) {
    }

    public function verifyAndConsume(
        string $candidate,
        string $generationId,
        RecoveryCodeStore $store,
    ): RecoveryCodeVerificationResult {
        try {
            $normalized = $this->normalizer->normalize($candidate);
        } catch (\InvalidArgumentException) {
            return RecoveryCodeVerificationResult::rejected('invalid_format');
        }

        if ($generationId === '') {
            return RecoveryCodeVerificationResult::rejected('invalid_generation');
        }

        foreach ($store->unused($generationId) as $record) {
            if (!$record instanceof RecoveryCodeRecord || !$this->hasher->verify($normalized, $record->hash())) {
                continue;
            }

            if (!$store->consumeIfUnused($record->id())) {
                return RecoveryCodeVerificationResult::rejected('already_used');
            }

            return RecoveryCodeVerificationResult::accepted($record->id());
        }

        return RecoveryCodeVerificationResult::rejected('not_found');
    }
}
