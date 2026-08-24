<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class ProviderCommit implements VerificationCommit
{
    /** @param array<string, scalar|null> $metadata */
    public function __construct(
        private ProviderKey $provider,
        private SafeMetadata $metadata,
    ) {
    }

    public function providerKey(): ProviderKey { return $this->provider; }
    public function metadata(): SafeMetadata { return $this->metadata; }
}
