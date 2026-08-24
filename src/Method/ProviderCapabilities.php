<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class ProviderCapabilities
{
    public function __construct(
        private bool $supportsEnrollment,
        private bool $supportsAuthentication,
        private bool $supportsRotation,
        private bool $supportsDiscovery,
        private bool $supportsMultipleActiveMethods,
        private bool $sensitivePublicPayload,
    ) {
    }

    public function supportsEnrollment(): bool { return $this->supportsEnrollment; }
    public function supportsAuthentication(): bool { return $this->supportsAuthentication; }
    public function supportsRotation(): bool { return $this->supportsRotation; }
    public function supportsDiscovery(): bool { return $this->supportsDiscovery; }
    public function supportsMultipleActiveMethods(): bool { return $this->supportsMultipleActiveMethods; }
    public function sensitivePublicPayload(): bool { return $this->sensitivePublicPayload; }
}
