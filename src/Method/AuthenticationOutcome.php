<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class AuthenticationOutcome
{
    private function __construct(
        private bool $successful,
        private ?MethodId $methodId,
        private ?VerificationFailureReason $failureReason,
    ) {
    }

    public static function success(MethodId $methodId): self
    {
        return new self(true, $methodId, null);
    }

    public static function failure(VerificationFailureReason $reason): self
    {
        return new self(false, null, $reason);
    }

    public function succeeded(): bool { return $this->successful; }
    public function methodId(): ?MethodId { return $this->methodId; }
    public function failureReason(): ?VerificationFailureReason { return $this->failureReason; }
}
