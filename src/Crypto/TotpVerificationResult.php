<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

final class TotpVerificationResult
{
    private function __construct(
        private readonly bool $valid,
        private readonly ?int $matchedStep,
        private readonly string $reason,
    ) {
    }

    public static function accepted(int $step): self
    {
        return new self(true, $step, 'accepted');
    }

    public static function rejected(string $reason, ?int $matchedStep = null): self
    {
        return new self(false, $matchedStep, $reason);
    }

    public function isValid(): bool
    {
        return $this->valid;
    }

    public function acceptedStep(): ?int
    {
        return $this->valid ? $this->matchedStep : null;
    }

    public function matchedStep(): ?int
    {
        return $this->matchedStep;
    }

    public function reason(): string
    {
        return $this->reason;
    }
}
