<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

final class RecoveryCodeVerificationResult
{
    private function __construct(
        private readonly bool $successful,
        private readonly string $reason,
        private readonly ?string $codeId,
    ) {
    }

    public static function accepted(string $codeId): self
    {
        return new self(true, 'accepted', $codeId);
    }

    public static function rejected(string $reason): self
    {
        return new self(false, $reason, null);
    }

    public function isSuccessful(): bool
    {
        return $this->successful;
    }

    public function reason(): string
    {
        return $this->reason;
    }

    public function codeId(): ?string
    {
        return $this->codeId;
    }
}
