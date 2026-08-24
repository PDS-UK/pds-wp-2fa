<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class VerificationResult
{
    private function __construct(
        private bool $succeeded,
        private ?MethodId $methodId,
        private ?VerificationCommit $commit,
        private ?SafeMetadata $metadata,
        private ?VerificationFailureReason $failureReason,
    ) {
        if ($succeeded && ($methodId === null || $commit === null || $failureReason !== null)) {
            throw new \InvalidArgumentException('A successful verification requires a method and commit.');
        }

        if (!$succeeded && ($commit !== null || $failureReason === null)) {
            throw new \InvalidArgumentException('A failed verification cannot carry a commit.');
        }
    }

    public static function success(MethodId $methodId, VerificationCommit $commit, SafeMetadata $metadata): self
    {
        return new self(true, $methodId, $commit, $metadata, null);
    }

    public static function failure(VerificationFailureReason $reason): self
    {
        return new self(false, null, null, null, $reason);
    }

    public function succeeded(): bool
    {
        return $this->succeeded;
    }

    public function isSuccessful(): bool
    {
        return $this->succeeded;
    }

    public function methodId(): ?MethodId
    {
        return $this->methodId;
    }

    public function commit(): VerificationCommit
    {
        if ($this->commit === null) {
            throw new \LogicException('A failed verification has no commit.');
        }

        return $this->commit;
    }

    public function metadata(): ?SafeMetadata
    {
        return $this->metadata;
    }

    public function failureReason(): ?VerificationFailureReason
    {
        return $this->failureReason;
    }
}
