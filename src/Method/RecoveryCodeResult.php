<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class RecoveryCodeResult implements VerificationCommit
{
    private RecoveryCodeId $codeId;

    public function __construct(
        private MethodId $methodId,
        RecoveryCodeId|string $codeId,
        private bool $exhausted,
    ) {
        $this->codeId = $codeId instanceof RecoveryCodeId ? $codeId : new RecoveryCodeId($codeId);
    }

    public function providerKey(): ProviderKey { return ProviderKey::fromString('recovery'); }
    public function methodId(): MethodId { return $this->methodId; }
    public function codeId(): RecoveryCodeId { return $this->codeId; }
    public function exhausted(): bool { return $this->exhausted; }
}
