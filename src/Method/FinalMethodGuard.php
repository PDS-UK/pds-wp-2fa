<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class FinalMethodGuard
{
    public function assertManualRevocationAllowed(MethodStatus $status, RetainedMethodCount $retained): void
    {
        if ($status === MethodStatus::ACTIVE && $retained->value() <= 1) {
            throw new FinalMethodProtectionException('The final active method cannot be manually revoked.');
        }
    }

    public function assertReplacementAllowed(RetainedMethodCount $retained, bool $replacementIsActive): void
    {
        if (!$replacementIsActive) {
            throw new FinalMethodProtectionException('A replacement must be active before the old method is revoked.');
        }

        if ($retained->value() < 1) {
            throw new FinalMethodProtectionException('A replacement requires a retained method transaction.');
        }
    }

    public function allowsRecoveryExhaustion(bool $currentSessionSucceeded): bool
    {
        return $currentSessionSucceeded;
    }
}
