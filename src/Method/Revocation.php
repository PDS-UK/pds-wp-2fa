<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

use DateTimeImmutable;

final class Revocation
{
    public function __construct(
        private RevocationReason $reason,
        private ?UserId $actor,
        private DateTimeImmutable $at,
    ) {
    }

    public function reason(): RevocationReason
    {
        return $this->reason;
    }

    public function actor(): ?UserId
    {
        return $this->actor;
    }

    public function at(): DateTimeImmutable
    {
        return $this->at;
    }
}
