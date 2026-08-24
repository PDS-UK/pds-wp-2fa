<?php

declare(strict_types=1);

namespace PDS\WP2FA\Policy;

use DateTimeImmutable;

final class RolePolicyContribution
{
    public function __construct(
        private RoleKey $roleKey,
        private DateTimeImmutable $affectedSince,
        private DateTimeImmutable $deadline,
    ) {
        $this->affectedSince = Time::utc($affectedSince);
        $this->deadline = Time::utc($deadline);
    }

    public function roleKey(): RoleKey { return $this->roleKey; }
    public function affectedSince(): DateTimeImmutable { return $this->affectedSince; }
    public function deadline(): DateTimeImmutable { return $this->deadline; }
}
