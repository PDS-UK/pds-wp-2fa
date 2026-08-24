<?php

declare(strict_types=1);

namespace PDS\WP2FA\Policy;

use DateTimeImmutable;

final class UserRolePolicyAnchor
{
    public function __construct(
        private int $userId,
        private RoleKey $roleKey,
        private DateTimeImmutable $affectedSince,
    ) {
        if ($userId < 1) {
            throw new \InvalidArgumentException('A user ID must be positive.');
        }
        $this->affectedSince = Time::utc($affectedSince);
    }

    public function userId(): int { return $this->userId; }
    public function roleKey(): RoleKey { return $this->roleKey; }
    public function affectedSince(): DateTimeImmutable { return $this->affectedSince; }
}
