<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

interface AdminAuthorizer
{
    public function assertSatisfiedSession(AdminActor $actor): void;

    public function assertCapability(AdminActor $actor, string $capability): void;

    public function assertCanEditUser(AdminActor $actor, int $targetUserId): void;
}
