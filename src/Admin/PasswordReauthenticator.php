<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

interface PasswordReauthenticator
{
    public function assertValid(AdminActor $actor, string $password): void;
}
