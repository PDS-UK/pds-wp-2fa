<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

use PDS\WP2FA\Method\UserId;

interface CapabilityChecker
{
    public function allows(UserId $user, string $capability): bool;
}
