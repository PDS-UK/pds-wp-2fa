<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

use PDS\WP2FA\Method\UserId;

interface ReauthenticationVerifier
{
    public function verify(UserId $user, string $password): bool;
}
