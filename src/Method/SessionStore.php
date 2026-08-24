<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

interface SessionStore
{
    public function state(UserId $userId, SessionDigest $session): SessionState;

    public function satisfy(UserId $userId, SessionDigest $session): void;

    public function invalidate(UserId $userId, SessionDigest $session): void;
}
