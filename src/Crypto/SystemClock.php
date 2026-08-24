<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

final class SystemClock implements UnixClock
{
    public function now(): int
    {
        return time();
    }
}
