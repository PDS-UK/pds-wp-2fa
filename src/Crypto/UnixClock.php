<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

interface UnixClock
{
    public function now(): int;
}
