<?php

declare(strict_types=1);

namespace PDS\WP2FA\Identity;

interface RandomBytesSource
{
    public function bytes(int $length): string;
}
