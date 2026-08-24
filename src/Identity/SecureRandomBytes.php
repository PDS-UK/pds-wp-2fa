<?php

declare(strict_types=1);

namespace PDS\WP2FA\Identity;

final class SecureRandomBytes implements RandomBytesSource
{
    public function bytes(int $length): string
    {
        return random_bytes($length);
    }
}
