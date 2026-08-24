<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

interface NonceVerifier
{
    public function assertValid(string $action, string $nonce): void;
}
