<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

interface NonceVerifier
{
    public function verify(string $action, ?string $nonce): bool;
}
