<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

interface NonceFieldProvider
{
    public function field(string $action): string;
}
