<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

final class ImmediateTransaction implements AdminTransaction
{
    public function run(callable $operation): mixed
    {
        return $operation();
    }
}
