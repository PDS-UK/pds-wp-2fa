<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

use DateTimeImmutable;

interface Clock
{
    public function now(): DateTimeImmutable;
}
