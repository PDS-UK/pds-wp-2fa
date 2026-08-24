<?php

declare(strict_types=1);

namespace PDS\WP2FA\Console;

final class CliExitCode
{
    public const SUCCESS = 0;
    public const USAGE = 1;
    public const CONFIRMATION = 2;
    public const IDENTITY_UNAVAILABLE = 3;
    public const CONFLICT = 4;
    public const NOT_FOUND = 5;

    private function __construct()
    {
    }
}
