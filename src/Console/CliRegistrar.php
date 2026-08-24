<?php

declare(strict_types=1);

namespace PDS\WP2FA\Console;

interface CliRegistrar
{
    public function addCommand(string $name, object|string $command): void;
}
