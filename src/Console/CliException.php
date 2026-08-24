<?php

declare(strict_types=1);

namespace PDS\WP2FA\Console;

final class CliException extends \RuntimeException
{
    public function __construct(string $message, private readonly int $exitCode = CliExitCode::USAGE)
    {
        parent::__construct($message, $exitCode);
    }

    public function exitCode(): int
    {
        return $this->exitCode;
    }
}
