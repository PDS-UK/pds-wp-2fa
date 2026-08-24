<?php

declare(strict_types=1);

namespace PDS\WP2FA\Console;

interface CliOutput
{
    /** @param array<string, mixed>|list<array<string, mixed>> $data */
    public function render(array $data, OutputFormat $format): void;

    public function line(string $message): void;

    public function error(string $message, int $exitCode): void;

    public function isTty(): bool;

    public function writeSecret(string $value): void;
}
