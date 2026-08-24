<?php

declare(strict_types=1);

namespace PDS\WP2FA\Console;

final class WordPressCliOutput implements CliOutput
{
    /** @param callable(string): void $line @param callable(string,int): void $error @param callable(): bool $isTty @param callable(string): void $secret */
    public function __construct(
        private readonly \Closure $line,
        private readonly \Closure $error,
        private readonly \Closure $isTty,
        private readonly \Closure $secret,
        private readonly CliRenderer $renderer = new CliRenderer(),
    ) {
    }

    /** @param callable(string): void $line @param callable(string,int): void $error @param callable(): bool $isTty @param callable(string): void $secret */
    public static function fromCallables(callable $line, callable $error, callable $isTty, callable $secret): self
    {
        return new self(\Closure::fromCallable($line), \Closure::fromCallable($error), \Closure::fromCallable($isTty), \Closure::fromCallable($secret));
    }

    public function render(array $data, OutputFormat $format): void
    {
        ($this->line)($this->renderer->render($data, $format));
    }

    public function line(string $message): void { ($this->line)($message); }
    public function error(string $message, int $exitCode): void { ($this->error)($message, $exitCode); }
    public function isTty(): bool { return (bool) ($this->isTty)(); }
    public function writeSecret(string $value): void { ($this->secret)($value); }
}
