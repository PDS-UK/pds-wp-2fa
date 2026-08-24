<?php

declare(strict_types=1);

namespace PDS\WP2FA\Console;

final class WordPressCliRegistrar implements CliRegistrar
{
    /** @param callable(string, object|string): void $addCommand */
    public function __construct(private readonly \Closure $addCommand)
    {
    }

    /** @param callable(string, object|string): void $addCommand */
    public static function fromCallable(callable $addCommand): self
    {
        return new self(\Closure::fromCallable($addCommand));
    }

    public function addCommand(string $name, object|string $command): void
    {
        ($this->addCommand)($name, $command);
    }
}
