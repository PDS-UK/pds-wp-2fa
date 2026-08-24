<?php

declare(strict_types=1);

namespace PDS\WP2FA\WordPress;

use Closure;
use RuntimeException;

final class CallableHookRegistrar implements HookRegistrar
{
    private readonly Closure $addAction;
    private readonly Closure $addFilter;

    public function __construct(callable $addAction, callable $addFilter)
    {
        $this->addAction = Closure::fromCallable($addAction);
        $this->addFilter = Closure::fromCallable($addFilter);
    }

    public static function fromWordPress(): self
    {
        if (!function_exists('add_action') || !function_exists('add_filter')) {
            throw new RuntimeException('WordPress hook functions are required to register the 2FA gates.');
        }

        return new self(
            static fn (string $hook, callable $callback, int $priority, int $acceptedArgs): mixed
                => \add_action($hook, $callback, $priority, $acceptedArgs),
            static fn (string $hook, callable $callback, int $priority, int $acceptedArgs): mixed
                => \add_filter($hook, $callback, $priority, $acceptedArgs),
        );
    }

    public function addAction(string $hook, callable $callback, int $priority, int $acceptedArgs): void
    {
        ($this->addAction)($hook, $callback, $priority, $acceptedArgs);
    }

    public function addFilter(string $hook, callable $callback, int $priority, int $acceptedArgs): void
    {
        ($this->addFilter)($hook, $callback, $priority, $acceptedArgs);
    }
}
