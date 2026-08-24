<?php

declare(strict_types=1);

namespace PDS\WP2FA\WordPress;

interface HookRegistrar
{
    public function addAction(string $hook, callable $callback, int $priority, int $acceptedArgs): void;

    public function addFilter(string $hook, callable $callback, int $priority, int $acceptedArgs): void;
}
