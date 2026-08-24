<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

use Closure;

final class CallableNonceFieldProvider implements NonceFieldProvider
{
    private readonly Closure $callback;

    public function __construct(callable $callback)
    {
        $this->callback = Closure::fromCallable($callback);
    }

    public function field(string $action): string
    {
        return (string) ($this->callback)($action);
    }
}
