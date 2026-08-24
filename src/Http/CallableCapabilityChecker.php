<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

use Closure;
use PDS\WP2FA\Method\UserId;

final class CallableCapabilityChecker implements CapabilityChecker
{
    private readonly Closure $callback;

    public function __construct(callable $callback)
    {
        $this->callback = Closure::fromCallable($callback);
    }

    public function allows(UserId $user, string $capability): bool
    {
        return (bool) ($this->callback)($user, $capability);
    }
}
