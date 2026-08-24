<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

use Closure;

final class CallableAuthenticationContextProvider implements AuthenticationContextProvider
{
    private readonly Closure $callback;

    public function __construct(callable $callback)
    {
        $this->callback = Closure::fromCallable($callback);
    }

    public function snapshot(): AuthenticationSnapshot
    {
        $snapshot = ($this->callback)();
        if (!$snapshot instanceof AuthenticationSnapshot) {
            throw new \UnexpectedValueException('The authentication context adapter returned an invalid snapshot.');
        }

        return $snapshot;
    }
}
