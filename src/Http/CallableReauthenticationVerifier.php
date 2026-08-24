<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

use Closure;
use PDS\WP2FA\Method\UserId;

final class CallableReauthenticationVerifier implements ReauthenticationVerifier
{
    private readonly Closure $callback;

    public function __construct(callable $callback)
    {
        $this->callback = Closure::fromCallable($callback);
    }

    public function verify(UserId $user, string $password): bool
    {
        return $password !== '' && (bool) ($this->callback)($user, $password);
    }
}
