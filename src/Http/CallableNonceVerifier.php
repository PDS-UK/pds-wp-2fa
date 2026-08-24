<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

use Closure;

final class CallableNonceVerifier implements NonceVerifier
{
    private readonly Closure $callback;

    public function __construct(callable $callback)
    {
        $this->callback = Closure::fromCallable($callback);
    }

    public function verify(string $action, ?string $nonce): bool
    {
        return $nonce !== null && $nonce !== '' && (bool) ($this->callback)($action, $nonce);
    }
}
