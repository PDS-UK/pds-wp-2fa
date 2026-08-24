<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

interface RateLimiter
{
    public function check(string $operation, AuthenticationSnapshot $authentication): RateLimitDecision;

    public function recordFailure(string $operation, AuthenticationSnapshot $authentication): void;
}
