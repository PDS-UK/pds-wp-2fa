<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

final class AllowAllRateLimiter implements RateLimiter
{
    public function check(string $operation, AuthenticationSnapshot $authentication): RateLimitDecision
    {
        return RateLimitDecision::permit();
    }

    public function recordFailure(string $operation, AuthenticationSnapshot $authentication): void
    {
    }
}
