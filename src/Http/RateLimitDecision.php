<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

final class RateLimitDecision
{
    private function __construct(private readonly bool $allowed, private readonly int $retryAfter)
    {
        if ($retryAfter < 0) {
            throw new \InvalidArgumentException('A retry interval cannot be negative.');
        }
    }

    public static function permit(): self { return new self(true, 0); }
    public static function limited(int $retryAfter): self { return new self(false, $retryAfter); }
    public function allowed(): bool { return $this->allowed; }
    public function retryAfter(): int { return $this->retryAfter; }
}
