<?php

declare(strict_types=1);

namespace PDS\WP2FA\WordPress;

use Closure;
use InvalidArgumentException;
use RuntimeException;

final class SessionTokenDigest
{
    private readonly Closure $authSalt;

    public function __construct(callable $authSalt)
    {
        $this->authSalt = Closure::fromCallable($authSalt);
    }

    public static function fromWordPress(): self
    {
        if (!function_exists('wp_salt')) {
            throw new RuntimeException('WordPress wp_salt() is required to calculate a session-token digest.');
        }

        return new self(static fn (): string => (string) \wp_salt('auth'));
    }

    public function digest(string $sessionToken): string
    {
        if ($sessionToken === '') {
            throw new InvalidArgumentException('A session-token digest requires a non-empty session token.');
        }

        $salt = (string) ($this->authSalt)();
        if ($salt === '') {
            throw new RuntimeException('The WordPress auth salt must not be empty.');
        }

        return hash_hmac('sha256', $sessionToken, $salt);
    }
}
