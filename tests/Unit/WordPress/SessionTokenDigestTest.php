<?php

declare(strict_types=1);

namespace PDS\WP2FA\Tests\Unit\WordPress;

use InvalidArgumentException;
use PDS\WP2FA\WordPress\SessionTokenDigest;
use PHPUnit\Framework\TestCase;

final class SessionTokenDigestTest extends TestCase
{
    public function testCreatesTheStoredHmacDigestWithoutRetainingTheRawToken(): void
    {
        $digest = new SessionTokenDigest(static fn (): string => 'test-auth-salt');

        self::assertSame(
            'd73e9004df34154ddc0051df3fbbc23d5c914808592f35211a403ca476065133',
            $digest->digest('token-123'),
        );
        self::assertFalse(str_contains($digest->digest('token-123'), 'token-123'));
    }

    public function testRejectsAnEmptySessionToken(): void
    {
        $digest = new SessionTokenDigest(static fn (): string => 'test-auth-salt');

        $this->expectException(InvalidArgumentException::class);
        $digest->digest('');
    }
}
