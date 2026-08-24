<?php

declare(strict_types=1);

namespace PDS\WP2FA\Tests\Unit\Method;

use PHPUnit\Framework\TestCase;
use PDS\WP2FA\Method\FinalMethodGuard;
use PDS\WP2FA\Method\MethodStatus;
use PDS\WP2FA\Method\RetainedMethodCount;

final class FinalMethodGuardTest extends TestCase
{
    public function testSoleActiveMethodCannotBeManuallyRevoked(): void
    {
        $guard = new FinalMethodGuard();

        $this->expectException(\PDS\WP2FA\Method\FinalMethodProtectionException::class);
        $guard->assertManualRevocationAllowed(
            MethodStatus::ACTIVE,
            new RetainedMethodCount(1),
        );
    }

    public function testReplacementCanReplaceTheFinalActiveMethod(): void
    {
        $guard = new FinalMethodGuard();

        $guard->assertReplacementAllowed(
            new RetainedMethodCount(1),
            true,
        );

        self::assertTrue(true);
    }

    public function testRecoveryExhaustionIsAllowedForTheCurrentSuccessfulSession(): void
    {
        $guard = new FinalMethodGuard();

        self::assertTrue($guard->allowsRecoveryExhaustion(true));
        self::assertFalse($guard->allowsRecoveryExhaustion(false));
    }
}
