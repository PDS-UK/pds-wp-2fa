<?php

declare(strict_types=1);

namespace PDS\WP2FA\Tests\Unit\WordPress;

use PDS\WP2FA\WordPress\SafeRedirectTarget;
use PHPUnit\Framework\TestCase;

final class SafeRedirectTargetTest extends TestCase
{
    public function testKeepsAValidatedAdminTargetOnTheSameSite(): void
    {
        $validator = new SafeRedirectTarget(
            static fn (string $target, string $fallback): string => $target,
            static fn (): string => 'https://example.test/wp-admin/',
        );

        self::assertSame(
            'https://example.test/wp-admin/admin.php?page=pds-2fa',
            $validator->validate('https://example.test/wp-admin/admin.php?page=pds-2fa'),
        );
    }

    public function testFallsBackForMissingExternalOrNonAdminTargets(): void
    {
        $fallback = 'https://example.test/wp-admin/';
        $validator = new SafeRedirectTarget(
            static fn (string $target, string $default): string => $target,
            static fn (): string => $fallback,
        );

        self::assertSame($fallback, $validator->validate(null));
        self::assertSame($fallback, $validator->validate('https://evil.test/wp-admin/'));
        self::assertSame($fallback, $validator->validate('https://example.test/account/'));
        self::assertSame($fallback, $validator->validate('//evil.test/wp-admin/'));
    }

    public function testRejectsCredentialBearingQueryParameters(): void
    {
        $fallback = 'https://example.test/wp-admin/';
        $validator = new SafeRedirectTarget(
            static fn (string $target, string $default): string => $target,
            static fn (): string => $fallback,
        );

        self::assertSame(
            $fallback,
            $validator->validate('https://example.test/wp-admin/admin.php?challenge=raw-secret'),
        );
    }
}
