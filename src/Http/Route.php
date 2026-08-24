<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

final class Route
{
    public const PAGE = 'pds-2fa';
    public const CHALLENGE = 'challenge';
    public const ENROLL = 'enroll';
    public const RECOVERY = 'recovery';

    public const CHALLENGE_ACTION = 'pds_wp_2fa_challenge';
    public const RECOVERY_ACTION = 'pds_wp_2fa_recovery';
    public const ENROLLMENT_BEGIN_ACTION = 'pds_wp_2fa_enrollment_begin';
    public const ENROLLMENT_COMPLETE_ACTION = 'pds_wp_2fa_enrollment_complete';
    public const ENROLLMENT_CANCEL_ACTION = 'pds_wp_2fa_enrollment_cancel';
    public const RECOVERY_REGENERATE_ACTION = 'pds_wp_2fa_recovery_regenerate';

    public static function isView(?string $route): bool
    {
        return in_array($route, [self::CHALLENGE, self::ENROLL, self::RECOVERY], true);
    }

    public static function isAction(?string $action): bool
    {
        return in_array($action, self::actions(), true);
    }

    /** @return list<string> */
    public static function actions(): array
    {
        return [
            self::CHALLENGE_ACTION,
            self::RECOVERY_ACTION,
            self::ENROLLMENT_BEGIN_ACTION,
            self::ENROLLMENT_COMPLETE_ACTION,
            self::ENROLLMENT_CANCEL_ACTION,
            self::RECOVERY_REGENERATE_ACTION,
        ];
    }

    public static function isFactorAction(?string $action): bool
    {
        return in_array($action, [self::CHALLENGE_ACTION, self::RECOVERY_ACTION], true);
    }

    public static function isPendingAction(?string $action): bool
    {
        return in_array($action, [
            self::CHALLENGE_ACTION,
            self::RECOVERY_ACTION,
            self::ENROLLMENT_BEGIN_ACTION,
            self::ENROLLMENT_COMPLETE_ACTION,
            self::ENROLLMENT_CANCEL_ACTION,
        ], true);
    }

    private function __construct()
    {
    }
}
