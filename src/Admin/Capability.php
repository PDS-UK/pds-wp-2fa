<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

final class Capability
{
    public const MANAGE = 'manage_pds_wp_2fa';
    public const VIEW_STATUS = 'view_pds_wp_2fa_status';
    public const MANAGE_USERS = 'manage_pds_wp_2fa_users';
    public const VIEW_AUDIT = 'view_pds_wp_2fa_audit';
    public const MANAGE_RETENTION = 'manage_pds_wp_2fa_retention';
    public const EMERGENCY = 'manage_pds_wp_2fa_emergency';

    private function __construct()
    {
    }
}
