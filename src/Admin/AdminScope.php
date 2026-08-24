<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

enum AdminScope: string
{
    case SETTINGS = 'settings';
    case USER_MANAGEMENT = 'user_management';
    case RETENTION = 'retention';
    case EMERGENCY = 'emergency';
}
