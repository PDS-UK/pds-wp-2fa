<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

enum RevocationReason: string
{
    case USER_REQUEST = 'user_request';
    case ADMIN_REQUEST = 'admin_request';
    case ROTATION = 'rotation';
    case RECOVERY_REGENERATION = 'recovery_regeneration';
    case SYSTEM_RESET = 'system_reset';
}
