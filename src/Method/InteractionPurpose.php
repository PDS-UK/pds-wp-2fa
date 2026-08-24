<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

enum InteractionPurpose: string
{
    case ENROLLMENT = 'enrollment';
    case AUTHENTICATION = 'authentication';
    case ROTATION = 'rotation';
    case RECOVERY_REGENERATION = 'recovery_regeneration';
}
