<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

enum MethodStatus: string
{
    case ACTIVE = 'active';
    case EXHAUSTED = 'exhausted';
    case REVOKED = 'revoked';
}
