<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

enum InteractionStatus: string
{
    case OPEN = 'open';
    case CONSUMED = 'consumed';
    case REVOKED = 'revoked';
}
