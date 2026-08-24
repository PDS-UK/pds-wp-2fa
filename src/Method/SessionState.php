<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

enum SessionState: string
{
    case PENDING = 'pending';
    case SATISFIED = 'satisfied';
    case INVALIDATED = 'invalidated';
}
