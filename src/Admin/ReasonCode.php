<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

enum ReasonCode: string
{
    case SUPPORT = 'support';
    case LOST_AUTHENTICATOR = 'lost_authenticator';
    case POLICY_CHANGE = 'policy_change';
    case CLONE_REBIND = 'clone_rebind';
    case INCIDENT = 'incident';
    case ROTATION = 'rotation';
    case USER_REQUEST = 'user_request';
    case OTHER = 'other';
}
