<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

interface ReauthGrantStore
{
    public function issue(AdminReauthGrant $grant): void;
}
